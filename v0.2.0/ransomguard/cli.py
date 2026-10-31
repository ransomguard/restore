from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .incidents import IncidentController, ProcessInstance, SimulationEffects
from .network_policy import make_plan
from .outbox import Outbox
from .protocol import ProcessRegistry, ProtocolError, decode_event


def _load_config(path: str) -> dict:
    config = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(config, dict) or config.get("schema_version") != 1:
        raise ValueError("Configuration must use schema_version=1")
    return config


def _hourly_volume(config: dict) -> str:
    import re
    recovery = config.get("recovery")
    if not isinstance(recovery, dict):
        raise ValueError("A recovery configuration is required")
    if (recovery.get("snapshot_policy") != "hourly_only"
            or type(recovery.get("snapshot_interval_seconds")) is not int
            or recovery["snapshot_interval_seconds"] != 3600
            or recovery.get("snapshot_creation_triggers") != ["hourly_schedule"]):
        raise ValueError("This release permits only hourly_schedule snapshots every 3600 seconds")
    volume = recovery.get("volume_root")
    if not isinstance(volume, str) or re.fullmatch(r"[A-Za-z]:[\\/]", volume) is None:
        raise ValueError("recovery.volume_root must be a local drive root such as C:\\")
    return volume[0].upper() + ":\\"


def _snapshot_run(args: argparse.Namespace) -> int:
    from datetime import datetime, timezone
    import time
    from .snapshots import HourlySnapshotCoordinator
    volume = _hourly_volume(_load_config(args.config))
    with Outbox(args.db) as outbox:
        outbox.append("snapshot_schedule_tick", {"execution_mode": "live_snapshot", "volume_root": volume})
        coordinator = HourlySnapshotCoordinator(args.state_db)
        result = coordinator.run(volume_root=volume, trigger="hourly_schedule")
        # PT1H tasks can arrive a few seconds earlier relative to the previous
        # actual start. Wait for that existing reservation to expire, instead
        # of needlessly skipping an entire hour. No VSS call has run on a skip.
        if (result.get("status") == "skipped" and result.get("reason") == "hourly_cooldown"
                and result.get("attempted") is False and not result.get("requires_reconciliation")):
            try:
                due = datetime.fromisoformat(result["next_eligible_at"].replace("Z", "+00:00"))
                delay = (due - datetime.now(timezone.utc)).total_seconds()
            except (KeyError, TypeError, ValueError, AttributeError):
                delay = None
            if delay is not None and delay <= 60.0:
                wait_seconds = min(max(0.0, delay) + 0.05, 60.0)
                outbox.append("snapshot_tick_wait", {"execution_mode": "live_snapshot", "volume_root": volume,
                                                    "wait_seconds": wait_seconds, "reason": "hourly_schedule_jitter"})
                time.sleep(wait_seconds)
                result = coordinator.run(volume_root=volume, trigger="hourly_schedule")
        status = result.get("status", "unknown")
        outbox.append("snapshot_" + status, {"execution_mode": "live_snapshot", **result})
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if status == "unknown" or result.get("requires_reconciliation"):
        return 2
    return 0 if status in ("created", "skipped") else 1


def _snapshot_reconcile(args: argparse.Namespace) -> int:
    from .snapshots import HourlySnapshotCoordinator
    if not args.operation_finished:
        raise ValueError("Verify the previous VSS operation has ended before using --operation-finished")
    volume = _hourly_volume(_load_config(args.config))
    with Outbox(args.db) as outbox:
        outbox.append("snapshot_reconciliation_requested", {
            "execution_mode": "live_snapshot", "volume_root": volume,
            "snapshot_id": args.snapshot_id, "confirm_no_snapshot": args.confirm_no_snapshot,
        })
        result = HourlySnapshotCoordinator(args.state_db).reconcile(
            volume, operation_finished=True, snapshot_id=args.snapshot_id,
            confirm_no_snapshot=args.confirm_no_snapshot,
        )
        outbox.append("snapshot_reconciled", {"execution_mode": "live_snapshot", **result})
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _replay(args: argparse.Namespace) -> int:
    with Outbox(args.db) as outbox:
        effects = SimulationEffects()
        controller = IncidentController(outbox, effects)
        if args.scenario == "track-a":
            controller.begin(ProcessInstance(4100, 133000000000000001), "A")
        elif args.scenario in ("shared-process", "shared-host"):
            one = controller.begin(ProcessInstance(4100, 133000000000000001), "B")
            two = controller.begin(ProcessInstance(4100, 133000000000000001), "B")
            controller.decision(controller.ticket(one.incident_id), 0.05)
            controller.decision(controller.ticket(two.incident_id), error="simulated_timeout")
        else:
            item = controller.begin(ProcessInstance(4100, 133000000000000001), "B")
            ticket = controller.ticket(item.incident_id)
            if args.scenario == "benign":
                controller.decision(ticket, 0.05)
            elif args.scenario == "malicious":
                controller.decision(ticket, 0.95)
            elif args.scenario == "timeout":
                controller.decision(ticket, error="simulated_timeout")
            elif args.scenario == "restore-failure":
                effects.recovery_status = "partial"
                controller.decision(ticket, 0.95)
            elif args.scenario == "late-response":
                controller.escalate_to_a(item.incident_id)
                controller.decision(ticket, 0.05)
        result = controller.summary()
        result["effect_calls"] = effects.calls
        if args.export:
            result["exported_events"] = outbox.export_jsonl(args.export)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def _observe(args: argparse.Namespace) -> int:
    from .windows_reader import WindowsDriverReader
    from .triage import TriageConfig, TriageIntake
    registry = ProcessRegistry()
    config = _load_config(args.config) if args.config else {}
    triage = TriageIntake(TriageConfig(**config.get("triage", {})))
    count = 0
    with Outbox(args.db) as outbox, WindowsDriverReader() as reader:
        outbox.append("observer_started", {"execution_mode": "observation", "driver_status": reader.status()})
        print("Observation mode: records driver events and Track B candidates. Live JEV/kill/recovery/network response is not enabled.")
        try:
            while args.limit == 0 or count < args.limit:
                raw = reader.read()
                if raw is None:
                    continue
                try:
                    event = decode_event(raw)
                except ProtocolError as exc:
                    outbox.append("protocol_error", {"execution_mode": "observation", "error": str(exc), "size": len(raw)})
                    record = triage.reset(reason="protocol_error")
                    outbox.append(record.kind, record.payload)
                    continue
                registry.update(event)
                payload = event.to_dict()
                payload.update({"execution_mode": "observation", "correlated_process_create_time": registry.generation_for(event.pid),
                                "correlation_is_authorization": False,
                                "sequence_anomaly_observed": registry.loss_detected,
                                "complete_event_coverage": False})
                outbox.append("kernel_event", payload)
                for record in triage.ingest(event, correlated_create_time=registry.generation_for(event.pid)):
                    outbox.append(record.kind, record.payload)
                print(json.dumps({"kind": event.kind, "pid": event.pid, "sequence": event.sequence}, ensure_ascii=False))
                count += 1
        except KeyboardInterrupt:
            pass
        finally:
            outbox.append("observer_stopped", {"execution_mode": "observation", "driver_status": reader.status(), "events_read": count})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RansomGuard integration baseline: observe or simulate; live response is not enabled")
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay", help="Run deterministic simulated Track A/B cases; no external actions")
    replay.add_argument("--scenario", choices=["benign", "malicious", "timeout", "track-a", "shared-process", "shared-host", "late-response", "restore-failure"], default="malicious")
    replay.add_argument("--db", default="ransomguard-demo.sqlite3")
    replay.add_argument("--export")
    observe = sub.add_parser("observe", help="Read the Windows driver into a local durable outbox")
    observe.add_argument("--db", default="ransomguard-observe.sqlite3")
    observe.add_argument("--config", help="Optional triage settings; defaults use bounded Track B intake")
    observe.add_argument("--limit", type=int, default=0, help="0 = until Ctrl+C")
    export = sub.add_parser("export-events")
    export.add_argument("--db", required=True)
    export.add_argument("--output", required=True)
    send = sub.add_parser("send-events", help="Explicitly send one outbox batch using the PROPOSED backend ACK contract")
    send.add_argument("--db", required=True)
    send.add_argument("--endpoint", required=True)
    send.add_argument("--token-env", default="RANSOMGUARD_DASHBOARD_TOKEN")
    plan = sub.add_parser("plan-network", help="Print a policy plan; does NOT apply WFP/firewall changes")
    plan.add_argument("--config", required=True)
    plan.add_argument("--resolve", action="store_true", help="Explicitly resolve endpoint DNS addresses now")
    snapshots = sub.add_parser("snapshot-inventory", help="Read an exact Windows volume's existing VSS metadata; does not create or restore")
    snapshots.add_argument("--volume-root", required=True, help="Local volume root, for example C:\\")
    snapshots.add_argument("--output", help="Optional JSON inventory output file")
    tick = sub.add_parser("snapshot-run", help="Run one REAL Windows VSS hourly tick with a durable duplicate guard")
    reconcile = sub.add_parser("snapshot-reconcile", help="Explicitly resolve an uncertain VSS attempt after inspecting the VM")
    task = sub.add_parser("snapshot-task", help="Write a task XML definition; does not install it or create a snapshot")
    for command in (tick, reconcile, task):
        command.add_argument("--config", required=True)
        command.add_argument("--state-db", required=True)
        command.add_argument("--db", required=True, help="Durable event outbox path")
    reconcile.add_argument("--operation-finished", action="store_true")
    outcome = reconcile.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--snapshot-id")
    outcome.add_argument("--confirm-no-snapshot", action="store_true")
    task.add_argument("--python-executable", required=True)
    task.add_argument("--user-sid", required=True)
    task.add_argument("--output", required=True)
    sub.add_parser("capabilities", help="Report implemented and unavailable capabilities")
    args = parser.parse_args(argv)
    try:
        if args.command == "replay":
            return _replay(args)
        if args.command == "observe":
            if args.limit < 0:
                parser.error("--limit cannot be negative")
            return _observe(args)
        if args.command == "export-events":
            with Outbox(args.db) as outbox:
                print(json.dumps({"exported_events": outbox.export_jsonl(args.output)}))
        elif args.command == "send-events":
            from .dashboard import send_batch
            with Outbox(args.db) as outbox:
                print(json.dumps({"acknowledged_events": send_batch(outbox, args.endpoint, token_env=args.token_env)}))
        elif args.command == "plan-network":
            config = _load_config(args.config)
            print(json.dumps(make_plan(config["network"], resolve=args.resolve), ensure_ascii=False, indent=2))
        elif args.command == "snapshot-run":
            return _snapshot_run(args)
        elif args.command == "snapshot-reconcile":
            return _snapshot_reconcile(args)
        elif args.command == "snapshot-task":
            from .scheduling import build_hourly_task_xml
            _hourly_volume(_load_config(args.config))
            xml = build_hourly_task_xml(
                python_executable=args.python_executable, config_path=str(Path(args.config).absolute()) if sys.platform == "win32" else args.config,
                state_db=args.state_db, outbox_db=args.db, user_sid=args.user_sid,
            )
            Path(args.output).write_text(xml, encoding="utf-8")
            print(json.dumps({"task_definition": args.output, "installed": False, "snapshot_created": False}))
        elif args.command == "snapshot-inventory":
            from .recovery import enumerate_snapshots, volume_id_for_root
            volume_id = volume_id_for_root(args.volume_root)
            result = {"schema_version": 1, "volume_root": args.volume_root, "volume_id": volume_id,
                      "snapshots": [item.to_dict() for item in enumerate_snapshots(volume_id)]}
            rendered = json.dumps(result, ensure_ascii=False, indent=2)
            if args.output:
                Path(args.output).write_text(rendered + "\n", encoding="utf-8")
            print(rendered)
        elif args.command == "capabilities":
            print(json.dumps({"version": "0.6.1", "windows_driver_build": "projects_reconstructed_not_built_here",
                              "windows_event_observation": "implemented_requires_vm_validation",
                              "high_entropy_track_b_intake": "implemented_observation_candidates_no_live_response",
                              "track_a_b_simulation": True, "durable_outbox": True,
                              "jev_module": "implemented_live_credentials_and_response_validation_required",
                              "recovery_module": "implemented_requires_windows_vss_validation",
                              "snapshot_creation": "implemented_windows_cim_requires_vm_validation",
                              "snapshot_schedule": "hourly_only_install_script_provided_not_installed_here",
                              "network_scope": "process", "process_network_enforcement": False,
                              "file_io_containment": False,
                              "automatic_live_response": False,
                              "dashboard_compatibility": "existing_backend_contract_required"}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
