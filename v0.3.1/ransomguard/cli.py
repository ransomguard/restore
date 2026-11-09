from __future__ import annotations

import argparse
from contextlib import nullcontext
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
        if status == "created" and args.ui:
            from .ui_bridge import UiBestEffortPublisher
            from .ui_pipe import WindowsUiPipe
            try:
                with WindowsUiPipe() as ui_sink:
                    delivered = UiBestEffortPublisher(ui_sink).publish_snapshot_created(result)
            except (OSError, TimeoutError):
                delivered = "send_failed"
            snapshot_details = result.get("snapshot")
            snapshot_id = snapshot_details.get("snapshot_id") if isinstance(snapshot_details, dict) else None
            outbox.append("local_ui_snapshot_notice", {"execution_mode": "best_effort_ui",
                                                       "result": delivered, "ui_acknowledged": False,
                                                       "snapshot_id": snapshot_id})
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
    from collections import OrderedDict
    import os
    import re
    import uuid
    from .windows_reader import WindowsDriverReader
    from .triage import TriageConfig, TriageIntake
    from .ui_bridge import UiBestEffortPublisher
    from .ui_pipe import WindowsUiPipe
    from .firewall_control import FirewallHoldManager
    from .incidents import ProcessInstance
    from .jev import JevClient, JevConfig
    from .live_response import LiveResponseCoordinator
    from .observer_filter import ObserverOutboxFilter
    from .protocol import filetime_to_iso
    from .response_commands import profile_from_config, thresholds_from_config, recovery_plan_from_template
    registry = ProcessRegistry()
    config = _load_config(args.config) if args.config else {}
    triage = TriageIntake(TriageConfig(**config.get("triage", {})))
    count = 0
    raw_events_read = 0
    storage_events_skipped = 0
    ui_context = WindowsUiPipe() if args.ui else nullcontext()
    response_owner_context = nullcontext()
    jev = None
    threshold_policy = None
    if args.live_track_b:
        if args.authorize_live is not True or args.confirm_isolated_vm is not True:
            raise PermissionError("Live Track B requires --authorize-live and --confirm-isolated-vm")
        if not args.response_state_db or not args.response_path_prefix or not args.config:
            raise ValueError("Live Track B requires --response-state-db, --response-path-prefix and --config")
        if bool(args.response_manifest_template) == bool(args.response_no_recovery_required):
            raise ValueError("Provide either --response-manifest-template or --response-no-recovery-required")
        prefix = args.response_path_prefix.replace("/", "\\").rstrip("\\") + "\\"
        if (not re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+\\[^*?]+\\", prefix, re.IGNORECASE)
                or any(part in (".", "..", "") for part in prefix[1:-1].split("\\"))):
            raise ValueError("Live response path scope must be one exact NT device directory prefix")
        profile = profile_from_config(config)
        threshold_policy = thresholds_from_config(config)
        if not os.environ.get("TYPESAFE_API_KEY"):
            raise ValueError("TYPESAFE_API_KEY must be configured BEFORE enabling live network cutoff")
        jev = JevClient(JevConfig(base_url=profile.jev_url))
        response_owner_context = FirewallHoldManager(args.response_state_db, profile)
    seen_response_keys: OrderedDict[str, None] = OrderedDict()
    response_results: dict[str, int] = {}
    with Outbox(args.db) as outbox, WindowsDriverReader() as reader, ui_context as ui_sink, response_owner_context as owner:
        storage_filter = ObserverOutboxFilter(outbox.path)
        publisher = UiBestEffortPublisher(ui_sink, file_rate=args.ui_file_rate) if ui_sink else None
        responder = (LiveResponseCoordinator(outbox=outbox, firewall=owner, driver=reader,
                                             jev=jev, thresholds=threshold_policy)
                     if args.live_track_b else None)
        initial_status = reader.status()
        dropped_before = initial_status.get("events_dropped")
        outbox.append("observer_started", {"execution_mode": "observation", "driver_status": initial_status,
                                           "local_ui_enabled": publisher is not None})
        if publisher:
            publisher.publish_status(initial_status)
        print("Observation mode: kernel -> durable outbox / Track B candidates"
              + (" / local UI IPC" if publisher else "")
              + (" / EXPLICIT LIVE HOST-OUTBOUND RESPONSE (lab only)." if responder else
                 ". Live JEV/kill/recovery/firewall actions are not enabled."))
        try:
            while args.limit == 0 or raw_events_read < args.limit:
                raw = reader.read()
                if raw is None:
                    continue
                try:
                    event = decode_event(raw)
                except ProtocolError as exc:
                    registry.invalidate()
                    outbox.append("protocol_error", {"execution_mode": "observation", "error": str(exc), "size": len(raw)})
                    record = triage.reset(reason="protocol_error")
                    outbox.append(record.kind, record.payload)
                    continue
                registry.update(event)
                raw_events_read += 1
                self_storage_io = storage_filter.matches(event)
                correlated_create_time = registry.generation_for(event.pid)
                if self_storage_io:
                    storage_events_skipped += 1
                else:
                    payload = event.to_dict()
                    payload.update({"execution_mode": "observation", "correlated_process_create_time": correlated_create_time,
                                    "correlation_is_authorization": False,
                                    "sequence_anomaly_observed": registry.loss_detected,
                                    "complete_event_coverage": False})
                    outbox.append("kernel_event", payload)
                for record in triage.ingest(event, correlated_create_time=correlated_create_time,
                                            ignore_file_evidence=self_storage_io):
                    outbox.append(record.kind, record.payload)
                    if not self_storage_io and responder is not None and record.kind == "track_b_candidate":
                        payload = record.payload
                        evidence = payload.get("evidence", {})
                        raw_path = evidence.get("trigger_path", "")
                        create_time = payload.get("correlated_process_create_time")
                        if (not isinstance(raw_path, str) or
                                not raw_path.casefold().startswith(prefix.casefold()) or
                                type(create_time) is not int or create_time <= 0):
                            outbox.append("live_candidate_outside_approved_scope", {
                                "execution_mode": "observation", "candidate_id": payload.get("candidate_id"),
                                "pid": event.pid, "scope": prefix, "no_live_response": True})
                            continue
                        incident_id = str(uuid.uuid5(uuid.NAMESPACE_OID,
                                                      f"RansomGuard:TrackB:{event.pid}:{create_time}"))
                        if incident_id in seen_response_keys:
                            continue
                        seen_response_keys[incident_id] = None
                        if len(seen_response_keys) > 2048:
                            seen_response_keys.popitem(last=False)
                        stamp = filetime_to_iso(event.filetime)
                        provider = (None if args.response_no_recovery_required else
                                    lambda stamp=stamp: recovery_plan_from_template(
                                        args.response_manifest_template, incident_at=stamp))
                        result = responder.respond(
                            track="B", process=ProcessInstance(event.pid, create_time),
                            jev_state=payload, recovery_plan_provider=provider,
                            recovery_required=not args.response_no_recovery_required,
                            incident_id=incident_id, explicit_authorization=True)
                        if publisher:
                            outcomes = publisher.publish_live_result(
                                result, protected_root=config.get("recovery", {}).get("protected_root", ""),
                                observed_path=raw_path)
                            if outcomes:
                                outbox.append("local_ui_live_response_notice", {
                                    "execution_mode": "best_effort_ui", "incident_id": incident_id,
                                    "results": outcomes, "ui_acknowledged": False}, incident_id=incident_id)
                        response_results[result.state] = response_results.get(result.state, 0) + 1
                        print(json.dumps({"incident_id": result.incident_id, "state": result.state,
                                          "reason": result.reason, "pid": event.pid}, ensure_ascii=False))
                if not self_storage_io:
                    if publisher:
                        publisher.publish_event(event)
                    print(json.dumps({"kind": event.kind, "pid": event.pid, "sequence": event.sequence}, ensure_ascii=False))
                    count += 1
                if raw_events_read % args.status_every == 0:
                    new_status = reader.status()
                    current_dropped = new_status.get("events_dropped")
                    if (type(dropped_before) is int and type(current_dropped) is int
                            and current_dropped > dropped_before):
                        registry.invalidate()
                        reset = triage.reset(reason="driver_drop_counter_advanced")
                        outbox.append(reset.kind, reset.payload)
                        outbox.append("driver_event_loss_observed", {"execution_mode": "observation",
                                                                    "previous_drops": dropped_before,
                                                                    "current_drops": current_dropped})
                    dropped_before = current_dropped
                    if publisher:
                        publisher.publish_status(new_status, sequence=event.sequence)
        except KeyboardInterrupt:
            pass
        finally:
            outbox.append("observer_stopped", {"execution_mode": "observation", "driver_status": reader.status(),
                                               "events_read": raw_events_read,
                                               "events_recorded": count,
                                               "observer_storage_events_skipped": storage_events_skipped,
                                               "triage_diagnostics": triage.stats(),
                                               "local_ui_diagnostics": publisher.diagnostics() if publisher else None,
                                               "local_ui_no_ack": True,
                                               "live_response_enabled": bool(responder),
                                               "live_response_results": response_results})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RansomGuard restore/JEV v0.3.1: observe by default; explicitly authorized lab response")
    sub = parser.add_subparsers(dest="command", required=True)
    replay = sub.add_parser("replay", help="Run deterministic simulated Track A/B cases; no external actions")
    replay.add_argument("--scenario", choices=["benign", "malicious", "timeout", "track-a", "shared-process", "shared-host", "late-response", "restore-failure"], default="malicious")
    replay.add_argument("--db", default="ransomguard-demo.sqlite3")
    replay.add_argument("--export")
    observe = sub.add_parser("observe", help="Read the Windows driver into a local durable outbox")
    observe.add_argument("--db", default="ransomguard-observe.sqlite3")
    observe.add_argument("--config", help="Optional triage settings; defaults use bounded Track B intake")
    observe.add_argument("--limit", type=int, default=0, help="0 = until Ctrl+C; counts decoded kernel events (including skipped self-I/O)")
    observe.add_argument("--ui", action="store_true", help="Best-effort IPC to an ALREADY RUNNING Ransom0_UI receiver")
    observe.add_argument("--ui-file-rate", type=int, default=10, help="UI file-event limit per second (1..100); outbox remains complete")
    observe.add_argument("--status-every", type=int, default=100, help="Poll kernel dropped-event counters every N received events")
    observe.add_argument("--live-track-b", action="store_true", help="OPT-IN automatic Track B on approved lab paths; may block entire VM network")
    observe.add_argument("--response-state-db", help="Durable host-wide incident hold DB")
    observe.add_argument("--response-path-prefix", help="Exact approved NT test directory prefix (\\\\Device\\HarddiskVolume3\\RG_Test)")
    observe.add_argument("--response-manifest-template", help="Fixed operator-approved lab VSS file manifest; snapshot selected AFTER exit")
    observe.add_argument("--response-no-recovery-required", action="store_true", help="Lab experiment with no file recovery required")
    observe.add_argument("--authorize-live", action="store_true", help="Allow real JEV/kernel/firewall actions")
    observe.add_argument("--confirm-isolated-vm", action="store_true", help="Confirm THIS IS AN ISOLATED VM; network cutoff is PC-WIDE")
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
    tick.add_argument("--ui", action="store_true", help="Send verified BACKUP_CREATED to the running local UI (best effort)")
    reconcile.add_argument("--operation-finished", action="store_true")
    outcome = reconcile.add_mutually_exclusive_group(required=True)
    outcome.add_argument("--snapshot-id")
    outcome.add_argument("--confirm-no-snapshot", action="store_true")
    task.add_argument("--python-executable", required=True)
    task.add_argument("--user-sid", required=True)
    task.add_argument("--output", required=True)
    fw_status = sub.add_parser("firewall-status", help="READ-ONLY local hold status; optionally query existing daemon IPC")
    fw_status.add_argument("--config", required=True)
    fw_status.add_argument("--state-db", required=True)
    fw_status.add_argument("--query-daemon", action="store_true", help="Read the already-running daemon's active state")
    fw_release = sub.add_parser("firewall-review-release", help="EXPLICIT operator-confirmed release of one review hold")
    fw_release.add_argument("--config", required=True)
    fw_release.add_argument("--state-db", required=True)
    fw_release.add_argument("--db", required=True)
    fw_release.add_argument("--incident-id", required=True)
    fw_release.add_argument("--reason", choices=["false_positive", "manual_recovery_verified", "lab_cleanup_confirmed"], required=True)
    fw_release.add_argument("--authorize-live", action="store_true")
    fw_release.add_argument("--confirm-isolated-vm", action="store_true")
    fw_release.add_argument("--operator-verified-safe", action="store_true")
    respond = sub.add_parser("respond-one", help="Explicit lab-only Track A/B host firewall -> JEV -> kill -> recovery")
    respond.add_argument("--config", required=True)
    respond.add_argument("--state-db", required=True, help="Durable global firewall hold DB; SAME path for every responder")
    respond.add_argument("--db", required=True, help="Durable event outbox DB")
    respond.add_argument("--track", choices=["A", "B"], required=True)
    respond.add_argument("--pid", type=int, required=True)
    respond.add_argument("--create-time", type=int, required=True, help="Exact kernel 64-bit process FILETIME; not UI milliseconds")
    respond.add_argument("--jev-state-json", help="Track B only: bounded JSON evidence sent to JEV")
    respond.add_argument("--recovery-plan", help="Operator-reviewed VSS snapshot + affected-file manifest JSON")
    respond.add_argument("--no-recovery-required", action="store_true", help="Explicitly assert this lab incident needs no file restore")
    respond.add_argument("--track-a-confirmed", action="store_true", help="I independently confirmed unmistakable Track A evidence")
    respond.add_argument("--authorize-live", action="store_true", help="Authorize real daemon/JEV/kernel actions")
    respond.add_argument("--confirm-isolated-vm", action="store_true", help="Acknowledge PC-WIDE network cutoff on THIS lab VM")
    respond.add_argument("--ui", action="store_true", help="Best-effort incident result to an already-running Ransom0_UI receiver")
    sub.add_parser("capabilities", help="Report implemented and unavailable capabilities")
    args = parser.parse_args(argv)
    try:
        if args.command == "replay":
            return _replay(args)
        if args.command == "observe":
            if args.limit < 0:
                parser.error("--limit cannot be negative")
            if not 1 <= args.status_every <= 100_000:
                parser.error("--status-every must be between 1 and 100000")
            if not 1 <= args.ui_file_rate <= 100:
                parser.error("--ui-file-rate must be between 1 and 100")
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
        elif args.command == "firewall-status":
            from .response_commands import firewall_status
            print(json.dumps(firewall_status(config_path=args.config, state_db=args.state_db,
                                            query_daemon=args.query_daemon), ensure_ascii=False, indent=2))
        elif args.command == "firewall-review-release":
            from .response_commands import operator_review_release
            result = operator_review_release(
                config_path=args.config, state_db=args.state_db, outbox_db=args.db,
                incident_id=args.incident_id, reason=args.reason,
                authorize_live=args.authorize_live,
                confirm_isolated_vm=args.confirm_isolated_vm,
                operator_verified_safe=args.operator_verified_safe)
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.command == "respond-one":
            from .response_commands import respond_one
            result = respond_one(
                config_path=args.config, state_db=args.state_db, outbox_db=args.db,
                track=args.track, pid=args.pid, create_time=args.create_time,
                jev_state_file=args.jev_state_json, recovery_plan_file=args.recovery_plan,
                no_recovery_required=args.no_recovery_required,
                track_a_confirmed=args.track_a_confirmed, authorize_live=args.authorize_live,
                confirm_isolated_vm=args.confirm_isolated_vm, ui=args.ui)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["state"] == "RELEASED" else 2
        elif args.command == "capabilities":
            print(json.dumps({"version": "0.3.1", "kernel_compatibility": "v0.7.0-rc2/v0.7.1 ABI v1",
                              "windows_driver_build": "separate_kernel_repository_vm_verified",
                              "windows_event_observation": "implemented_requires_vm_validation",
                              "local_ui_ipc": "implemented_optional_best_effort_requires_vm_validation_no_ack",
                              "generation_bound_terminate_ioctl": "available_in_explicit_live_response_requires_vm_validation",
                              "high_entropy_track_b_intake": "implemented_observation_and_opt_in_lab_response",
                              "track_a_b_simulation": True, "durable_outbox": True,
                              "jev_module": "implemented_live_credentials_and_response_validation_required",
                              "recovery_module": "implemented_requires_windows_vss_validation",
                              "snapshot_creation": "implemented_windows_cim_requires_vm_validation",
                              "snapshot_schedule": "hourly_only_install_script_provided_not_installed_here",
                              "network_scope": "host_outbound", "host_firewall_daemon_ipc": "implemented_requires_windows_vm_validation",
                              "durable_global_incident_holds": True,
                              "track_a_b_live_response": "implemented_opt_in_respond_one_requires_vm_validation",
                              "firewall_ipc_ack_is_wfp_proof": False,
                              "network_limits": ["outbound_only", "remote_dns_port_53_permitted", "allowlist_applies_to_all_processes"],
                              "automated_observer_response": "track_b_opt_in_lab_path_requires_vm_validation", "process_network_enforcement": False,
                              "file_io_containment": False,
                              "automatic_live_response": "restricted_track_b_opt_in_requires_vm_validation",
                              "dashboard_compatibility": "existing_backend_contract_required"}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
