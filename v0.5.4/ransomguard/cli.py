from __future__ import annotations

import argparse
from contextlib import closing, nullcontext, contextmanager
import json
from pathlib import Path
import sys
import sqlite3

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


def _propose_recovery(args: argparse.Namespace) -> int:
    """Produce a review-only manifest proposal from stored kernel attempts."""
    from .damage_candidates import propose_recovery_candidates
    db_path = Path(args.db).resolve()
    if not db_path.is_file():
        raise ValueError("Existing outbox database is required")
    # Opening in read-only mode guarantees no observer state or file is changed.
    with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as db:
        proposal = propose_recovery_candidates(
            db, pid=args.pid, process_create_time=args.create_time,
            approved_path_prefix=args.path_prefix, max_files=args.max_files)
    rendered = json.dumps(proposal, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


def _response_status(args: argparse.Namespace) -> int:
    """Inspect automatic-response reservations without altering an outbox."""
    db_path = Path(args.db).resolve()
    if not db_path.is_file():
        raise ValueError("Existing outbox database is required")
    with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as db:
        exists = db.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='live_response_attempts'"
        ).fetchone()[0]
        if not exists:
            records = []
        else:
            fields = ("incident_id", "pid", "process_create_time", "claimed_at_utc",
                      "finished_at_utc", "state", "reason")
            rows = db.execute(
                """SELECT incident_id,pid,process_create_time,claimed_at_utc,
                          finished_at_utc,state,reason FROM live_response_attempts
                   ORDER BY claimed_at_utc DESC LIMIT ?""", (args.limit,))
            records = [dict(zip(fields, row)) for row in rows]
    print(json.dumps({"execution_mode": "read_only", "attempts": records,
                      "reserved_count_in_result": sum(r["state"] == "RESERVED" for r in records),
                      "operator_review_required_for_reserved": True}, ensure_ascii=False, indent=2))
    return 0


def _observe(args: argparse.Namespace, *, shared_reader=None, reload_requested=None) -> int:
    from .scope_settings import apply_observer_scope
    apply_observer_scope(args)
    import os
    import re
    import time
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
    from .response_ledger import ResponseLedger
    from .track_a import TrackACorroborator
    live_a = getattr(args, "live_track_a", False)
    live_any = args.live_track_b or live_a
    async_live = live_any and getattr(args, "async_response", False)
    from .correlation_identity import RecoverableProcessRegistry
    registry = RecoverableProcessRegistry()
    config = _load_config(args.config) if args.config else {}
    triage = TriageIntake(TriageConfig(**config.get("triage", {})))
    count = 0
    raw_events_read = 0
    storage_events_skipped = 0
    from .ui_delivery import DurableUiDelivery
    ui_context = (DurableUiDelivery(args.db) if getattr(args, "ui_durable", False) else WindowsUiPipe()) if args.ui else nullcontext()
    response_owner_context = nullcontext()
    jev = None
    threshold_policy = None
    if live_any:
        if args.authorize_live is not True or not (args.confirm_isolated_vm is True or getattr(args,'confirm_internal_test',False) is True):
            raise PermissionError("Live response requires --authorize-live and explicit VM or internal PC-wide containment consent")
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
        bridge_path = os.environ.get('RANSOMGUARD_JEV_BRIDGE')
        if bridge_path and (not Path(bridge_path).is_absolute() or not Path(bridge_path).is_file()
                            or profile.jev_url != 'https://api.typesafe.ai'):
            raise ValueError('A fixed-endpoint absolute JEV bridge executable is required')
        if args.live_track_b and not (bridge_path or os.environ.get("TYPESAFE_API_KEY")):
            raise ValueError("TYPESAFE_API_KEY must be configured BEFORE enabling live network cutoff")
        jev = JevClient(JevConfig(base_url=profile.jev_url))
        response_owner_context = nullcontext() if async_live else FirewallHoldManager(args.response_state_db, profile)
    if live_a and args.response_no_recovery_required:
        raise ValueError("Automatic Track A requires a fixed approved recovery manifest")
    track_a = TrackACorroborator(prefix) if live_a else None
    response_results: dict[str, int] = {}
    prefetch = getattr(args, "prefetch_events", 0)
    if prefetch and live_any and not async_live:
        raise ValueError("Buffered intake is restricted to passive observation")
    from .buffered_reader import BufferedReader
    from .retention import RawRetention
    @contextmanager
    def prepared_outbox():
        with Outbox(args.db) as store:
            if getattr(args, 'ui_durable', False):
                store.enable_local_diagnostics()
                # One bounded slice, including during resident replacement.
                # Draining the entire eligible history here can block worker
                # startup/health for minutes while the kernel reader is live.
                startup_retention = RawRetention(store.db, grace_seconds=max(
                    120, triage.config.window_seconds + triage.config.cooldown_seconds + 30),
                    batch_limit=128,capacity_limit=512,interval=1)
                startup_retention.cleanup(force=True)
            yield store
    def make_reader():
        if shared_reader is not None:
            return nullcontext(shared_reader)
        return BufferedReader(WindowsDriverReader(), prefetch, preserve=outbox.preserve_intake) if prefetch else WindowsDriverReader()
    from .live_console import LiveConsole
    console_enabled = getattr(args, 'live_console', False) or (args.ready_file and (Path(args.ready_file).parent/'live-console.enabled').exists())
    console_context = LiveConsole(control_path=Path(args.ready_file).parent/'console-display.json' if args.ready_file else None) if console_enabled else nullcontext()
    from .intake_scheduling import intake_priority
    with intake_priority(shared_reader), prepared_outbox() as outbox, make_reader() as reader, ui_context as ui_sink, response_owner_context as owner, console_context as live_console:
        retention = RawRetention(outbox.db,grace_seconds=max(120,triage.config.window_seconds+triage.config.cooldown_seconds+30),
                                 batch_limit=128,capacity_limit=512,interval=1) if getattr(args,"ui_durable",False) else None
        response_ledger = ResponseLedger(outbox.db) if live_any and not async_live else None
        if (not live_any or async_live) and hasattr(ui_sink, 'use_enqueue_connection'):
            ui_sink.use_enqueue_connection(outbox.db)
        storage_filter = ObserverOutboxFilter(outbox.path)
        publisher = UiBestEffortPublisher(ui_sink, file_rate=args.ui_file_rate) if ui_sink else None
        responder = (LiveResponseCoordinator(outbox=outbox, firewall=owner, driver=reader,
                                             jev=jev, thresholds=threshold_policy)
                     if live_any and not async_live else None)
        initial_status = reader.status()
        if shared_reader is None or getattr(args, '_resident_info', {}).get('worker_generation') == 1:
            native = getattr(reader, 'reader', reader)
            if hasattr(native, '_ioctl'):
                import struct
                from .protocol import MAGIC, VERSION, UPDATE_POLICY
                native._ioctl(UPDATE_POLICY, struct.pack('<IIIII', MAGIC, VERSION,
                    initial_status['fastpath_mode'], 1, initial_status['self_protect_enabled']), 0, 5000)
        from .live_pipeline import LivePipeline
        pipeline = (LivePipeline(outbox, reader, args, profile, threshold_policy, config, initial_status)
                    if async_live else None)
        from .response_rearm import ResponseRearm
        rearm=ResponseRearm(args.ready_file,pipeline,resident=shared_reader is not None)
        def response_health(status):
            if pipeline:
                pending=reader.queue.qsize() if hasattr(reader,'queue') else 0
                result=rearm.tick(status,pending)
                health.metadata['response_collection_invalid']=pipeline.invalid.is_set()
                health.metadata['response_rearm_error']=rearm.last_error
                if result:outbox.append('response_rearm_requested',result)
        from .counter_history import CounterHistory
        from .driver_maintenance import DriverMaintenance
        ready_file = getattr(args, 'ready_file', None)
        counters = CounterHistory(Path(ready_file).with_suffix('.counters.json') if ready_file else None)
        cumulative_status = counters.observe(initial_status, force=True)
        maintenance = DriverMaintenance(ready_file, reader,
            session=getattr(args, '_resident_info', {}).get('resident_session'),
            enabled=shared_reader is not None and not live_any)
        from .installer_drain import InstallerDrain
        installer_drain = InstallerDrain(ready_file,reader,getattr(args,'_resident_info',{}).get('resident_session'))
        dropped_before = initial_status.get("events_dropped")
        outbox.append("observer_started", {"execution_mode": "observation", "driver_status": initial_status,
                                           "local_ui_enabled": publisher is not None,
                                           "resident_worker": getattr(args, '_resident_info', None)})
        if publisher:
            publisher.publish_status(cumulative_status)
        from .observer_health import ObserverHealth
        health = ObserverHealth(getattr(args, 'ready_file', None), args.db,
                                metadata=getattr(args, '_resident_info', None), stop_check_interval=.1)
        health.metadata['intake_thread_priority'] = getattr(reader, 'intake_priority', 'unchanged')
        # Publish effective worker settings after validation, including hot reloads.
        # runtime.json describes launcher startup and can predate scope/key setup.
        health.metadata['response_tracks'] = (['A'] if live_a else []) + (['B'] if args.live_track_b else [])
        health.metadata['response_authorized'] = bool(live_any and args.authorize_live)
        health.metadata['response_path_prefix'] = args.response_path_prefix if live_any else None
        health.publish(initial_status, intake=reader.diagnostics() if prefetch else None, force=True)
        print("Observation mode: kernel -> durable outbox / Track B candidates"
              + (" / local UI IPC" if publisher else "")
              + (" / EXPLICIT LIVE HOST-OUTBOUND RESPONSE (lab only)." if live_any else
                 ". Live JEV/kill/recovery/firewall actions are not enabled."))
        raw = None
        from .storage_transaction import PassiveBatch
        storage_batch = PassiveBatch(outbox,limit=256,max_seconds=.05) if not live_any or async_live else None
        from .internal_collection import InternalCollection
        internal_collection = InternalCollection(Path(args.ready_file).parent) if args.ready_file else None
        last_status_poll = time.monotonic()
        try:
            while args.limit == 0 or raw_events_read < args.limit:
                raw = None
                if health.stop_requested():
                    if pipeline: pipeline.request_stop()
                    if (not pipeline or pipeline.jobs.stopped) and installer_drain.ready_to_close(): break
                # Finish the previous record before switching workers. The
                # resident owner continues reading the SAME kernel handle.
                if reload_requested is not None and reload_requested():
                    if pipeline: pipeline.request_stop()
                    if not pipeline or pipeline.jobs.stopped: break
                if internal_collection:
                    internal_collection.tick()
                    health.metadata['identity_correlation'] = dict(registry.stats, epoch=registry.epoch, ever_loss_detected=registry.ever_loss_detected)
                    health.metadata['internal_collection'] = {'collect':internal_collection.collect,'excluded':internal_collection.excluded,'observed':internal_collection.observed,'error':internal_collection.error}
                    if publisher: publisher.include_internal_storage = internal_collection.collect
                if pipeline: pipeline.tick()
                # Prioritize incoming records during bursts. Completed evidence
                # remains durable until a later short maintenance slice.
                maintenance_room = not hasattr(reader,'queue') or reader.queue.qsize()<256
                if retention and time.time()-retention.last_run>=retention.interval and maintenance_room:
                    if storage_batch:storage_batch.flush()
                    retention.cleanup()
                if storage_batch and (not hasattr(reader,'queue') or reader.queue.empty()):
                    storage_batch.flush()
                raw = reader.read()
                if raw is None:
                    if storage_batch:storage_batch.flush()
                    # A restarted UI must receive status even on an idle guest.
                    idle_status = reader.status()
                    cumulative_status = counters.observe(idle_status)
                    maintenance.tick(idle_status, idle=True)
                    response_health(idle_status)
                    health.metadata['counter_totals'] = dict(counters.state.get('totals', {}))
                    health.metadata['pending_intake'] = reader.queue.qsize() if hasattr(reader, 'queue') else 0
                    health.publish(idle_status, intake=reader.diagnostics() if prefetch else None)
                    if publisher:
                        publisher.publish_status(cumulative_status)
                    last_status_poll = time.monotonic()
                    continue
                try:
                    event = decode_event(raw)

                except ProtocolError as exc:
                    if storage_batch:storage_batch.flush()
                    registry.invalidate()
                    outbox.append("protocol_error", {"execution_mode": "observation", "error": str(exc), "size": len(raw)})
                    record = triage.reset(reason="protocol_error")
                    outbox.append(record.kind, record.payload)
                    continue
                registry.update(event)
                if internal_collection and internal_collection.exclude(event):
                    for skipped in triage.ingest(event, correlated_create_time=None, ignore_file_evidence=True):
                        outbox.append(skipped.kind, skipped.payload)
                    raw_events_read += 1
                    raw = None
                    continue
                if live_console: live_console.offer(event)
                elif args.ready_file:
                    from .console_stream import kernel_event
                    kernel_event(Path(args.ready_file).parent,event)
                with (storage_batch.record(raw) if storage_batch else nullcontext()):
                    if pipeline: pipeline.observe(event, registry)
                    raw_events_read += 1
                    self_storage_io = storage_filter.matches(event)
                    correlated_create_time = registry.generation_for_event(event)
                    if self_storage_io:
                        storage_events_skipped += 1
                    else:
                        payload = event.to_dict()
                        payload.update({"execution_mode": "observation", "correlated_process_create_time": correlated_create_time,
                                        "correlation_is_authorization": False,
                                        "sequence_anomaly_observed": registry.loss_detected,
                                        "complete_event_coverage": False})
                        raw_id=outbox.append("kernel_event", payload)
                        if retention:
                            retention.begin(raw_id,event,correlated_create_time or event.fields.get('process_create_time'))
                            if event.event_type==4 and event.fields.get('flags',0)&8:
                                retention.protect(event.pid,correlated_create_time,'high_entropy')
                        if event.event_type == 3 and event.fields.get("matched_rule_id", 0) in range(1001, 1009):
                            # The kernel denied this CHILD's creation, not the
                            # parent process; don't silently promote it to a kill
                            # request or pretend that file recovery occurred.
                            outbox.append("track_a_command_preempted", {
                                "execution_mode": "kernel_fastpath",
                                "pid": event.pid,
                                "parent_pid": event.fields.get("parent_pid"),
                                "rule_id": event.fields.get("matched_rule_id"),
                                "process_create_time": event.fields.get("process_create_time"),
                                "process_creation_denied": True,
                                "parent_termination_requested": False,
                                "recovery_requested": False,
                                "network_cutoff_requested": False,
                            })
                        elif (event.event_type == 1 and
                              event.fields.get("matched_rule_id") == 1009):
                            outbox.append("track_a_command_audit_only", {
                                "execution_mode": "kernel_fastpath_audit",
                                "pid": event.pid, "rule_id": 1009,
                                "process_creation_denied": False,
                                "malware_verdict_confirmed": False,
                            })
                    a_candidate = (track_a.ingest(event, registry) if track_a and
                                   (not pipeline or event.filetime>=pipeline.started_filetime) else None)
                    if a_candidate and retention: retention.protect(a_candidate['pid'],a_candidate['create_time'],'track_a')
                    if a_candidate and pipeline:
                        pipeline.submit("A", a_candidate, pid=a_candidate["pid"],
                            generation=a_candidate["create_time"], path=a_candidate["path"], filetime=event.filetime)
                    if a_candidate and responder:
                        # Check losses again immediately before any destructive action.
                        if reader.status().get("events_dropped") != dropped_before:
                            registry.invalidate()
                            outbox.append("track_a_deferred", {"reason": "driver_loss", "no_live_response": True})
                        else:
                            a_pid, generation = a_candidate["pid"], a_candidate["create_time"]
                            incident_id = str(uuid.uuid5(uuid.NAMESPACE_OID, f"RansomGuard:TrackA:{a_pid}:{generation}"))
                            if response_ledger.claim(incident_id=incident_id, pid=a_pid, process_create_time=generation):
                                outbox.append("track_a_corroborated", a_candidate, incident_id=incident_id)
                                stamp = filetime_to_iso(event.filetime)
                                try:
                                    result = responder.respond(track="A", process=ProcessInstance(a_pid, generation),
                                        recovery_plan_provider=lambda stamp=stamp: recovery_plan_from_template(
                                            args.response_manifest_template, incident_at=stamp),
                                        recovery_required=True, track_a_confirmed=True,
                                        explicit_authorization=True, incident_id=incident_id)
                                except Exception:
                                    response_ledger.finish(incident_id, state="REVIEW_REQUIRED", reason="unexpected_live_response_exception")
                                    raise
                                response_ledger.finish(incident_id, state=result.state, reason=result.reason)
                                if publisher:
                                    a_outcomes=publisher.publish_live_result(result,
                                        protected_root=config.get("recovery", {}).get("protected_root", ""),
                                        observed_path=a_candidate["path"], track_a_corroborated=True)
                                    if retention: retention.resolution(result,a_outcomes)
                                response_results[result.state] = response_results.get(result.state, 0) + 1
                    for record in triage.ingest(event, correlated_create_time=correlated_create_time,
                                                ignore_file_evidence=self_storage_io,
                                              identity_source=registry.identity_source):
                        if record.kind in ('track_b_candidate', 'track_b_deferred'):
                            record.payload['identity_resolution'] = dict(registry.identity_resolution)
                        outbox.append(record.kind, record.payload)
                        if retention and record.kind in ("track_b_candidate","track_b_deferred"):
                            retention.protect(record.payload.get("pid",event.pid),record.payload.get("correlated_process_create_time"),record.kind)
                        if args.live_track_b and not self_storage_io and (responder is not None or pipeline is not None) and record.kind == "track_b_candidate":
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
                            if pipeline:
                                pipeline.candidate_b(payload)
                                continue
                            incident_id = str(uuid.uuid5(uuid.NAMESPACE_OID,
                                                          f"RansomGuard:TrackB:{event.pid}:{create_time}"))
                            if not response_ledger.claim(incident_id=incident_id,
                                                         pid=event.pid,
                                                         process_create_time=create_time):
                                outbox.append("automatic_response_duplicate_skipped", {
                                    "execution_mode": "live_response",
                                    "incident_id": incident_id,
                                    "reason": "previous_durable_reservation_requires_review_if_incomplete",
                                    "no_new_side_effects": True,
                                }, incident_id=incident_id)
                                continue
                            outbox.append("automatic_response_reserved", {
                                "execution_mode": "live_response",
                                "incident_id": incident_id,
                                "pid": event.pid, "process_create_time": create_time,
                                "crash_recovery": "manual_review_no_automatic_retry",
                            }, incident_id=incident_id)
                            stamp = filetime_to_iso(event.filetime)
                            provider = (None if args.response_no_recovery_required else
                                        lambda stamp=stamp: recovery_plan_from_template(
                                            args.response_manifest_template, incident_at=stamp))
                            try:
                                result = responder.respond(
                                    track="B", process=ProcessInstance(event.pid, create_time),
                                    jev_state=payload, recovery_plan_provider=provider,
                                    recovery_required=not args.response_no_recovery_required,
                                    incident_id=incident_id, explicit_authorization=True)
                            except Exception as exc:
                                response_ledger.finish(incident_id, state="REVIEW_REQUIRED",
                                                       reason="unexpected_live_response_exception")
                                outbox.append("automatic_response_aborted_for_review", {
                                    "execution_mode": "live_response",
                                    "incident_id": incident_id,
                                    "error_type": type(exc).__name__,
                                    "no_automatic_retry": True,
                                }, incident_id=incident_id)
                                raise
                            response_ledger.finish(incident_id, state=result.state,
                                                   reason=result.reason)
                            if publisher:
                                outcomes = publisher.publish_live_result(
                                    result, protected_root=config.get("recovery", {}).get("protected_root", ""),
                                    observed_path=raw_path)
                                if retention: retention.resolution(result,outcomes)
                                if outcomes:
                                    outbox.append("local_ui_live_response_notice", {
                                        "execution_mode": "best_effort_ui", "incident_id": incident_id,
                                        "results": outcomes, "ui_acknowledged": False}, incident_id=incident_id)
                            response_results[result.state] = response_results.get(result.state, 0) + 1
                            print(json.dumps({"incident_id": result.incident_id, "state": result.state,
                                              "reason": result.reason, "pid": event.pid}, ensure_ascii=False))
                    if not self_storage_io:
                        outcome="not_sent"
                        if publisher:
                            outcome=publisher.publish_event(event,event_id=raw_id)
                        if retention: retention.finish(raw_id,outcome)
                        if not getattr(args, "quiet_events", False):
                            print(json.dumps({"kind": event.kind, "pid": event.pid, "sequence": event.sequence}, ensure_ascii=False))
                        count += 1
                # A record-count-only cadence can starve health when each FULL
                # SQLite commit is slow. Poll real status at record boundaries
                # after one second too; never fabricate an independent heartbeat.
                if raw_events_read % args.status_every == 0 or time.monotonic()-last_status_poll>=1:
                    if storage_batch:storage_batch.flush()
                    new_status = reader.status()
                    cumulative_status = counters.observe(new_status)
                    maintenance.tick(new_status)
                    response_health(new_status)
                    health.metadata['counter_totals'] = dict(counters.state.get('totals', {}))
                    health.metadata['pending_intake'] = reader.queue.qsize() if hasattr(reader, 'queue') else 0
                    health.publish(new_status, intake=reader.diagnostics() if prefetch else None)
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
                        publisher.publish_status(cumulative_status, sequence=event.sequence)
                    last_status_poll = time.monotonic()
        except KeyboardInterrupt:
            if raw is not None:
                outbox.preserve_intake([raw], 'interrupted_in_flight_record_may_duplicate_processed_event')
            pass
        except Exception:
            if raw is not None:
                outbox.preserve_intake([raw], 'failed_in_flight_record_may_duplicate_processed_event')
            raise
        finally:
            registry.close()
            if internal_collection:internal_collection.close()
            if storage_batch:storage_batch.flush()
            if pipeline:
                pipeline.request_stop()
                # Continue persisting incoming raw evidence while an already
                # started recovery finishes; never close its driver underneath it.
                while not pipeline.jobs.stopped:
                    tail = reader.read()
                    if tail is not None: outbox.preserve_intake([tail], "response_shutdown_unprocessed")
                pipeline.close()
            installer_drain.finish()
            maintenance.close(stopping=health.stop_requested())
            counters.observe(reader.status(), force=True)
            if prefetch and shared_reader is None:
                pending = reader.stop_and_drain()
                outbox.preserve_intake(pending, 'intake_shutdown_unprocessed')
                outbox.append("intake_buffer_stopped",{**reader.diagnostics(),"shutdown_records_preserved":len(pending)})
            outbox.append("observer_stopped", {"execution_mode": "observation", "driver_status": reader.status(),
                                               "resident_worker": getattr(args, '_resident_info', None),
                                               "driver_connection_retained": shared_reader is not None,
                                               "events_read": raw_events_read,
                                               "events_recorded": count,
                                               "observer_storage_events_skipped": storage_events_skipped,
                                               "triage_diagnostics": triage.stats(),
                                               "local_ui_diagnostics": publisher.diagnostics() if publisher else None,
                                               "local_ui_no_ack": not getattr(args, "ui_durable", False),
                                               "ui_delivery": ui_sink.diagnostics() if getattr(args, "ui_durable", False) and ui_sink else None,
                                               "live_response_enabled": live_any,
                                               "durable_response_ledger_enabled": live_any,
                                               "live_response_results": response_results})
            from .console_stream import close_outputs
            close_outputs()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="RansomGuard restore/JEV v0.5.0: observe by default; explicitly authorized lab response")
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
    observe.add_argument("--ui-durable", action="store_true", help="Persist new UI events until the dashboard commits and acknowledges them (requires --ui)")
    observe.add_argument("--ready-file", help="Local launcher handshake written only after driver registration and outbox startup")
    observe.add_argument("--ui-file-rate", type=int, default=10, help="Deprecated compatibility argument; file events are no longer sampled")
    observe.add_argument("--prefetch-events", type=int, choices=range(0,131073), metavar="0..131072", default=0, help="Bounded passive intake buffer; 384 MiB raw-byte limit; no event eviction")
    observe.add_argument("--live-console", action="store_true", help="Show actual received kernel events in a bounded collector console")
    observe.add_argument("--quiet-events", action="store_true", help="Suppress per-event console writes; durable raw records are unchanged")
    observe.add_argument("--resident", action="store_true", help="Keep passive kernel intake alive across Python worker replacements")
    observe.add_argument("--resident-start-gate", help="Initial migration only: local gate opened after the previous process exits")
    observe.add_argument("--status-every", type=int, default=100, help="Poll kernel dropped-event counters every N received events")
    observe.add_argument("--async-response", action="store_true", help="Collect evidence and run durable live responses independently of intake")
    observe.add_argument("--live-track-a", action="store_true", help="OPT-IN lab response to corroborated high-entropy parent write plus kernel child denial")
    observe.add_argument("--live-track-b", action="store_true", help="OPT-IN automatic Track B on approved lab paths; may block entire VM network")
    observe.add_argument("--response-state-db", help="Durable host-wide incident hold DB")
    observe.add_argument("--response-path-prefix", help="Exact approved NT test directory prefix (\\\\Device\\HarddiskVolume3\\RG_Test)")
    observe.add_argument("--response-manifest-template", help="Fixed operator-approved lab VSS file manifest; snapshot selected AFTER exit")
    observe.add_argument("--response-no-recovery-required", action="store_true", help="Lab experiment with no file recovery required")
    observe.add_argument("--authorize-live", action="store_true", help="Allow real JEV/kernel/firewall actions")
    observe.add_argument("--confirm-isolated-vm", action="store_true", help="Confirm THIS IS AN ISOLATED VM; network cutoff is PC-WIDE")
    observe.add_argument("--confirm-internal-test", action="store_true", help="Approve internal testing and PC-WIDE containment on this PC")
    export = sub.add_parser("export-events")
    export.add_argument("--db", required=True)
    export.add_argument("--output", required=True)
    proposal = sub.add_parser("propose-recovery", help="READ ONLY: operator-review manifest proposal from saved write attempts")
    proposal.add_argument("--db", required=True, help="Existing event outbox SQLite database")
    proposal.add_argument("--pid", required=True, type=int)
    proposal.add_argument("--create-time", required=True, type=int, help="Exact kernel process creation FILETIME")
    proposal.add_argument("--path-prefix", required=True, help=r"Exact approved NT directory, e.g. \Device\HarddiskVolume3\RG_Test")
    proposal.add_argument("--max-files", type=int, default=500)
    proposal.add_argument("--output", help="Optional JSON proposal only; NEVER a live restore plan")
    attempts = sub.add_parser("response-status", help="READ ONLY: show durable auto-response reservations after observer restart")
    attempts.add_argument("--db", required=True)
    attempts.add_argument("--limit", type=int, default=100)
    send = sub.add_parser("send-events", help="Explicitly send one outbox batch using the PROPOSED backend ACK contract")
    send.add_argument("--db", required=True)
    send.add_argument("--endpoint", required=True)
    send.add_argument("--token-env", default="RANSOMGUARD_DASHBOARD_TOKEN")
    plan = sub.add_parser("plan-network", help="Print a policy plan; does NOT apply WFP/firewall changes")
    plan.add_argument("--config", required=True)
    plan.add_argument("--resolve", action="store_true", help="Explicitly resolve endpoint DNS addresses now")
    catalog = sub.add_parser('recovery-catalog', help='READ ONLY: hash a bounded protected directory from an existing VSS; does not enable recovery')
    catalog.add_argument('--volume-root', required=True)
    catalog.add_argument('--protected-root', required=True)
    catalog.add_argument('--snapshot-id')
    catalog.add_argument('--max-age-seconds', type=int, default=7200)
    catalog.add_argument('--max-files', type=int, default=5000)
    catalog.add_argument('--output', required=True, help='New manifest JSON file; existing files are never replaced')
    snapshots = sub.add_parser("snapshot-inventory", help="Read an exact Windows volume's existing VSS metadata; does not create or restore")
    snapshots.add_argument("--volume-root", required=True, help="Local volume root, for example C:\\")
    snapshots.add_argument("--output", help="Optional JSON inventory output file")
    tick = sub.add_parser("snapshot-run", help="Run one REAL Windows VSS hourly tick with a durable duplicate guard")
    retention = sub.add_parser('snapshot-retention', help='Preview owned-only retention; --apply deletes exact eligible owned IDs')
    retention.add_argument('--state-db', required=True)
    retention.add_argument('--volume-root', required=True)
    retention.add_argument('--apply', action='store_true')
    retention.add_argument('--output')
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
            if args.resident:
                from .resident import run
                return run(args)
            return _observe(args)
        if args.command == "export-events":
            with Outbox(args.db) as outbox:
                print(json.dumps({"exported_events": outbox.export_jsonl(args.output)}))
        elif args.command == "propose-recovery":
            return _propose_recovery(args)
        elif args.command == "response-status":
            if not 1 <= args.limit <= 1000:
                raise ValueError("response-status limit must be 1..1000")
            return _response_status(args)
        elif args.command == "send-events":
            from .dashboard import send_batch
            with Outbox(args.db) as outbox:
                print(json.dumps({"acknowledged_events": send_batch(outbox, args.endpoint, token_env=args.token_env)}))
        elif args.command == "plan-network":
            config = _load_config(args.config)
            print(json.dumps(make_plan(config["network"], resolve=args.resolve), ensure_ascii=False, indent=2))
        elif args.command == 'snapshot-retention':
            from .snapshot_retention import SnapshotRetention, load_config
            from .recovery import volume_id_for_root
            result = SnapshotRetention(args.state_db, load_config(args.state_db)).run(
                volume_id_for_root(args.volume_root), apply=args.apply)
            encoded = json.dumps(result, ensure_ascii=False, indent=2)
            if args.output:
                Path(args.output).write_text(encoded, encoding='utf-8')
            print(encoded)
            return 0 if result['status'] == 'ready' else 2
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
        elif args.command == 'recovery-catalog':
            from .recovery_catalog import create_manifest
            target = Path(args.output)
            if target.exists():
                raise ValueError('Catalog output exists; choose a new file to preserve prior evidence')
            result = create_manifest(volume_root=args.volume_root, protected_root=args.protected_root,
                                     snapshot_id=args.snapshot_id, max_age_seconds=args.max_age_seconds,
                                     max_files=args.max_files)
            with target.open('x', encoding='utf8') as stream:
                stream.write(json.dumps(result, ensure_ascii=False, indent=2)+'\n')
            print(json.dumps({'manifest':str(target),'files':len(result['manifest']),
                              'snapshot_id':result['snapshot_id'],'activated':False}))
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
            print(json.dumps({"version": "0.5.0", "kernel_compatibility": "v0.8.0/v0.9.0 ABI v1",
                              "windows_driver_build": "separate_kernel_repository_signed_package_required",
                              "windows_event_observation": "implemented_requires_vm_validation",
                              "local_ui_ipc": "durable_commit_ack_with_legacy_best_effort_option",
                              "generation_bound_terminate_ioctl": "available_in_explicit_live_response_requires_vm_validation",
                              "high_entropy_track_b_intake": "implemented_observation_and_opt_in_lab_response",
                              "track_a_kernel_preempt_notice": "child_preemption_and_opt_in_generation_bound_parent_response",
                              "durable_automatic_response_ledger": "implemented_no_retry_after_crash",
                              "preop_recovery_manifest_proposal": "implemented_read_only_operator_review_required",
                              "track_a_b_simulation": True, "durable_outbox": True,
                              "jev_module": "implemented_live_credentials_and_response_validation_required",
                              "recovery_module": "implemented_requires_windows_vss_validation",
                              "snapshot_creation": "implemented_windows_cim_requires_vm_validation",
                              "snapshot_schedule": "hourly_only_install_script_provided_not_installed_here",
                              "network_scope": "host_outbound", "host_firewall_daemon_ipc": "implemented_requires_windows_vm_validation",
                              "durable_global_incident_holds": True,
                              "track_a_b_live_response": "opt_in_scoped_track_a_b_async_response",
                              "firewall_ipc_ack_is_wfp_proof": False,
                              "network_limits": ["daemon_bidirectional_block_outbound_permits", "daemon_dns_exception", "separate_program_specific_jev_policy_required"],
                              "automated_observer_response": "track_a_b_finite_authorized_scope", "process_network_enforcement": False,
                              "file_io_containment": False,
                              "automatic_live_response": "restricted_track_a_b_requires_explicit_profile",
                              "dashboard_compatibility": "durable_id_commit_ack_and_bounded_batch_negotiation",
                              "recovery_catalog": "bounded_read_only_vss_inventory_hashes_exact_snapshot",
                              "automatic_snapshot_max_age_seconds": 7200,
                              "evaluation": "offline_labelled_holdout_metrics_no_automatic_policy_promotion",
                              "runtime_health": "not_measured_by_this_static_capabilities_command"}, indent=2))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

