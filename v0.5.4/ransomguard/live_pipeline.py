"""Automatic evidence window and asynchronous, explicitly scoped lab response."""
from contextlib import nullcontext
import threading
import time
import uuid
import struct
import os

from .evidence_window import EvidenceWindow
from .response_jobs import ResponseJobs
from .live_response import LiveResponseCoordinator
from .incidents import ProcessInstance
from .firewall_control import FirewallHoldManager
from .jev import JevClient, JevConfig
from .protocol import filetime_to_iso, MAGIC, VERSION, UPDATE_POLICY
from .response_commands import recovery_plan_from_template
from .retention import RawRetention
from .ui_delivery import DurableUiDelivery
from .ui_pipe import WindowsUiPipe
from .ui_bridge import UiBestEffortPublisher


class LivePipeline:
    def __init__(self, outbox, reader, args, profile, thresholds, config, initial_status):
        self.outbox, self.reader, self.args = outbox, reader, args
        self.driver = getattr(reader, 'reader', reader)
        self.profile, self.thresholds, self.config = profile, thresholds, config
        self.baseline = (initial_status.get('events_dropped'), initial_status.get('events_flushed'))
        if any(type(x) is not int for x in self.baseline):
            raise ValueError('Verified driver loss counters are required')
        self.invalid = threading.Event()
        self.started_filetime = int((time.time()+11644473600)*10_000_000)
        self.window = EvidenceWindow(args.response_path_prefix, seconds=config.get('evidence_window_seconds',2.0))
        self.registry = None
        self.next_evidence_peek = 0.0
        # Keep the pre-live policy across in-process worker replacements.
        # Otherwise a second worker would mistake our own BLOCK mode for the
        # original passive policy and leave it enabled after live shutdown.
        self.original_policy = getattr(args, '_live_policy_before', dict(initial_status))
        args._live_policy_before = self.original_policy
        # A previous drained maintenance owner can leave process monitoring
        # paused. Automatic correlation requires fresh lifecycle events.
        self.driver._ioctl(UPDATE_POLICY, struct.pack('<IIIII', MAGIC, VERSION,
            2 if args.live_track_a or config.get('kernel_child_preemption') is True else initial_status['fastpath_mode'], 1,
            initial_status['self_protect_enabled']), 0, 5000)
        self.jobs = ResponseJobs(outbox, self._respond).start()

    def defer(self, items):
        for item in items:
            self.outbox.append('automatic_evidence_deferred', item)

    def observe(self, event, registry):
        self.registry = registry
        if registry.loss_detected:
            self.invalid.set()
        self.defer(self.window.observe(event, registry))

    def candidate_b(self, payload):
        if payload['pid'] == os.getpid():
            self.defer([payload | {'deferred_reason':'collector_process_requires_review'}])
            return
        if payload.get('source_filetime',0)<self.started_filetime:
            self.defer([payload | {'deferred_reason':'evidence_predates_response_worker'}])
            return
        outcome = self.window.begin(payload)
        if outcome == 'evidence_window_full':
            self.defer([payload | {'deferred_reason': outcome}])

    def submit(self, track, payload, *, pid, generation, path, filetime):
        if pid == os.getpid():
            self.defer([payload | {'deferred_reason':'collector_process_requires_review'}])
            return
        if filetime<self.started_filetime:
            self.defer([payload | {'deferred_reason':'evidence_predates_response_worker'}])
            return
        job = {'id': str(uuid.uuid5(uuid.NAMESPACE_OID, f'RansomGuard:Track{track}:{pid}:{generation}')),
               'track': track, 'pid': pid, 'generation': generation, 'path': path,
               'filetime': filetime, 'evidence': payload,
               'deadline': filetime / 10_000_000 - 11644473600 + 30}
        outcome = self.jobs.enqueue(job)
        if track == 'A' and outcome not in ('scope_change_in_progress', 'stopping'):
            self.window.pending.pop((pid, generation), None)
        self.outbox.append('automatic_response_queued',
                           {'pid': pid, 'process_create_time': generation, 'track': track,
                            'queue_state': outcome, 'asynchronous': True}, incident_id=job['id'])

    def tick(self):
        # A malformed raw can invalidate the registry before observe() runs.
        # Never peek around that invalidation or authorize from its old window.
        if self.registry is not None and self.registry.loss_detected:
            self.invalid.set()
            self.defer(self.window.invalidate('sequence_or_driver_loss'))
        caught_up = not hasattr(self.reader, 'queue')
        if self.window.pending and self.registry is not None and time.monotonic() >= self.next_evidence_peek:
            from .evidence_peek import pending_evidence
            self.next_evidence_peek = time.monotonic() + .25
            try:
                snapshot = pending_evidence(self.reader, self.registry,
                                            {pid: generation for pid, generation in self.window.pending},
                                            validated_through=min(item['last_collection_sequence']
                                                for _, item in self.window.pending.values()))
                if snapshot is not None:
                    events, metrics = snapshot
                    for event, local_registry in events:
                        self.defer(self.window.observe(event, local_registry))
                    caught_up = True
                    self.last_evidence_peek = metrics
                    for _, item in self.window.pending.values():
                        item['queue_evidence_inspection'] = metrics
                        if metrics['validated_through'] is not None:
                            item['last_collection_sequence'] = max(item['last_collection_sequence'], metrics['validated_through'])
            except (ValueError, struct.error):
                self.invalid.set()
                self.defer(self.window.invalidate('queued_evidence_invalid'))
        if self.args.live_track_a:
            for proof in self.window.confirmed_a():
                self.submit('A', proof, pid=proof['pid'], generation=proof['create_time'],
                            path=proof['path'], filetime=proof['rule_filetime'])
        for item in self.window.due(caught_up=caught_up):
            self.submit('B', item, pid=item['pid'], generation=item['correlated_process_create_time'],
                        path=item['evidence']['trigger_path'], filetime=item['source_filetime'])
        if self.jobs.error:
            raise RuntimeError('Response worker failed: ' + self.jobs.error)

    def _respond(self, job, outbox, cancelled):
        getattr(outbox, 'start_response_timing', lambda: None)()
        note_timing = getattr(outbox, 'note_response_timing', lambda phase, start: None)
        if job.get('resume_jev_review'):
            outbox.append('late_track_a_review_upgraded', {
                'pid': job['pid'], 'process_create_time': job['generation'],
                'previous_review_reason': job['previous_review_reason'],
                'corroborated_evidence': job['evidence'], 'previous_audit_preserved': True,
            }, incident_id=job['id'])
        def guard():
            if job['pid']==os.getpid() or self.invalid.is_set() or cancelled.is_set() or time.time() > job['deadline']:
                return False
            started = time.perf_counter()
            try:
                status = self.driver.status()
            finally:
                note_timing('driver_status_guard', started)
            return (status.get('events_dropped'), status.get('events_flushed')) == self.baseline
        args = self.args
        if job['track']=='B' and args.response_manifest_template and guard():
            from .file_evidence import measure_changes
            try:
                measured=measure_changes(args.response_manifest_template,job['evidence'],
                                         approved_prefix=args.response_path_prefix)
                job['evidence']['verified_write_effects']=measured
                outbox.append('automatic_file_evidence',measured,incident_id=job['id'])
            except (OSError,ValueError):
                job['evidence']['file_comparison_unavailable']=True
        if job['track']=='B':
            if job.get('resume_b_review'):
                from .late_track_b import new_verified_facts
                if not guard() or not new_verified_facts(job):
                    outbox.append('track_b_reassessment_deferred',{'reason':'no_new_verified_file_effects','hold_retained':True},incident_id=job['id'])
                    return 'REVIEW_REQUIRED','jev_ambiguous_demo_threshold'
                job['evidence']['reassessment_prior_changed_paths']=job['prior_changed_paths']
                outbox.append('track_b_new_evidence_reassessment',{'prior_changed_paths':job['prior_changed_paths'],'verified_write_effects':job['evidence']['verified_write_effects'],'thresholds_unchanged':True},incident_id=job['id'])
            # Retain the measured first evidence for a later bounded upgrade.
            import json
            with outbox.db:
                outbox.db.execute('UPDATE response_jobs SET payload=? WHERE id=? AND state=\'RUNNING\'',(json.dumps(job,ensure_ascii=False),job['id']))
            outbox.append('automatic_jev_evidence',job['evidence'],incident_id=job['id'])
        provider = (None if args.response_no_recovery_required else
                    lambda: recovery_plan_from_template(args.response_manifest_template,
                                                         incident_at=filetime_to_iso(job.get('recovery_filetime', job['filetime']))))
        from pathlib import Path
        from .review_pause import PauseJournal, ReviewPause
        pause_journal = PauseJournal(Path(outbox.path).parent / 'review-pauses.sqlite3')
        def additional_file_evidence(evidence):
            if not args.response_manifest_template or not guard():
                return None
            from .file_evidence import measure_changes
            evidence['verified_write_effects'] = measure_changes(args.response_manifest_template,
                evidence, approved_prefix=args.response_path_prefix)
            outbox.append('review_additional_file_evidence', evidence['verified_write_effects'], incident_id=job['id'])
            return evidence
        with FirewallHoldManager(args.response_state_db, self.profile) as owner:
            from .process_identity import WindowsProcessSession
            def timed_process(process):
                started = time.perf_counter()
                try:
                    return WindowsProcessSession(process)
                finally:
                    note_timing('process_open_and_generation', started)
            responder = LiveResponseCoordinator(outbox=outbox, firewall=owner, driver=self.driver,
                jev=JevClient(JevConfig(base_url=self.profile.jev_url)),
                thresholds=self.thresholds, decision_guard=guard, process_factory=timed_process,
                review_followup=ReviewPause(pause_journal, additional_file_evidence))
            result = responder.respond(track=job['track'], process=ProcessInstance(job['pid'], job['generation']),
                jev_state=job['evidence'], recovery_plan_provider=provider,
                recovery_required=not args.response_no_recovery_required,
                resume_jev_review=job.get('resume_jev_review', False),
                resume_b_review=job.get('resume_b_review', False),
                track_a_confirmed=job['track']=='A', explicit_authorization=True, incident_id=job['id'])
        if result.exit_confirmed:
            try:
                pause_journal.mark_exited(result)
            except Exception as error:
                outbox.append('review_exit_journal_unconfirmed',
                    {'error_type': type(error).__name__, 'exit_confirmed': True}, incident_id=job['id'])
        if args.ui:
            if getattr(args, 'ui_durable', False):
                sink = DurableUiDelivery(outbox.path)
                sink.enable_detached_spool()
                sink.use_enqueue_connection(outbox.db)
                # The existing delivery thread consumes these committed rows.
                # Never share the intake producer's SQLite connection here.
                context = nullcontext(sink)
            else:
                sink = None
                context = WindowsUiPipe()
            try:
                with context as actual:
                    outcomes = UiBestEffortPublisher(actual).publish_live_result(result,
                        protected_root=self.config.get('recovery', {}).get('protected_root', ''),
                        observed_path=job['path'], track_a_corroborated=job['track']=='A')
                    if sink:
                        RawRetention(outbox.db).resolution(result, outcomes)
            finally:
                if sink:
                    sink.close()
        return result.state, result.reason

    def request_stop(self):
        self.defer(self.window.invalidate('observer_handover_or_shutdown'))
        self.jobs.request_stop()

    def close(self):
        self.jobs.close()
        self.driver._ioctl(UPDATE_POLICY, struct.pack('<IIIII', MAGIC, VERSION,
            self.original_policy['fastpath_mode'], 1,
            self.original_policy['self_protect_enabled']), 0, 5000)
