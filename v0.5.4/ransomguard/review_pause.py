"""Bounded incident-only suspension; never filters or pauses event collection.

Native API acknowledgement is not proof of immutable, all-thread containment.
Already issued I/O and other processes can continue. Unknown outcomes remain
durable for operator review; timeout/crash never implies benign or auto-resume.
"""
import copy
import ctypes as C
import json
import ntpath
import os
from pathlib import Path
import sqlite3
import time
from contextlib import contextmanager

from .process_identity import WindowsProcessSession, HANDLE, DWORD, BOOL
from .incidents import ProcessInstance


class NativePauseSession(WindowsProcessSession):
    def __init__(self, process):
        super().__init__(process, suspend_access=True)
        try:
            self.nt = C.WinDLL('ntdll')
            for name in ('NtSuspendProcess', 'NtResumeProcess'):
                fn = getattr(self.nt, name)
                fn.argtypes, fn.restype = [HANDLE], C.c_int32
            critical = BOOL()
            fn = self.k.IsProcessCritical
            fn.argtypes, fn.restype = [HANDLE, C.POINTER(BOOL)], BOOL
            if not fn(self.handle, C.byref(critical)) or critical.value:
                raise RuntimeError('Critical status unavailable or critical process')
            sid = DWORD()
            fn = self.k.ProcessIdToSessionId
            fn.argtypes, fn.restype = [DWORD, C.POINTER(DWORD)], BOOL
            if not fn(process.pid, C.byref(sid)) or sid.value == 0:
                raise RuntimeError('Service/session-zero processes excluded')
            path = ntpath.normcase(self.image_path())
            windows = ntpath.normcase(os.environ.get('SystemRoot', r'C:\Windows')).rstrip('\\')
            if (process.pid in (0, 4, os.getpid(), os.getppid())
                    or path.startswith(windows + '\\')
                    or ntpath.basename(path) in ('ransom0-ui.exe', 'r0-fw-daemon.exe',
                        'ransomguard.exe', 'ransom0.exe', 'ransom0_install.exe')
                    or self.is_exited()):
                raise RuntimeError('Protected or exited process excluded')
        except BaseException:
            self.close()
            raise

    def suspend(self):
        if self.is_exited():
            raise RuntimeError('Process exited before suspension')
        status = self.nt.NtSuspendProcess(self.handle)
        if status != 0:
            raise RuntimeError('Suspension outcome uncertain: 0x%08X' % (status & 0xffffffff))

    def resume(self):
        if self.is_exited():
            raise RuntimeError('Process exited before resume')
        status = self.nt.NtResumeProcess(self.handle)
        if status != 0:
            raise RuntimeError('Resume outcome uncertain: 0x%08X' % (status & 0xffffffff))


class PauseJournal:
    """Separate, tiny durable DB. No intake SQLite transaction or network wait."""
    def __init__(self, path):
        self.path = Path(path)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS pauses (incident TEXT PRIMARY KEY, pid INTEGER, generation TEXT, state TEXT, updated REAL, UNIQUE(pid,generation))')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=2)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db:
                yield db
        finally:
            db.close()

    def reserve(self, item):
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT COUNT(*) FROM pauses WHERE state IN ('REQUESTING','SUSPENDED','RESUME_REQUESTED')").fetchone()[0] >= 4:
                raise RuntimeError('Outstanding suspension limit reached; operator review required')
            db.execute("INSERT INTO pauses VALUES (?,?,?,'REQUESTING',?)",
                       (item.incident_id, item.process.pid, str(item.process.create_time), time.time()))

    def transition(self, incident, previous, state):
        with self.connect() as db:
            if db.execute('UPDATE pauses SET state=?,updated=? WHERE incident=? AND state=?',
                          (state, time.time(), incident, previous)).rowcount != 1:
                raise RuntimeError('Pause ownership/state transition refused')

    def get(self, incident):
        with self.connect() as db:
            row = db.execute('SELECT pid,generation,state FROM pauses WHERE incident=?', (incident,)).fetchone()
        return None if row is None else {'pid': row[0], 'generation': int(row[1]), 'state': row[2]}

    def mark_exited(self, item):
        row = self.get(item.incident_id)
        if row and (row['pid'], row['generation']) == (item.process.pid, item.process.create_time):
            self.transition(item.incident_id, row['state'], 'EXIT_CONFIRMED')


def eligible(evidence):
    """Only scoped, corroborated file effects; JEV score alone never qualifies."""
    effects = evidence.get('verified_write_effects', {})
    counts = evidence.get('counts', {})
    return (effects.get('files_changed_sha256', 0) >= 2
            and effects.get('files_unverified') == 0
            and not effects.get('bounded_scan_incomplete', False)
            and counts.get('high_entropy_writes', 0) >= 2
            and counts.get('extension_change_attempts', 0) >= 2)


class ReviewPause:
    def __init__(self, journal, evidence_provider, *, session_factory=NativePauseSession):
        self.journal, self.evidence_provider = journal, evidence_provider
        self.session_factory = session_factory

    def run(self, coordinator, item, evidence, stop):
        """At most one fresh-evidence JEV call. Original deadline still applies."""
        c = coordinator
        item.review_followup = {'phase': 'INELIGIBLE', 'additional_requests': 0,
                                'all_thread_containment_verified': False}
        detail = item.review_followup
        response_started = False
        if not eligible(evidence) or not c._decision_allowed():
            return c._review(item, 'jev_ambiguous_demo_threshold')
        try:
            with self.session_factory(item.process) as session:
                if not c._decision_allowed():
                    return c._review(item, 'evidence_expired_or_collection_invalidated')
                self.journal.reserve(item)
                detail['phase'] = 'REQUESTING'
                c._log(item, 'review_suspend_requested')
                session.suspend()
                self.journal.transition(item.incident_id, 'REQUESTING', 'SUSPENDED')
                detail['phase'] = 'SUSPENDED'
                c._log(item, 'review_suspend_acknowledged', all_thread_containment_verified=False)
                if not c._decision_allowed():
                    return c._review(item, 'evidence_expired_or_collection_invalidated')
                fresh = self.evidence_provider(copy.deepcopy(evidence))
                # Provider must return verified new facts, never merely a new
                # timestamp, score or claim that this process caused damage.
                before = evidence.get('verified_write_effects', {})
                after = (fresh or {}).get('verified_write_effects', {})
                added = set(after.get('changed_relative_paths', [])) - set(before.get('changed_relative_paths', []))
                checked_more = after.get('files_checked', 0) > before.get('files_checked', 0)
                if not fresh or not (added or checked_more):
                    detail['reassessment'] = 'NO_NEW_VERIFIED_FACTS'
                    return c._review(item, 'jev_ambiguous_demo_threshold')
                if (after.get('files_unverified') != 0 or after.get('bounded_scan_incomplete')
                        or not set(before.get('changed_relative_paths', [])).issubset(after.get('changed_relative_paths', []))
                        or not c._decision_allowed()):
                    detail['reassessment'] = 'INCOMPLETE_OR_EXPIRED'
                    return c._review(item, 'jev_ambiguous_demo_threshold')
                detail['additional_requests'] = 1
                c._log(item, 'review_jev_requested', evidence=fresh)
                verdict = c.jev.evaluate(fresh)
                import math
                score = verdict.get('score')
                if (type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1
                        or not isinstance(verdict.get('request_id'), str) or not verdict['request_id']
                        or verdict['request_id'] == item.jev_request_id):
                    raise ValueError('Invalid or reused follow-up verdict')
                c._log(item, 'review_jev_responded', score=score, request_id=verdict['request_id'],
                       request_state=verdict.get('request_state'), decision_thresholds=item.decision_thresholds)
                if not c._decision_allowed():
                    return c._review(item, 'evidence_expired_or_collection_invalidated')
                detail['initial_score'] = item.jev_score
                detail['initial_request_id'] = item.jev_request_id
                item.jev_score, item.jev_request_id = float(score), verdict['request_id']
                item.jev_request_state = verdict.get('request_state')
                item.jev_model = verdict.get('model')
                if score >= c.thresholds.malicious:
                    item.jev_classification = 'malicious'
                    response_started = True
                    result = stop()
                    if result.exit_confirmed:
                        detail['phase'] = 'EXIT_CONFIRMED'
                        try:
                            self.journal.mark_exited(item)
                        except Exception as error:
                            detail['journal_error'] = type(error).__name__
                            c._log(item, 'review_exit_journal_unconfirmed')
                    return result
                if score <= c.thresholds.benign:
                    item.jev_classification = 'benign'
                    self.journal.transition(item.incident_id, 'SUSPENDED', 'RESUME_REQUESTED')
                    detail['phase'] = 'RESUME_REQUESTED'
                    session.resume()
                    self.journal.transition(item.incident_id, 'RESUME_REQUESTED', 'RESUMED')
                    detail['phase'] = 'RESUMED'
                    c._log(item, 'review_resume_acknowledged')
                    return c._release(item, reason='review_jev_benign_after_new_evidence')
                detail['reassessment'] = 'STILL_AMBIGUOUS'
                return c._review(item, 'jev_ambiguous_demo_threshold')
        except Exception as error:
            # If suspension or persistence failed, do not blindly resume or
            # suspend twice. The journal preserves the uncertain transition.
            detail['error_type'] = type(error).__name__
            c._log(item, 'review_followup_unconfirmed', followup=detail)
            return c._review(item, 'review_followup_after_response_unconfirmed' if response_started
                             else 'jev_ambiguous_demo_threshold')


def operator_resume(journal, incident, *, confirmed_safe=False, session_factory=NativePauseSession):
    """Explicit operator decision only. Does NOT release any firewall hold."""
    if confirmed_safe is not True:
        raise PermissionError('Explicit reviewed-safe acknowledgement required')
    row = journal.get(incident)
    if not row or row['state'] != 'SUSPENDED':
        raise RuntimeError('Only an acknowledged owned suspension can be resumed')
    with session_factory(ProcessInstance(row['pid'], row['generation'])) as session:
        journal.transition(incident, 'SUSPENDED', 'RESUME_REQUESTED')
        session.resume()
        journal.transition(incident, 'RESUME_REQUESTED', 'RESUMED_BY_OPERATOR')
    return {'incident_id': incident, 'state': 'RESUMED_BY_OPERATOR', 'network_hold_changed': False}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--journal', required=True)
    parser.add_argument('--incident', required=True)
    parser.add_argument('--resume-reviewed-safe', action='store_true')
    args = parser.parse_args()
    journal = PauseJournal(args.journal)
    print(json.dumps(operator_resume(journal, args.incident, confirmed_safe=True)
                     if args.resume_reviewed_safe else journal.get(args.incident)))
