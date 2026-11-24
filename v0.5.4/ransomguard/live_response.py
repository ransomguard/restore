"""Explicit Track A/B live response backed by the existing external daemon.

Track A: host outbound block request -> generation-bound kill -> verified exit
-> explicitly planned pre-incident VSS recovery -> release the incident hold.
Track B: same global block -> allowlisted JEV request -> threshold decision ->
kill/recovery or benign release; ambiguous/error means retain the hold for review.

High-entropy file events alone are only Track B candidates. The caller must
verify an exact live process generation and explicitly authorize real effects.
Missing recovery plans NEVER cause blind writes; the network hold is retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import math
import os
import time
from typing import Any, Callable
import uuid

from .incidents import ProcessInstance
from .jev import JevClient
from .outbox import Outbox
from .process_identity import WindowsProcessSession
from .recovery import RecoveryEngine, RecoveryPlan


@dataclass(frozen=True)
class ResponseThresholds:
    benign: float = 0.2
    malicious: float = 0.8

    def __post_init__(self) -> None:
        if any(type(x) not in (float, int) or not math.isfinite(x) for x in (self.benign, self.malicious)):
            raise ValueError("Thresholds must be finite numbers")
        if not 0 <= self.benign < self.malicious <= 1:
            raise ValueError("Thresholds must satisfy 0 <= benign < malicious <= 1")


@dataclass
class ResponseResult:
    incident_id: str
    track: str
    process: ProcessInstance
    state: str = "DETECTED"
    reason: str | None = None
    jev_score: float | None = None
    jev_request_id: str | None = None
    jev_classification: str | None = None
    jev_request_state: dict | None = None
    jev_model: str | None = None
    decision_thresholds: dict[str, float] | None = None
    firewall_hold_retained: bool = False
    firewall_policy_acknowledged: bool = False
    exit_confirmed: bool = False
    kernel_termination_accepted: bool = False
    recovery_verified: bool = False
    recovery_snapshot_id: str | None = None
    recovered_files: list[str] = field(default_factory=list)
    recovery_root: str | None = None
    review_followup: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"incident_id": self.incident_id, "track": self.track,
                "pid": self.process.pid, "process_create_time": self.process.create_time,
                "state": self.state, "reason": self.reason, "jev_score": self.jev_score,
                "jev_request_id": self.jev_request_id,
                "jev_classification": self.jev_classification,
                "jev_request_state": self.jev_request_state, "jev_model": self.jev_model, "decision_thresholds": self.decision_thresholds,
                "firewall_hold_retained": self.firewall_hold_retained,
                "firewall_policy_acknowledged": self.firewall_policy_acknowledged,
                "kernel_termination_accepted": self.kernel_termination_accepted,
                "exit_confirmed": self.exit_confirmed, "recovery_verified": self.recovery_verified,
                "recovery_snapshot_id": self.recovery_snapshot_id,
                "recovered_files": self.recovered_files, "recovery_root": self.recovery_root,
                "review_followup": self.review_followup,
                "network_scope": "host_outbound", "wfp_enforcement_verified": False}


class LiveResponseCoordinator:
    """One-shot synchronous coordinator; all side-effects are injectible for tests.

    This class does not install a scheduled task, register with a driver, or
    start a firewall/UI daemon. Caller supplies an already opened reader.
    Real calls are gated per invocation by explicit_authorization=True.
    """

    def __init__(self, *, outbox: Outbox, firewall: Any, driver: Any,
                 jev: JevClient | Any | None = None, recovery: RecoveryEngine | Any | None = None,
                 process_factory: Callable[[ProcessInstance], Any] = WindowsProcessSession,
                 thresholds: ResponseThresholds = ResponseThresholds(),
                 exit_timeout_ms: int = 5000,
                 decision_guard: Callable[[], bool] | None = None,
                 review_followup: Any | None = None) -> None:
        if type(exit_timeout_ms) is not int or not 100 <= exit_timeout_ms <= 60_000:
            raise ValueError("exit_timeout_ms must be between 100 and 60000")
        self.outbox = outbox
        self.firewall = firewall
        self.driver = driver
        self.jev = jev
        self.recovery = recovery or RecoveryEngine()
        self.process_factory = process_factory
        self.thresholds = thresholds
        self.exit_timeout_ms = exit_timeout_ms
        self.decision_guard = decision_guard
        self.review_followup = review_followup

    def _decision_allowed(self):
        try:
            return self.decision_guard is None or self.decision_guard() is True
        except Exception:
            return False

    def _log(self, item: ResponseResult, kind: str, **extra: Any) -> None:
        self.outbox.append(kind, {
            "execution_mode": "live_response", "track": item.track,
            "evidence_mode": os.environ.get("RANSOM0_EVIDENCE_MODE", "unknown"),
            "run_id": os.environ.get("RANSOM0_TEST_RUN_ID", ""),
            "pid": item.process.pid, "process_create_time": item.process.create_time,
            "state": item.state, "network_scope": "host_outbound",
            "wfp_enforcement_verified": False, **extra,
        }, incident_id=item.incident_id)

    def _review(self, item: ResponseResult, reason: str) -> ResponseResult:
        item.state = "REVIEW_REQUIRED"
        item.reason = reason
        if item.firewall_hold_retained:
            try:
                self.firewall.retain_for_review(item.incident_id)
            except Exception:
                # Never reinterpret an uncertain persistence result as safe to
                # unlock. The outbox records the failed review action too.
                self._log(item, "firewall_review_retention_unconfirmed")
        self._log(item, "review_required", reason=reason, hold_retained=item.firewall_hold_retained)
        return item

    def _release(self, item: ResponseResult, *, reason: str) -> ResponseResult:
        item.state = "RELEASE_REQUESTED"
        self._log(item, "release_requested", reason=reason)
        try:
            status = self.firewall.release(item.incident_id)
        except Exception:
            return self._review(item, "firewall_release_not_confirmed")
        item.firewall_hold_retained = False
        item.state = "RELEASED"
        item.reason = reason
        self._log(item, "incident_firewall_hold_released", remaining_holds=status["remaining_holds"],
                  firewall_off_requested=status["firewall_off_requested"])
        return item

    def _stop_and_restore(self, item: ResponseResult, *, recovery_plan: RecoveryPlan | None,
                          recovery_required: bool,
                          recovery_plan_provider: Callable[[], RecoveryPlan] | None = None) -> ResponseResult:
        if not self._decision_allowed():
            return self._review(item, 'evidence_expired_or_collection_invalidated')
        try:
            with self.process_factory(item.process) as session:
                if session.is_exited():
                    item.exit_confirmed = True
                    self._log(item, "process_exit_confirmed", source="same_generation_handle_already_exited")
                else:
                    if not self._decision_allowed():
                        return self._review(item, 'evidence_expired_or_collection_invalidated')
                    item.state = "TERMINATION_REQUESTED"
                    self._log(item, "termination_requested")
                    result = self.driver.terminate_checked(
                        pid=item.process.pid, expected_create_time=item.process.create_time,
                        reason=0xA001 if item.track == "A" else 0xB001,
                        explicit_authorization=True)
                    if result.get("request_accepted") is not True:
                        return self._review(item, "kernel_termination_not_accepted")
                    item.kernel_termination_accepted = True
                    self._log(item, "kernel_termination_request_acknowledged",
                              kernel_ntstatus=result.get("kernel_ntstatus"), exit_confirmed=False)
                    if not session.wait_exit(self.exit_timeout_ms):
                        return self._review(item, "process_exit_not_confirmed")
                    item.exit_confirmed = True
                    self._log(item, "process_exit_confirmed", source="same_generation_process_handle")
        except (OSError, RuntimeError, ValueError, TimeoutError):
            return self._review(item, "live_process_identity_or_termination_unavailable")

        item.state = "EXIT_CONFIRMED"
        if not recovery_required:
            return self._release(item, reason="exit_confirmed_recovery_not_required")
        if recovery_plan is None and recovery_plan_provider is not None:
            from .recovery import SnapshotFreshnessError
            try:
                recovery_plan = recovery_plan_provider()
            except SnapshotFreshnessError:
                return self._review(item, "recovery_snapshot_stale_or_not_preincident")
            except (OSError, RuntimeError, ValueError, TimeoutError) as error:
                self._log(item, "recovery_plan_error", error_type=type(error).__name__,
                          detail=str(error)[:500])
                return self._review(item, "recovery_plan_selection_failed")
        if recovery_plan is None:
            return self._review(item, "verified_recovery_plan_missing")
        if not isinstance(recovery_plan, RecoveryPlan):
            return self._review(item, "recovery_plan_type_invalid")
        # The recovery engine independently re-enumerates the chosen VSS and
        # validates exact protected paths; only verified exit authorizes writes.
        item.state = "RESTORING"
        item.recovery_snapshot_id = recovery_plan.snapshot.snapshot_id
        self._log(item, "restore_started", job_id=recovery_plan.job_id,
                  snapshot_id=recovery_plan.snapshot.snapshot_id)
        try:
            result = self.recovery.execute(recovery_plan, allow_live=True, containment_confirmed=True)
        except (OSError, RuntimeError, ValueError, TimeoutError):
            return self._review(item, "restore_operation_failed")
        if result.get("status") != "verified" or result.get("verified") is not True:
            self._log(item, "restore_incomplete", files_total=result.get("files_total"),
                      files_failed=result.get("files_failed"))
            return self._review(item, "restore_not_verified")
        item.recovery_verified = True
        item.recovery_root = recovery_plan.protected_root
        if result.get("files_verified") == len(recovery_plan.entries):
            item.recovered_files = sorted({recovery_plan.protected_root.rstrip("\\") + "\\" + e.relative_path for e in recovery_plan.entries})
        self._log(item, "restore_verified", snapshot_id=recovery_plan.snapshot.snapshot_id,
                  job_id=recovery_plan.job_id, files_verified=result.get("files_verified"))
        return self._release(item, reason="exit_and_restore_verified")

    def respond(self, **kwargs) -> ResponseResult:
        # Selection, restore and durable review outcome share the deletion gate.
        # Intake runs separately; no producer SQLite transaction is held here.
        from .snapshot_guard import snapshot_guard
        with snapshot_guard():
            return self._respond(**kwargs)

    def _respond(self, *, track: str, process: ProcessInstance,
                jev_state: dict[str, Any] | None = None,
                recovery_plan: RecoveryPlan | None = None,
                recovery_plan_provider: Callable[[], RecoveryPlan] | None = None,
                recovery_required: bool = True,
                track_a_confirmed: bool = False,
                resume_jev_review: bool = False,
                resume_b_review: bool = False,
                explicit_authorization: bool = False,
                incident_id: str | None = None) -> ResponseResult:
        if explicit_authorization is not True:
            raise PermissionError("Live firewall, JEV and kernel actions require explicit authorization")
        if not isinstance(process, ProcessInstance):
            raise ValueError("A PID AND exact kernel creation FILETIME are required")
        if track not in ("A", "B"):
            raise ValueError("Track must be A or B")
        if track == "A" and track_a_confirmed is not True:
            raise PermissionError("Track A must be explicitly confirmed using corroborated evidence")
        if resume_jev_review and (track != 'A' or track_a_confirmed is not True):
            raise PermissionError('Only corroborated Track A can resume a JEV-only review')
        if resume_b_review:
            from .late_track_b import new_verified_facts
            if track!='B' or resume_jev_review or not new_verified_facts({'evidence':jev_state,'prior_changed_paths':(jev_state or {}).get('reassessment_prior_changed_paths',[])}):
                raise PermissionError('Track B reassessment requires new verified file effects')
        if track == "B" and (not isinstance(jev_state, dict) or not jev_state):
            raise ValueError("Track B requires bounded nonempty JEV evidence")
        if recovery_plan is not None and not isinstance(recovery_plan, RecoveryPlan):
            raise ValueError("Recovery must use an explicitly validated plan")
        if recovery_plan is not None and recovery_plan_provider is not None:
            raise ValueError("Use one fixed plan or one post-exit recovery-plan provider")
        if type(recovery_required) is not bool:
            raise ValueError("recovery_required must be boolean")
        if incident_id is None:
            incident_id = str(uuid.uuid4())
        item = ResponseResult(incident_id, track, process)
        if track == 'B':
            item.decision_thresholds = {'benign': self.thresholds.benign, 'malicious': self.thresholds.malicious}
        self._log(item, "detection_recorded", decision_thresholds_are_uncalibrated_demo_values=True)

        # Only this coordinator's automatic effects are exempted. Intake,
        # kernel self protection and child-create blocking never consult this.
        from pathlib import Path
        from .program_allowlist import match
        if getattr(self.outbox, 'path', None):
            try:
                rule = match(Path(self.outbox.path).parent, process)
            except Exception as error:
                rule = None
                self._log(item, 'program_exception_unverified', error_type=type(error).__name__)
            if rule:
                item.state = 'EXEMPTED'
                item.reason = 'program_path_sha256_automatic_response_exception'
                # Retain Track B analysis, but never acquire a hold or perform
                # termination/recovery, even when the score is malicious.
                if track == 'B' and self.jev is not None and self._decision_allowed():
                    try:
                        verdict = self.jev.evaluate(jev_state)
                        score = verdict.get('score')
                        if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
                            raise ValueError('Invalid JEV score')
                        if not isinstance(verdict.get('request_id'), str) or not verdict['request_id']:
                            raise ValueError('Invalid JEV request identity')
                        item.jev_score = float(score)
                        item.jev_request_id = verdict['request_id']
                        item.jev_request_state = verdict.get('request_state')
                        item.jev_classification = ('benign' if score <= self.thresholds.benign else
                                                   'malicious' if score >= self.thresholds.malicious else 'ambiguous')
                        self._log(item, 'program_exception_jev_observed', score=score,
                                  classification=item.jev_classification, request_id=item.jev_request_id,
                                  request_state=item.jev_request_state, automatic_response=False)
                    except Exception as error:
                        self._log(item, 'program_exception_jev_unavailable', error_type=type(error).__name__)
                self._log(item, 'automatic_response_exempted', program_exception=rule,
                          telemetry_preserved=True, kernel_self_protection_preserved=True)
                return item

        if not self._decision_allowed():
            return self._review(item, 'evidence_expired_or_collection_invalidated')

        item.state = "CONTAINMENT_REQUESTED"
        self._log(item, "host_outbound_block_requested", allowlist_scope="whole_host_jev_only")
        containment_started = time.monotonic()
        try:
            # Even on timeout, the firewall manager stores a durable hold; a
            # missing/false ACK cannot be treated as proven filtering.
            if resume_b_review:
                self.firewall.resume_track_b_review(item.incident_id)
                self._log(item,'track_b_review_hold_retained',isolation_released=False)
            elif resume_jev_review:
                self.firewall.resume_track_a_review(item.incident_id)
                self._log(item, 'late_track_a_hold_transferred', isolation_released=False)
            else:
                self.firewall.acquire(item.incident_id, track)
            item.firewall_hold_retained = True
            item.firewall_policy_acknowledged = True
            item.state = "POLICY_ACKNOWLEDGED"
            self._log(item, "host_outbound_policy_acknowledged", wfp_enforcement_verified=False)
        except Exception as error:
            item.firewall_hold_retained = True  # may be unknown; retain conservatively
            self._log(item, "host_outbound_policy_unconfirmed", hold_status="unknown_review_required",
                      error_type=type(error).__name__, winerror=getattr(error, 'winerror', None),
                      errno=getattr(error, 'errno', None),
                      sqlite_errorname=getattr(error, 'sqlite_errorname', None),
                      elapsed_ms=round((time.monotonic()-containment_started)*1000))
            if track == "A":
                # Clear malicious behavior still requires prompt termination,
                # even when network control is unavailable. Do not auto-release.
                self._stop_and_restore(item, recovery_plan=recovery_plan,
                                       recovery_required=recovery_required,
                                       recovery_plan_provider=recovery_plan_provider)
            return self._review(item, "host_outbound_containment_unconfirmed")

        if track == "A":
            return self._stop_and_restore(item, recovery_plan=recovery_plan,
                                          recovery_required=recovery_required,
                                          recovery_plan_provider=recovery_plan_provider)

        # An observed process-created event and its cached generation are not
        # sufficient kill authorization. Verify an actual live handle before
        # sending the candidate to the remote JEV service.
        try:
            with self.process_factory(process) as session:
                if session.is_exited():
                    return self._review(item, "process_exited_before_jev")
        except (OSError, RuntimeError, ValueError):
            return self._review(item, "live_process_identity_unverified_before_jev")

        item.state = "JEV_PENDING"
        self._log(item, "jev_requested", threshold_policy="uncalibrated_demo_only")
        if self.jev is None:
            return self._review(item, "jev_client_not_configured")
        try:
            verdict = self.jev.evaluate(jev_state)
        except Exception:
            return self._review(item, "jev_query_or_validation_failed")
        if isinstance(verdict, dict):
            item.jev_request_state = verdict.get("request_state")
        score = verdict.get("score") if isinstance(verdict, dict) else None
        if type(score) not in (int, float) or not math.isfinite(score) or not 0.0 <= score <= 1.0:
            return self._review(item, "jev_score_invalid")
        if not isinstance(verdict.get("request_id"), str) or not verdict["request_id"]:
            return self._review(item, "jev_request_identity_invalid")
        item.jev_score = float(score)
        item.jev_request_id = verdict["request_id"]
        item.jev_model = verdict.get('model') if isinstance(verdict.get('model'), str) else None
        self._log(item, "jev_responded", score=item.jev_score,
                  model=verdict.get("model"), request_id=item.jev_request_id,
                  request_state=item.jev_request_state, decision_thresholds=item.decision_thresholds)
        if not self._decision_allowed():
            return self._review(item, 'evidence_expired_or_collection_invalidated')
        if score <= self.thresholds.benign:
            item.jev_classification = "benign"
            return self._release(item, reason="jev_benign_demo_threshold")
        if score >= self.thresholds.malicious:
            item.jev_classification = "malicious"
            return self._stop_and_restore(item, recovery_plan=recovery_plan,
                                          recovery_required=recovery_required,
                                          recovery_plan_provider=recovery_plan_provider)
        item.jev_classification = "ambiguous"
        if self.review_followup is not None and not resume_b_review:
            return self.review_followup.run(self, item, jev_state,
                lambda: self._stop_and_restore(item, recovery_plan=recovery_plan,
                    recovery_required=recovery_required, recovery_plan_provider=recovery_plan_provider))
        return self._review(item, "jev_ambiguous_demo_threshold")
