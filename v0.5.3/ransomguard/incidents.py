"""Deterministic incident controller used by the offline response simulator.

This module intentionally accepts only SimulationEffects in this milestone.
Live enforcement is not enabled until a tested file-containment backend and
network backend exist. No emitted 'applied' event can be mistaken for a real
Windows action: every event includes execution_mode='simulation'.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Any
import uuid

from .outbox import Outbox


@dataclass(frozen=True)
class ProcessInstance:
    pid: int
    create_time: int

    def __post_init__(self) -> None:
        if (type(self.pid) is not int or not 4 < self.pid <= 0xFFFFFFFF
                or type(self.create_time) is not int or not 0 < self.create_time <= 0x7FFFFFFFFFFFFFFF):
            raise ValueError("A non-system 32-bit PID and exact positive 64-bit process generation are required")

    @property
    def effect_key(self) -> str:
        """JSON-safe identity for fake effects; a PID alone is insufficient."""
        return f"{self.pid}:{self.create_time}"


@dataclass(frozen=True)
class DecisionTicket:
    incident_id: str
    request_id: str
    state_version: int


@dataclass
class Incident:
    incident_id: str
    process: ProcessInstance
    track: str
    state: str = "DETECTED"
    state_version: int = 0
    request_id: str | None = None
    recovery_required: bool = True
    reason: str | None = None


class SimulationEffects:
    """Recorded fake effects for replay and tests. Never calls OS/network APIs."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str | int]] = []
        self.fail: set[str] = set()
        self.recovery_status = "verified"

    def action(self, name: str, subject: str | int) -> None:
        self.calls.append((name, subject))
        if name in self.fail:
            raise RuntimeError(f"Simulated failure: {name}")

    def recover(self, incident_id: str) -> dict[str, Any]:
        self.action("restore", incident_id)
        return {"status": self.recovery_status, "verification_complete": self.recovery_status == "verified"}


class IncidentController:
    def __init__(self, outbox: Outbox, effects: SimulationEffects, *, benign_threshold: float = 0.2,
                 malicious_threshold: float = 0.8):
        if type(effects) is not SimulationEffects:
            raise TypeError("This milestone permits simulation effects only")
        if not (0 <= benign_threshold < malicious_threshold <= 1):
            raise ValueError("Invalid thresholds")
        # These defaults are DEMO values, not calibrated ransomware thresholds.
        self.outbox = outbox
        self.effects = effects
        self.benign_threshold = benign_threshold
        self.malicious_threshold = malicious_threshold
        self.incidents: dict[str, Incident] = {}
        self.network_holders: set[str] = set()
        self.file_holders: dict[ProcessInstance, set[str]] = {}

    def _log(self, item: Incident, kind: str, **fields: Any) -> None:
        self.outbox.append(kind, {"execution_mode": "simulation", "track": item.track,
                                 "state": item.state, "state_version": item.state_version,
                                 "pid": item.process.pid, "process_create_time": item.process.create_time,
                                 **fields}, incident_id=item.incident_id)

    def _state(self, item: Incident, state: str) -> None:
        item.state = state
        item.state_version += 1

    def _review(self, item: Incident, reason: str) -> None:
        item.reason = reason
        self._state(item, "REVIEW_REQUIRED")
        self._log(item, "review_required", reason=reason)

    def begin(self, process: ProcessInstance, track: str, *, recovery_required: bool = True) -> Incident:
        if track not in ("A", "B"):
            raise ValueError("track must be A or B")
        item = Incident(str(uuid.uuid4()), process, track, recovery_required=recovery_required)
        self.incidents[item.incident_id] = item
        self._log(item, "detection_recorded")
        self._state(item, "CONTAINMENT_REQUESTED")
        self._log(item, "quarantine_requested", scope="host_outbound")
        try:
            if not self.file_holders.get(process):
                self.effects.action("file_hold", process.effect_key)
            self.file_holders.setdefault(process, set()).add(item.incident_id)
            if not self.network_holders:
                self.effects.action("host_outbound_on", "whole_host")
            self.network_holders.add(item.incident_id)
        except RuntimeError as exc:
            self._log(item, "quarantine_failed", error=str(exc))
            # Track A must still initiate termination despite containment failure.
            if track == "A":
                try:
                    self._log(item, "termination_requested")
                    self.effects.action("terminate_and_confirm", process.effect_key)
                    self._log(item, "process_exit_confirmed")
                except RuntimeError as termination_error:
                    self._log(item, "termination_failed", error=str(termination_error))
            self._review(item, "containment_not_confirmed")
            return item
        self._state(item, "CONTAINED")
        self._log(item, "quarantine_applied", scope="host_outbound")
        if track == "A":
            self._malicious(item)
        else:
            item.request_id = str(uuid.uuid4())
            self._state(item, "JEV_PENDING")
            self._log(item, "jev_requested", request_id=item.request_id)
        return item

    def ticket(self, incident_id: str) -> DecisionTicket:
        item = self.incidents[incident_id]
        if item.state != "JEV_PENDING" or item.request_id is None:
            raise ValueError("Incident has no pending JEV request")
        return DecisionTicket(item.incident_id, item.request_id, item.state_version)

    def decision(self, ticket: DecisionTicket, score: Any = None, *, error: str | None = None) -> str:
        item = self.incidents[ticket.incident_id]
        if (item.state != "JEV_PENDING" or item.state_version != ticket.state_version
                or item.request_id != ticket.request_id):
            self._log(item, "stale_decision_ignored", request_id=ticket.request_id)
            return item.state
        if error is not None:
            self._log(item, "jev_failed", error=error)
            self._review(item, "decision_unavailable")
            return item.state
        if isinstance(score, bool) or not isinstance(score, (float, int)) or not math.isfinite(score) or not 0 <= score <= 1:
            self._review(item, "invalid_decision_score")
            return item.state
        self._log(item, "jev_responded", score=float(score), request_id=ticket.request_id,
                  threshold_policy="unvalidated_demo_only")
        if score <= self.benign_threshold:
            self._release(item, "benign")
        elif score >= self.malicious_threshold:
            self._malicious(item)
        else:
            self._review(item, "ambiguous_decision")
        return item.state

    def escalate_to_a(self, incident_id: str) -> None:
        item = self.incidents[incident_id]
        if item.state in ("RELEASED", "CLOSED"):
            raise ValueError("Closed incidents require a new incident for new evidence")
        item.track = "A"
        self._state(item, "ESCALATED")
        self._log(item, "track_a_escalation")
        if (item.incident_id not in self.network_holders
                or item.incident_id not in self.file_holders.get(item.process, set())):
            # Escalation must not defer the Track A termination request merely
            # because an earlier Track B containment action failed.
            try:
                self._log(item, "termination_requested")
                self.effects.action("terminate_and_confirm", item.process.effect_key)
                self._log(item, "process_exit_confirmed")
            except RuntimeError as exc:
                self._log(item, "termination_failed", error=str(exc))
            self._review(item, "containment_not_confirmed")
            return
        self._malicious(item)

    def _malicious(self, item: Incident) -> None:
        self._state(item, "TERMINATION_REQUESTED")
        self._log(item, "termination_requested")
        try:
            self.effects.action("terminate_and_confirm", item.process.effect_key)
        except RuntimeError as exc:
            self._log(item, "termination_failed", error=str(exc))
            self._review(item, "exit_not_confirmed")
            return
        self._state(item, "EXIT_CONFIRMED")
        self._log(item, "process_exit_confirmed")
        if item.recovery_required:
            self._state(item, "RESTORING")
            self._log(item, "restore_started")
            try:
                result = self.effects.recover(item.incident_id)
            except RuntimeError as exc:
                self._log(item, "restore_failed", error=str(exc))
                self._review(item, "recovery_failed")
                return
            if result.get("status") != "verified" or result.get("verification_complete") is not True:
                self._log(item, "restore_incomplete", result=result)
                self._review(item, "recovery_not_verified")
                return
            self._log(item, "restore_verified", result=result)
        self._release(item, "malicious_process_stopped_and_recovery_verified")

    def _release(self, item: Incident, reason: str) -> None:
        self._state(item, "RELEASE_REQUESTED")
        self._log(item, "release_requested", reason=reason)
        try:
            owners = self.file_holders.get(item.process, set())
            if item.incident_id in owners:
                if len(owners) == 1:
                    self.effects.action("file_release", item.process.effect_key)
                owners.remove(item.incident_id)
                if not owners:
                    self.file_holders.pop(item.process, None)
            if item.incident_id in self.network_holders:
                if len(self.network_holders) == 1:
                    self.effects.action("host_outbound_off", "whole_host")
                self.network_holders.remove(item.incident_id)
        except RuntimeError as exc:
            self._log(item, "release_failed", error=str(exc))
            self._review(item, "release_not_confirmed")
            return
        self._state(item, "RELEASED")
        self._log(item, "incident_quarantine_released", scope="host_outbound",
                  host_outbound_still_blocked=bool(self.network_holders), reason=reason)

    def summary(self) -> dict[str, Any]:
        return {"execution_mode": "simulation", "network_scope": "host_outbound",
                "network_hold_count": len(self.network_holders),
                "host_outbound_blocked": bool(self.network_holders),
                "host_firewall_holder_incident_ids": sorted(self.network_holders),
                "incidents": [{"incident_id": x.incident_id, "pid": x.process.pid,
                               "process_create_time": x.process.create_time,
                               "track": x.track, "state": x.state, "reason": x.reason}
                              for x in self.incidents.values()]}
