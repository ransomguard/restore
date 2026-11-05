"""Portable, bounded intake of kernel evidence into Track B candidates.

Feed *every* decoded lifecycle/file event, after updating ProcessRegistry. A
high-entropy write is sufficient for a candidate, never a Track A verdict. This
module records evidence; it cannot isolate, call JEV, terminate, or restore.

File-event ABI v1 omits process creation time. Correlation is corroborated against
an observed process-create event, but is still NOT authorization for an action.
Missing/revoked identities produce deferred records, not a silent rejection.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass, field
import math
import time
from typing import Any, Callable
import uuid

from .protocol import Event, FILE_FLAG_HIGH_ENTROPY


@dataclass(frozen=True)
class TriageConfig:
    window_seconds: float = 10.0
    cooldown_seconds: float = 30.0
    max_processes: int = 1024
    max_events_per_process: int = 256
    max_paths_per_process: int = 8

    def __post_init__(self) -> None:
        for name in ("window_seconds", "cooldown_seconds"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number")
            if value < 0 or (name == "window_seconds" and value == 0):
                raise ValueError(f"Invalid {name}")
        for name in ("max_processes", "max_events_per_process", "max_paths_per_process"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive integer")


@dataclass(frozen=True)
class TriageRecord:
    kind: str
    payload: dict[str, Any]


@dataclass(frozen=True, slots=True)
class _Observation:
    at: float
    kind: int
    high_entropy: bool
    sequence: int


@dataclass
class _ProcessState:
    generation: int | None
    observations: deque[_Observation] = field(default_factory=deque)
    paths: OrderedDict[str, float] = field(default_factory=OrderedDict)
    last_emitted_at: float | None = None
    suppressed_since_last_emit: int = 0
    observation_evictions: int = 0
    truncated_until: float = -math.inf


class TriageIntake:
    """Single-consumer intake; timing uses the injected monotonic clock only.

    The state limit includes lifecycle identities, even when no file operations
    have been seen. Capacity eviction loses that identity/cooldown and is audited.
    A later file event requires a fresh lifecycle observation before its identity
    can be correlated again. No timers, background workers or OS APIs are used.
    """

    def __init__(self, config: TriageConfig | None = None, *,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config if config is not None else TriageConfig()
        if not isinstance(self.config, TriageConfig):
            raise TypeError("config must be TriageConfig")
        self._clock = clock
        self._last_time: float | None = None
        self._last_sequence: int | None = None
        self._states: OrderedDict[int, _ProcessState] = OrderedDict()
        self._epoch = 0
        self._counters = {"candidates_emitted": 0, "deferred_emitted": 0,
                          "high_entropy_observations": 0, "suppressed_candidates": 0,
                          "identity_resets": 0, "state_resets": 0, "capacity_evictions": 0}

    def _now(self) -> float:
        value = self._clock()
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ValueError("Triage clock must return a finite monotonic time")
        now = float(value)
        if self._last_time is not None and now < self._last_time:
            raise ValueError("Triage monotonic clock moved backwards")
        self._last_time = now
        return now

    @staticmethod
    def _generation(value: Any) -> int | None:
        return value if type(value) is int and value > 0 else None

    def _record(self, kind: str, **fields: Any) -> TriageRecord:
        return TriageRecord(kind, {"schema_version": 1, "execution_mode": "observation",
                                  "identity_authorization": False,
                                  "complete_event_coverage": False,
                                  "correlation_epoch": self._epoch, **fields})

    def _reset(self, reason: str) -> TriageRecord:
        count = len(self._states)
        observations = sum(len(state.observations) for state in self._states.values())
        self._states.clear()
        self._last_sequence = None
        self._epoch += 1
        self._counters["state_resets"] += 1
        return self._record("triage_reset", reason=reason, cleared_processes=count,
                            cleared_observations=observations, fresh_lifecycle_required=True)

    def reset(self, *, reason: str) -> TriageRecord:
        """Audit a decoder/driver-loss/reconnect boundary and invalidate identities.

        Persist the returned record. Stale identities in an external registry
        cannot revive cleared state without a subsequent process-create event.
        """
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 256:
            raise ValueError("A short, nonempty reset reason is required")
        self._now()
        return self._reset(reason)

    def _new_state(self, pid: int, generation: int | None,
                   records: list[TriageRecord]) -> _ProcessState:
        if len(self._states) >= self.config.max_processes:
            evicted_pid, evicted = self._states.popitem(last=False)
            self._counters["capacity_evictions"] += 1
            records.append(self._record("triage_state_evicted", reason="process_capacity",
                                        pid=evicted_pid, correlated_process_create_time=evicted.generation,
                                        retained_observations_lost=len(evicted.observations),
                                        fresh_lifecycle_required=True))
        state = _ProcessState(generation)
        self._states[pid] = state
        return state

    def _identity_reset(self, pid: int, previous: _ProcessState, reason: str,
                        records: list[TriageRecord]) -> None:
        self._states.pop(pid, None)
        self._counters["identity_resets"] += 1
        records.append(self._record("triage_identity_reset", pid=pid, reason=reason,
                                    previous_process_create_time=previous.generation,
                                    cleared_observations=len(previous.observations)))

    def _prune(self, state: _ProcessState, now: float) -> None:
        cutoff = now - self.config.window_seconds
        while state.observations and state.observations[0].at <= cutoff:
            state.observations.popleft()
        for path, observed_at in list(state.paths.items()):
            if observed_at <= cutoff:
                del state.paths[path]

    def ingest(self, event: Event, *, correlated_create_time: int | None) -> list[TriageRecord]:
        """Return auditable records for one event; never wait for external work.

        Call after ProcessRegistry.update(event), including for lifecycle events.
        Returned kinds: track_b_candidate, track_b_deferred, triage_reset,
        triage_identity_reset and triage_state_evicted. Repeated high-entropy
        signals inside the cooldown update evidence/counters without another
        candidate. Keep persisting the original kernel event as well.
        """
        if event.event_type not in (1, 2, 3, 4, 5):
            raise ValueError("Unsupported triage event type")
        now = self._now()
        records: list[TriageRecord] = []
        if self._last_sequence is not None and event.sequence != self._last_sequence + 1:
            expected = self._last_sequence + 1
            record = self._reset("sequence_gap_or_reorder")
            record.payload.update(expected_sequence=expected, observed_sequence=event.sequence)
            records.append(record)
        self._last_sequence = event.sequence
        state = self._states.get(event.pid)

        if event.event_type == 1:
            generation = self._generation(event.fields.get("process_create_time"))
            if state is not None:
                self._identity_reset(event.pid, state, "process_create_observed", records)
            self._new_state(event.pid, generation, records)
            return records
        if event.event_type in (2, 3):
            generation = self._generation(event.fields.get("process_create_time"))
            if state is not None and (generation is None or state.generation is None or
                                      state.generation == generation):
                reason = "process_exited" if event.event_type == 2 else "process_creation_blocked"
                self._identity_reset(event.pid, state, reason, records)
            return records

        supplied_generation = self._generation(correlated_create_time)
        if state is not None and state.generation is not None and state.generation != supplied_generation:
            reason = "correlation_missing" if supplied_generation is None else "correlation_generation_changed"
            self._identity_reset(event.pid, state, reason, records)
            state = None
        if state is None:
            state = self._new_state(event.pid, None, records)
        self._states.move_to_end(event.pid)
        self._prune(state, now)

        flags = event.fields.get("flags", 0)
        if type(flags) is not int or not 0 <= flags <= 0xFFFFFFFF:
            raise ValueError("File flags must be an unsigned 32-bit integer")
        high_entropy = event.event_type == 4 and bool(flags & FILE_FLAG_HIGH_ENTROPY)
        if len(state.observations) >= self.config.max_events_per_process:
            evicted = state.observations.popleft()
            state.observation_evictions += 1
            state.truncated_until = max(state.truncated_until, evicted.at + self.config.window_seconds)
        state.observations.append(_Observation(now, event.event_type, high_entropy, event.sequence))
        raw_path = event.fields.get("path", "")
        path = raw_path[:1024] if isinstance(raw_path, str) else ""
        if path:
            state.paths[path] = now
            state.paths.move_to_end(path)
            if len(state.paths) > self.config.max_paths_per_process:
                state.paths.popitem(last=False)

        if not high_entropy:
            return records
        self._counters["high_entropy_observations"] += 1
        if state.last_emitted_at is not None and now - state.last_emitted_at < self.config.cooldown_seconds:
            state.suppressed_since_last_emit += 1
            self._counters["suppressed_candidates"] += 1
            return records

        generation = state.generation
        identity_available = generation is not None and generation == supplied_generation
        kind = "track_b_candidate" if identity_available else "track_b_deferred"
        reasons = ["high_entropy_write_observed"]
        if not identity_available:
            reasons.append("missing_process_generation" if supplied_generation is None else
                           "fresh_process_lifecycle_required")
        counts = {"write_attempts": sum(item.kind == 4 for item in state.observations),
                  "rename_attempts": sum(item.kind == 5 for item in state.observations),
                  "high_entropy_writes": sum(item.high_entropy for item in state.observations),
                  "retained_observations": len(state.observations)}
        record = self._record(
            kind, candidate_id=str(uuid.uuid4()), track="B",
            status="candidate" if identity_available else "deferred_identity",
            reason_codes=reasons, pid=event.pid,
            correlated_process_create_time=generation if identity_available else None,
            registry_process_create_time=supplied_generation,
            correlation_is_authorization=False,
            identity_source="observed_lifecycle_correlation" if identity_available else "unresolved",
            source_sequence=event.sequence, source_filetime=event.filetime,
            window_seconds=self.config.window_seconds, cooldown_seconds=self.config.cooldown_seconds,
            counts=counts, counts_scope="retained_observations_in_window",
            window_truncated_by_capacity=now < state.truncated_until,
            observation_evictions_since_identity_reset=state.observation_evictions,
            suppressed_since_last_emit=state.suppressed_since_last_emit,
            evidence={"trigger_flags": flags, "trigger_path": path,
                      "trigger_path_clipped": isinstance(raw_path, str) and len(raw_path) > 1024,
                      "sample_source_paths": list(state.paths),
                      "sample_paths_are_complete": False,
                      "operation_result": "unknown_pre_operation"},
            containment_confirmed=False, jev_requested=False, termination_requested=False,
            restore_requested=False, automatic_response=False,
            next_step="live_identity_and_containment_required_before_jev")
        state.last_emitted_at = now
        state.suppressed_since_last_emit = 0
        self._counters["candidates_emitted" if identity_available else "deferred_emitted"] += 1
        records.append(record)
        return records

    def stats(self) -> dict[str, int]:
        """Bounded-state and suppression counters for observer status logging."""
        return {**self._counters, "tracked_processes": len(self._states),
                "retained_observations": sum(len(state.observations) for state in self._states.values()),
                "retained_paths": sum(len(state.paths) for state in self._states.values()),
                "correlation_epoch": self._epoch}
