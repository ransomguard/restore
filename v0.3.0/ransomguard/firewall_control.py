"""Durable, reference-counted WHOLE-PC firewall holds for Track A and B.

All response paths use a single policy profile and the existing daemon IPC.
The first incident activates the global outbound policy. Each subsequent
incident owns a durable hold; no incident can disable the policy while other
holds remain. Failures and ambiguous results retain holds for operator review.

Important: IPC ACKs do not independently prove WFP filtering. Outbound-only
coverage, DNS port 53 and the process-global allowlist remain known gaps.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import sqlite3
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .firewall_ipc import FirewallIpcClient, FirewallIpcError


class FirewallHoldError(RuntimeError):
    pass


def _safe_https_url(value: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 500:
        raise ValueError("Only explicit bounded HTTPS API URLs may be allowlisted")
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme == "https" and bool(parsed.hostname)
                 and "*" not in parsed.hostname
                 and parsed.username is None and parsed.password is None
                 and not parsed.query and not parsed.fragment
                 and (parsed.port is None or 1 <= parsed.port <= 65535)
                 and not any(ch.isspace() or ord(ch) < 33 for ch in value))
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("Allowlist targets must be HTTPS URLs without credentials, query or fragment")
    return value.rstrip("/")


@dataclass(frozen=True)
class FirewallProfile:
    jev_url: str
    extra_https_targets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "jev_url", _safe_https_url(self.jev_url))
        if not isinstance(self.extra_https_targets, tuple) or len(self.extra_https_targets) > 16:
            raise ValueError("Additional allowlist must be a tuple of at most 16 explicitly approved URLs")
        normalized = tuple(_safe_https_url(value) for value in self.extra_https_targets)
        if len(set(normalized)) != len(normalized) or self.jev_url in normalized:
            raise ValueError("Duplicate firewall allowlist targets")
        object.__setattr__(self, "extra_https_targets", normalized)

    @property
    def allowlist(self) -> list[str]:
        return [self.jev_url, *self.extra_https_targets]


class FirewallHoldManager:
    """Local coordinated owner of the ONE host-wide daemon policy.

    Use the same SQLite path for every coordinator process on the same VM.
    Do not reuse the SQLite outbox DB: firewall ownership has separate life
    cycle and must survive crashes, reboots and stale JEV decisions.

    The daemon is a separate process. A crash exactly between remote success
    and SQLite commit can leave an unowned active firewall. We never disable
    that state automatically; it requires explicit operator reconciliation.
    """

    def __init__(self, state_db: str | Path, profile: FirewallProfile, *,
                 client: FirewallIpcClient | Any | None = None) -> None:
        if not isinstance(profile, FirewallProfile):
            raise TypeError("A validated FirewallProfile is required")
        self.profile = profile
        self.client = client or FirewallIpcClient()
        self.state_db = Path(state_db)
        self.state_db.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.state_db, timeout=15.0)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA busy_timeout=15000")
        self.db.execute("""CREATE TABLE IF NOT EXISTS firewall_holds (
          incident_id TEXT PRIMARY KEY, track TEXT NOT NULL,
          created_at TEXT NOT NULL, state TEXT NOT NULL)""")
        self.db.execute("""CREATE TABLE IF NOT EXISTS firewall_owner (
          singleton INTEGER PRIMARY KEY CHECK(singleton=1),
          allowlist_json TEXT NOT NULL, policy_acknowledged INTEGER NOT NULL DEFAULT 0)""")
        self.db.commit()

    def _begin(self) -> None:
        self.db.execute("BEGIN IMMEDIATE")

    def _profile_row(self) -> tuple[list[str], bool] | None:
        row = self.db.execute("SELECT allowlist_json,policy_acknowledged FROM firewall_owner WHERE singleton=1").fetchone()
        if row is None:
            return None
        return json.loads(row[0]), row[1] == 1

    def _response_matches(self, result: dict[str, Any]) -> bool:
        if result.get("active") is not True:
            return False
        values = [item.get("value") for item in result.get("whitelist", [])]
        return len(values) == len(self.profile.allowlist) and set(values) == set(self.profile.allowlist)

    def _log_error(self, incident_id: str, state: str) -> None:
        self.db.execute("UPDATE firewall_holds SET state=? WHERE incident_id=?", (state, incident_id))

    def acquire(self, incident_id: str, track: str) -> dict[str, Any]:
        """Record an incident hold, then request the global outbound block.

        An acknowledgement + GET are checked. No claim of proven packet-level
        isolation is made. On any failure the durable hold remains for review.
        """
        if not isinstance(incident_id, str) or not 1 <= len(incident_id) <= 128:
            raise ValueError("A stable incident ID is required")
        if track not in ("A", "B"):
            raise ValueError("Track must be A or B")
        try:
            self._begin()
            row = self._profile_row()
            if row is None:
                self.db.execute("INSERT INTO firewall_owner(singleton,allowlist_json) VALUES(1,?)",
                                (json.dumps(self.profile.allowlist, separators=(",", ":")),))
                row = (self.profile.allowlist, False)
            if row[0] != self.profile.allowlist:
                raise FirewallHoldError("Different firewall profile already owns the global policy")
            old = self.db.execute("SELECT track,state FROM firewall_holds WHERE incident_id=?", (incident_id,)).fetchone()
            if old is not None and old[0] != track:
                raise FirewallHoldError("Incident hold cannot change tracks silently")
            if old is not None and old[1] != "acknowledged":
                raise FirewallHoldError("Incident has an unresolved hold; operator review required")
            if old is None:
                self.db.execute("INSERT INTO firewall_holds VALUES(?,?,?,?)",
                                (incident_id, track, datetime.now(timezone.utc).isoformat(), "requesting"))
            # One host-wide transition is enough while an acknowledged policy
            # remains active. The daemon's "on" also replaces its WFP allowlist
            # filters, so reissuing it for every incident can disrupt JEV and
            # unrelated host connections. Always GET first to detect a daemon
            # restart (its dynamic WFP session may have disappeared).
            current = self.client.request("get")
            if current["active"] is True:
                if not row[1]:
                    raise FirewallHoldError("An existing active firewall policy is not owned by this coordinator")
                if not self._response_matches(current):
                    # Do not silently overwrite a changed host-global policy.
                    # Keep the new hold for explicit operator reconciliation.
                    raise FirewallHoldError("Acknowledged firewall policy drifted; operator review required")
                # Already owned and matching: another incident only takes a
                # durable hold, without another on/set/refresh request.
            else:
                # First incident, or an acknowledged session lost by a daemon
                # restart: reassert ON only when GET reports the policy inactive.
                applied = self.client.request("on", whitelist=self.profile.allowlist)
                observed = self.client.request("get")
                if not self._response_matches(applied) or not self._response_matches(observed):
                    raise FirewallHoldError("Daemon did not confirm expected global policy/allowlist")
            self.db.execute("UPDATE firewall_owner SET policy_acknowledged=1 WHERE singleton=1")
            self.db.execute("UPDATE firewall_holds SET state='acknowledged' WHERE incident_id=?", (incident_id,))
            count = self.db.execute("SELECT COUNT(*) FROM firewall_holds").fetchone()[0]
            self.db.commit()
            return {"incident_id": incident_id, "scope": "host_outbound", "active_reported": True,
                    "active_holds": count, "wfp_enforcement_verified": False,
                    "allowlist_reported": self.profile.allowlist, "state": "policy_acknowledged"}
        except BaseException:
            self.db.rollback()
            # Crash/restart safety: persist a hold even if remote state is
            # unknown. Leave it for manual review, not automatic "off".
            try:
                self._begin()
                row = self._profile_row()
                if row is None:
                    self.db.execute("INSERT INTO firewall_owner(singleton,allowlist_json) VALUES(1,?)",
                                    (json.dumps(self.profile.allowlist, separators=(",", ":")),))
                if row is None or row[0] == self.profile.allowlist:
                    current = self.db.execute("SELECT track FROM firewall_holds WHERE incident_id=?",
                                              (incident_id,)).fetchone()
                    if current is None:
                        self.db.execute("INSERT INTO firewall_holds VALUES(?,?,?,?)",
                                        (incident_id, track, datetime.now(timezone.utc).isoformat(), "review_required"))
                    elif current[0] == track:
                        self._log_error(incident_id, "review_required")
                self.db.commit()
            except BaseException:
                self.db.rollback()
            raise

    def retain_for_review(self, incident_id: str) -> None:
        """Mark a confirmed hold as requiring manual release, surviving restart.

        Re-running the same deterministic candidate cannot turn a previous JEV
        timeout or incomplete restore into a silent benign release.
        """
        self._begin()
        try:
            row = self.db.execute("SELECT state FROM firewall_holds WHERE incident_id=?",
                                  (incident_id,)).fetchone()
            if row is None:
                raise FirewallHoldError("Cannot retain a nonexistent incident hold")
            self.db.execute("UPDATE firewall_holds SET state='review_required' WHERE incident_id=?",
                            (incident_id,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def release(self, incident_id: str) -> dict[str, Any]:
        """Release only the caller's hold, never other incident owners' holds.

        Last holder triggers `off` only after GET verifies the policy still
        matches one this coordinator acknowledged. Any uncertainty retains
        the hold. There is intentionally no force/off override.
        """
        self._begin()
        try:
            current = self.db.execute("SELECT state FROM firewall_holds WHERE incident_id=?",
                                      (incident_id,)).fetchone()
            if current is None:
                raise FirewallHoldError("Incident has no firewall hold to release")
            if current[0] != "acknowledged":
                raise FirewallHoldError("Uncertain firewall hold requires operator review")
            count = self.db.execute("SELECT COUNT(*) FROM firewall_holds").fetchone()[0]
            if count > 1:
                self.db.execute("DELETE FROM firewall_holds WHERE incident_id=?", (incident_id,))
                self.db.commit()
                return {"incident_id": incident_id, "scope": "host_outbound", "remaining_holds": count - 1,
                        "firewall_off_requested": False}
            row = self._profile_row()
            if row is None or row[0] != self.profile.allowlist or not row[1]:
                raise FirewallHoldError("No proof this coordinator owns the active firewall profile")
            current_status = self.client.request("get")
            if not self._response_matches(current_status):
                raise FirewallHoldError("Firewall state changed outside the coordinator; manual review needed")
            self.client.request("off")
            after_off = self.client.request("get")
            if after_off["active"] is not False:
                raise FirewallHoldError("Firewall daemon did not report disabled after release")
            self.db.execute("DELETE FROM firewall_holds WHERE incident_id=?", (incident_id,))
            self.db.execute("UPDATE firewall_owner SET policy_acknowledged=0 WHERE singleton=1")
            self.db.commit()
            return {"incident_id": incident_id, "scope": "host_outbound", "remaining_holds": 0,
                    "firewall_off_requested": True, "firewall_off_reported": True}
        except BaseException:
            self.db.rollback()
            raise

    def operator_review_release(self, incident_id: str, *, operator_verified_safe: bool = False) -> dict[str, Any]:
        """Explicitly resolve a review hold after a HUMAN verifies the incident.

        Never silently acknowledge an uncertain startup or external policy.
        For an unowned, inactive policy the stale local hold can be cleared
        without sending `off`. If an unowned policy is active, stop and ask
        for external operator reconciliation; do not seize or disable it.
        """
        if operator_verified_safe is not True:
            raise PermissionError("Operator must explicitly confirm safety before releasing a review hold")
        self._begin()
        try:
            holder = self.db.execute("SELECT state FROM firewall_holds WHERE incident_id=?",
                                     (incident_id,)).fetchone()
            if holder is None:
                raise FirewallHoldError("No hold exists for that incident")
            row = self._profile_row()
            if row is None or row[0] != self.profile.allowlist:
                raise FirewallHoldError("Firewall owner profile has changed")
            status = self.client.request("get")
            if row[1] is False:
                if status["active"] is True:
                    raise FirewallHoldError("Unowned active policy cannot be disabled automatically")
                self.db.execute("DELETE FROM firewall_holds WHERE incident_id=?", (incident_id,))
                remaining = self.db.execute("SELECT COUNT(*) FROM firewall_holds").fetchone()[0]
                self.db.commit()
                return {"incident_id": incident_id, "scope": "host_outbound",
                        "remaining_holds": remaining, "firewall_off_requested": False,
                        "operator_reconciliation": "cleared_unowned_inactive_hold"}
            if not self._response_matches(status):
                raise FirewallHoldError("Previously acknowledged daemon policy drifted; operator reconciliation required")
            if holder[0] == "review_required":
                self.db.execute("UPDATE firewall_holds SET state='acknowledged' WHERE incident_id=?", (incident_id,))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise
        return self.release(incident_id)

    def status(self, *, with_daemon: bool = True) -> dict[str, Any]:
        rows = self.db.execute("SELECT incident_id,track,state FROM firewall_holds ORDER BY created_at").fetchall()
        status = {"scope": "host_outbound", "holds": [
            {"incident_id": row[0], "track": row[1], "state": row[2]} for row in rows],
            "active_holds": len(rows), "wfp_enforcement_verified": False}
        if with_daemon:
            daemon = self.client.request("get")
            status["daemon_active_reported"] = daemon["active"]
            status["daemon_allowlist_matches_profile"] = (
                self._response_matches(daemon) if daemon["active"] else False)
        return status

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "FirewallHoldManager":
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()
