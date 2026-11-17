"""Opt-in Windows VM entry points for the independently owned firewall daemon.

The read-only status command never enables/disables the policy. The response
command requires TWO explicit flags before changing network or process state.
The existing `observe` command remains non-enforcing by default.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .firewall_control import FirewallHoldManager, FirewallProfile
from .incidents import ProcessInstance
from .jev import JevClient, JevConfig
from .live_response import LiveResponseCoordinator, ResponseThresholds
from .outbox import Outbox
from .recovery import RecoveryPlan, build_plan, enumerate_snapshots, select_snapshot, volume_id_for_root
from .windows_reader import WindowsDriverReader


def _json_file(path: str) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("JSON input must contain an object")
    return data


def profile_from_config(config: dict[str, Any]) -> FirewallProfile:
    network = config.get("network")
    if not isinstance(network, dict) or network.get("scope") != "host_outbound":
        raise ValueError("network.scope must be host_outbound for BOTH response tracks")
    targets = network.get("extra_https_targets", [])
    if not isinstance(targets, list) or any(not isinstance(x, str) for x in targets):
        raise ValueError("extra_https_targets must contain explicit HTTPS URLs")
    url = network.get("jev_url")
    return FirewallProfile(jev_url=url, extra_https_targets=tuple(targets))


def thresholds_from_config(config: dict[str, Any]) -> ResponseThresholds:
    decision = config.get("decision", {})
    if not isinstance(decision, dict) or decision.get("thresholds_are_demo_only") is not True:
        raise ValueError("This RC requires explicit acknowledgement of uncalibrated demo thresholds")
    return ResponseThresholds(benign=decision.get("benign_threshold", 0.2),
                              malicious=decision.get("malicious_threshold", 0.8))


def recovery_plan_from_file(path: str) -> RecoveryPlan:
    """Select an existing VSS by EXACT GUID and a finite, operator-reviewed manifest.

    This intentionally does not infer a full restore manifest from sampled
    kernel pre-operation file paths. It never creates a new VSS snapshot.
    """
    data = _json_file(path)
    if data.get("schema_version") != 1:
        raise ValueError("Recovery plan input requires schema_version=1")
    volume_root = data.get("volume_root")
    protected_root = data.get("protected_root")
    at = data.get("incident_at")
    snapshot_id = data.get("snapshot_id")
    manifest = data.get("manifest")
    if not isinstance(manifest, list) or not manifest or len(manifest) > 5000:
        raise ValueError("Recovery requires an explicit nonempty manifest of up to 5000 files")
    if not isinstance(snapshot_id, str):
        raise ValueError("An exact pre-incident snapshot ID must be selected")
    volume_id = volume_id_for_root(volume_root)
    snapshots = enumerate_snapshots(volume_id)
    selected = select_snapshot(snapshots, volume_id=volume_id, incident_at=at, snapshot_id=snapshot_id)
    return build_plan(selected, volume_root=volume_root, protected_root=protected_root,
                      manifest=manifest, incident_at=at)


def recovery_plan_from_template(path: str, *, incident_at: str) -> RecoveryPlan:
    """Resolve a pre-approved LAB manifest after confirming the process exited.

    The fixed file list must be prepared by the operator; kernel pre-op samples
    are not a complete affected-file manifest. The newest VSS strictly before
    the original event timestamp is used. No snapshot is created here.
    """
    template = _json_file(path)
    if template.get("schema_version") != 1:
        raise ValueError("Manifest template requires schema_version=1")
    manifest = template.get("manifest")
    if not isinstance(manifest, list) or not 1 <= len(manifest) <= 5000:
        raise ValueError("Manifest template requires 1..5000 explicitly reviewed file entries")
    volume_root = template.get("volume_root")
    protected_root = template.get("protected_root")
    volume_id = volume_id_for_root(volume_root)
    snapshot = select_snapshot(enumerate_snapshots(volume_id), volume_id=volume_id,
                               incident_at=incident_at)
    return build_plan(snapshot, volume_root=volume_root, protected_root=protected_root,
                      manifest=manifest, incident_at=incident_at)


def firewall_status(*, config_path: str, state_db: str, query_daemon: bool = False) -> dict[str, Any]:
    config = _json_file(config_path)
    profile = profile_from_config(config)
    with FirewallHoldManager(state_db, profile) as owner:
        return owner.status(with_daemon=query_daemon)


def operator_review_release(*, config_path: str, state_db: str, outbox_db: str,
                            incident_id: str, reason: str, authorize_live: bool,
                            confirm_isolated_vm: bool, operator_verified_safe: bool) -> dict[str, Any]:
    if not (authorize_live is True and confirm_isolated_vm is True and operator_verified_safe is True):
        raise PermissionError("Operator release requires all three explicit authorization confirmations")
    if reason not in ("false_positive", "manual_recovery_verified", "lab_cleanup_confirmed"):
        raise ValueError("A specific operator reconciliation reason is required")
    profile = profile_from_config(_json_file(config_path))
    with Outbox(outbox_db) as outbox, FirewallHoldManager(state_db, profile) as owner:
        # Record intent BEFORE possibly disconnecting the VM network policy.
        outbox.append("operator_firewall_release_requested", {"execution_mode": "live_operator_action",
                    "incident_id": incident_id, "reason": reason, "network_scope": "host_outbound"},
                    incident_id=incident_id)
        result = owner.operator_review_release(incident_id, operator_verified_safe=True)
        outbox.append("operator_firewall_release_result", {"execution_mode": "live_operator_action",
                    "network_scope": "host_outbound", "reason": reason, **result}, incident_id=incident_id)
        return result


def respond_one(*, config_path: str, state_db: str, outbox_db: str, track: str,
                pid: int, create_time: int, jev_state_file: str | None,
                recovery_plan_file: str | None, no_recovery_required: bool,
                track_a_confirmed: bool, authorize_live: bool, confirm_isolated_vm: bool,
                ui: bool = False) -> dict[str, Any]:
    if authorize_live is not True or confirm_isolated_vm is not True:
        raise PermissionError("Both --authorize-live and --confirm-isolated-vm are required")
    config = _json_file(config_path)
    profile = profile_from_config(config)
    thresholds = thresholds_from_config(config)
    process = ProcessInstance(pid, create_time)
    if track == "A" and track_a_confirmed is not True:
        raise PermissionError("Track A requires --track-a-confirmed")
    if track == "B" and not jev_state_file:
        raise ValueError("Track B requires --jev-state-json for a real JEV query")
    if recovery_plan_file and no_recovery_required:
        raise ValueError("Do not combine a recovery plan with --no-recovery-required")
    state = _json_file(jev_state_file) if jev_state_file else None
    plan = recovery_plan_from_file(recovery_plan_file) if recovery_plan_file else None
    if not no_recovery_required and plan is None:
        raise ValueError("Specify an explicit --recovery-plan or --no-recovery-required for this lab case")
    # Do all local and VSS input validation BEFORE any daemon policy change.
    jev = JevClient(JevConfig(base_url=profile.jev_url)) if track == "B" else None
    with Outbox(outbox_db) as outbox, FirewallHoldManager(state_db, profile) as owner, WindowsDriverReader() as driver:
        coordinator = LiveResponseCoordinator(outbox=outbox, firewall=owner, driver=driver,
                                              jev=jev, thresholds=thresholds)
        result = coordinator.respond(track=track, process=process, jev_state=state,
                                     recovery_plan=plan, recovery_required=not no_recovery_required,
                                     track_a_confirmed=track_a_confirmed, explicit_authorization=True)
        if ui:
            from .ui_bridge import UiBestEffortPublisher
            from .ui_pipe import WindowsUiPipe
            try:
                with WindowsUiPipe() as sink:
                    outcomes = UiBestEffortPublisher(sink).publish_live_result(
                        result, protected_root=config.get("recovery", {}).get("protected_root", ""))
            except (OSError, TimeoutError):
                outcomes = ["send_failed"]
            outbox.append("local_ui_live_response_notice", {
                "execution_mode": "best_effort_ui", "incident_id": result.incident_id,
                "results": outcomes, "ui_acknowledged": False}, incident_id=result.incident_id)
        return result.to_dict()
