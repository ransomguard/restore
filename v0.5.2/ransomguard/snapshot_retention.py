"""Owned-only VSS retention with durable deletion intent and conservative pins.

The budget observes the whole volume's shared diff area; it is NOT an invented
per-snapshot size or an OS quota. Never resize shadowstorage: that can evict
foreign or protected copies. Pressure which cannot safely be relieved stops
new creation. External writers/Windows can still consume space or evict VSS.
"""
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import subprocess
import uuid

from .recovery import Snapshot, _aware_utc, _snapshot_id, _volume_id, _powershell_executable, enumerate_snapshots
from .snapshot_guard import snapshot_guard

GiB = 1024 ** 3


@dataclass(frozen=True)
class RetentionPolicy:
    max_count: int = 12
    max_age_seconds: int = 86400
    min_keep: int = 2
    max_used_bytes: int = 4 * GiB
    creation_reserve_bytes: int = 512 * 1024 ** 2
    min_free_bytes: int = 2 * GiB

    def __post_init__(self):
        bounds = {'max_count': (2, 64), 'max_age_seconds': (7200, 2592000),
                  'min_keep': (2, 64), 'max_used_bytes': (512 * 1024**2, 1024 * GiB),
                  'creation_reserve_bytes': (64 * 1024**2, 16 * GiB),
                  'min_free_bytes': (256 * 1024**2, 1024 * GiB)}
        for key, (lo, hi) in bounds.items():
            value = getattr(self, key)
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError('Invalid retention limit: ' + key)
        if self.min_keep > self.max_count or self.creation_reserve_bytes >= self.max_used_bytes:
            raise ValueError('Inconsistent retention limits')


def policy_path(state_db):
    return Path(state_db).with_suffix('.retention.json')


def load_config(state_db):
    value = json.loads(policy_path(state_db).read_text(encoding='utf-8-sig'))
    if value.get('schema_version') != 1 or value.get('enabled') is not True:
        raise ValueError('Retention policy must be explicitly enabled')
    RetentionPolicy(**value['policy'])
    for field in ('outbox_db', 'holds_db'):
        if not isinstance(value.get(field), str) or not Path(value[field]).is_absolute():
            raise ValueError('Retention requires absolute protection database paths')
    manifests = value.get('manifest_paths')
    if not isinstance(manifests, list) or not manifests or len(manifests) > 64:
        raise ValueError('Retention requires explicit approved manifest paths')
    if any(not isinstance(p, str) or not Path(p).is_absolute() for p in manifests):
        raise ValueError('Manifest paths must be absolute')
    return value


def policy_required(state_db):
    if not Path(state_db).exists():
        return False
    with closing(_readonly(state_db)) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='snapshot_retention_required'").fetchone():
            return False
        return db.execute('SELECT required FROM snapshot_retention_required WHERE singleton=1').fetchone() == (1,)


def _readonly(path):
    return sqlite3.connect(Path(path).absolute().as_uri()+'?mode=ro', uri=True, timeout=3)


def protection_state(config, snapshots):
    """Fail closed on missing state; unresolved incidents protect ALL pre-claim copies.

    This also covers old holds whose detailed event was already pruned. Claimed
    time is an upper bound on incident time. Explicit selected IDs in manifests
    and retained restore records are always pinned. No pins expire by timeout.
    """
    protected = set()
    reasons = []
    with closing(_readonly(config['holds_db'])) as db:
        holds = db.execute('SELECT incident_id,created_at FROM firewall_holds').fetchall()
    with closing(_readonly(config['outbox_db'])) as db:
        attempts = db.execute("SELECT incident_id,claimed_at_utc FROM live_response_attempts WHERE state != 'RELEASED'").fetchall()
        jobs = db.execute("SELECT id,created FROM response_jobs WHERE state != 'RELEASED' AND state != 'DONE'").fetchall()
        # The pre-claim superset includes every valid selected pre-incident
        # snapshot. Do not scan the large raw event table to rediscover those
        # same IDs; manual engine jobs are covered by durable recovery pins.
        for ident, when in holds + attempts:
            cutoff = _aware_utc(when, 'incident claim')
            protected.update(s.snapshot_id for s in snapshots if s.created_at <= cutoff)
            reasons.append({'source': 'unresolved_incident', 'id': ident})
        for ident, when in jobs:
            if type(when) not in (int, float):
                raise ValueError('Invalid pending job time')
            cutoff = datetime.fromtimestamp(when, timezone.utc)
            protected.update(s.snapshot_id for s in snapshots if s.created_at <= cutoff)
            reasons.append({'source': 'pending_response', 'id': ident})
    for name in config['manifest_paths']:
        manifest = json.loads(Path(name).read_text(encoding='utf-8-sig'))
        if manifest.get('schema_version') != 1 or not isinstance(manifest.get('manifest'), list):
            raise ValueError('Invalid approved manifest')
        if manifest.get('snapshot_id'):
            protected.add(_snapshot_id(manifest['snapshot_id']))
    return protected, reasons


_STORAGE_SCRIPT = r'''
$ErrorActionPreference='Stop'
$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$v=@(Get-CimInstance Win32_Volume|Where-Object DeviceID -eq $i.volume_id)
if($v.Count -ne 1){throw 'Volume unavailable'}
$s=@(Get-CimInstance Win32_ShadowStorage|Where-Object {$_.Volume.DeviceID -eq $i.volume_id})
if($s.Count -gt 1){throw 'Ambiguous shadow storage'}
$used=0L;$allocated=0L;$max=0L;$free=[uint64]$v[0].FreeSpace
if($s.Count -eq 1){
 $used=[uint64]$s[0].UsedSpace;$allocated=[uint64]$s[0].AllocatedSpace;$max=[uint64]$s[0].MaxSpace
 $d=@(Get-CimInstance Win32_Volume|Where-Object DeviceID -eq $s[0].DiffVolume.DeviceID)
 if($d.Count -ne 1){throw 'Diff volume unavailable'}
 $free=[uint64]$d[0].FreeSpace
}
@{used_bytes=$used;allocated_bytes=$allocated;os_max_bytes=$max;free_bytes=$free}|ConvertTo-Json -Compress
'''

_DELETE_SCRIPT = r'''
$ErrorActionPreference='Stop'
$i=[Console]::In.ReadToEnd()|ConvertFrom-Json
$s=@(Get-CimInstance Win32_ShadowCopy|Where-Object ID -eq $i.snapshot_id)
if($s.Count -ne 1){throw 'Exact snapshot unavailable'}
$s=$s[0]
if($s.VolumeName -ne $i.volume_id -or $s.DeviceObject.TrimEnd('\') -ne $i.device_path -or
 ([datetime]$s.InstallDate).ToUniversalTime().Ticks -ne ([datetime]$i.created_at).ToUniversalTime().Ticks){throw 'Snapshot metadata changed'}
$s|Remove-CimInstance -ErrorAction Stop
$remaining=@(Get-CimInstance Win32_ShadowCopy|Where-Object ID -eq $i.snapshot_id)
@{absent=($remaining.Count -eq 0);snapshot_id=$i.snapshot_id}|ConvertTo-Json -Compress
'''


def _powershell(script, payload):
    result = subprocess.run([_powershell_executable(), '-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
        input=json.dumps(payload), capture_output=True, text=True, encoding='utf-8',
        timeout=30, check=False, shell=False)
    if result.returncode != 0:
        raise RuntimeError('VSS provider operation failed; inspect retention journal')
    return json.loads(result.stdout.lstrip('\ufeff'))


def read_storage(volume):
    return _powershell(_STORAGE_SCRIPT, {'volume_id': _volume_id(volume)})


def delete_exact(snapshot):
    # No /all, oldest, snapshot-set, resize or volume-wide deletion API.
    result = _powershell(_DELETE_SCRIPT, snapshot.to_dict())
    if result.get('absent') is not True or _snapshot_id(result.get('snapshot_id')) != snapshot.snapshot_id:
        raise RuntimeError('Exact deletion was not verified')


class SnapshotRetention:
    def __init__(self, state_db, config, *, inventory=enumerate_snapshots, storage=read_storage,
                 delete=delete_exact, protections=protection_state, clock=lambda: datetime.now(timezone.utc)):
        self.state_db = Path(state_db)
        self.config = config
        self.policy = RetentionPolicy(**config['policy'])
        self.inventory, self.storage, self.delete = inventory, storage, delete
        self.protections, self.clock = protections, clock

    def _owned(self, volume):
        with closing(_readonly(self.state_db)) as db:
            rows = db.execute('SELECT status,result_json FROM snapshot_attempts WHERE volume_id=?', (volume,)).fetchall()
        owned = {}
        for status, raw in rows:
            if status in ('unknown', 'in_progress'):
                raise ValueError('Unresolved creation attempt; no cleanup or creation')
            # Reconciliation alone cannot prove who originally created a copy.
            if status != 'created':
                continue
            data = json.loads(raw)
            if data.get('created') is not True or data.get('reason') != 'vss_create_verified':
                raise ValueError('Ownership receipt invalid')
            item = Snapshot(**data['snapshot'])
            if item.volume_id != volume or item.snapshot_id in owned:
                raise ValueError('Ownership receipt inconsistent')
            owned[item.snapshot_id] = item
        return owned

    def _journal(self, volume, snapshot, state, *, token=None, detail=None):
        with closing(sqlite3.connect(self.state_db, timeout=3)) as db:
            db.execute('PRAGMA synchronous=FULL')
            db.execute('''CREATE TABLE IF NOT EXISTS snapshot_deletions (
                id TEXT PRIMARY KEY,volume_id TEXT NOT NULL,snapshot_id TEXT NOT NULL,
                requested_at TEXT NOT NULL,state TEXT NOT NULL,detail TEXT)''')
            if token is None:
                token = str(uuid.uuid4())
                db.execute('INSERT INTO snapshot_deletions VALUES(?,?,?,?,?,?)',
                    (token, volume, snapshot.snapshot_id, self.clock().isoformat(), state, detail))
            else:
                db.execute('UPDATE snapshot_deletions SET state=?,detail=? WHERE id=?', (state, detail, token))
            db.commit()
        return token

    def _unresolved_delete(self, existing):
        with closing(_readonly(self.state_db)) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='snapshot_deletions'").fetchone():
                return False
            rows = db.execute("SELECT snapshot_id FROM snapshot_deletions WHERE state IN ('requested','unknown')").fetchall()
            # A present copy after an uncertain delete must never be retried blindly.
            return any(ident in existing for (ident,) in rows)

    def _space(self, volume):
        result = self.storage(volume)
        for key in ('used_bytes', 'allocated_bytes', 'os_max_bytes', 'free_bytes'):
            if type(result.get(key)) is not int or result[key] < 0:
                raise ValueError('Storage measurement unavailable')
        return result

    def run(self, volume, *, apply=False, reserve_for_creation=False):
        with snapshot_guard():
            report = self._run(_volume_id(volume), apply=apply, reserve_for_creation=reserve_for_creation)
            if apply:
                # Durable result for scheduled runs, including capacity-blocked runs.
                # A missing/broken state DB must not be silently recreated here.
                try:
                    with closing(sqlite3.connect(self.state_db.absolute().as_uri()+'?mode=rw', uri=True, timeout=3)) as db:
                        db.execute('PRAGMA synchronous=FULL')
                        db.execute('CREATE TABLE IF NOT EXISTS snapshot_retention_runs(id INTEGER PRIMARY KEY,at TEXT,result_json TEXT)')
                        db.execute('INSERT INTO snapshot_retention_runs(at,result_json) VALUES(?,?)',
                                   (self.clock().isoformat(), json.dumps(report)))
                        db.commit()
                except (sqlite3.Error, OSError):
                    report.update(status='blocked', creation_allowed=False, reason='retention_result_not_persisted')
            return report

    def _run(self, volume, *, apply, reserve_for_creation):
        report = {'status': 'blocked', 'policy': asdict(self.policy), 'deleted': [], 'candidates': [],
                  'creation_allowed': False, 'storage_scope': 'shared_volume_diff_area', 'quota_resized': False}
        try:
            owned = self._owned(volume)
            initial = {s.snapshot_id: s for s in self.inventory(volume)}
            if self._unresolved_delete(initial):
                raise ValueError('Previous deletion outcome requires review')
            now = _aware_utc(self.clock(), 'retention clock')
            for _ in range(65):
                live = {s.snapshot_id: s for s in self.inventory(volume)}
                if any(s.volume_id != volume for s in live.values()):
                    raise ValueError('Inventory volume mismatch')
                own = sorted((s for ident, s in live.items() if ident in owned), key=lambda s: s.created_at)
                # Windows may renumber HarddiskVolumeShadowCopyN across sessions.
                # Ownership uses persistent ID + volume + exact creation time;
                # delete_exact rechecks the CURRENT device path immediately.
                if any((owned[s.snapshot_id].volume_id, owned[s.snapshot_id].created_at) !=
                       (s.volume_id, s.created_at) for s in own):
                    raise ValueError('Owned snapshot metadata mismatch')
                if any(s.created_at > now for s in own):
                    raise ValueError('Clock precedes a known creation; no cleanup')
                protected, reasons = self.protections(self.config, list(live.values()))
                protected = {_snapshot_id(x) for x in protected}
                with closing(_readonly(self.state_db)) as db:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE name='snapshot_recovery_pins'").fetchone():
                        protected.update(_snapshot_id(r[0]) for r in db.execute(
                            "SELECT snapshot_id FROM snapshot_recovery_pins WHERE state!='released'"))
                protected.update(s.snapshot_id for s in own[-self.policy.min_keep:])
                space = self._space(volume)
                reserve = self.policy.creation_reserve_bytes if reserve_for_creation else 0
                max_used = self.policy.max_used_bytes
                # Stay below the existing Windows limit too, without changing it.
                if space['os_max_bytes']:
                    max_used = min(max_used, space['os_max_bytes'])
                pressure = (max(space['used_bytes'], space['allocated_bytes']) + reserve > max_used or
                            space['free_bytes'] < self.policy.min_free_bytes + reserve)
                excess = len(own) + int(reserve_for_creation) > self.policy.max_count
                available = [s for s in own if s.snapshot_id not in protected]
                candidates = [s for s in available if pressure or excess or
                              (now - s.created_at).total_seconds() > self.policy.max_age_seconds]
                report.update(owned_count=len(own), foreign_count=len(live)-len(own),
                    protected_ids=sorted(protected), protection_reasons=reasons, storage=space,
                    pressure=pressure, count_exceeded=excess,
                    candidates=[s.snapshot_id for s in candidates],
                    missing_owned_ids=sorted(set(owned)-set(live)))
                if not candidates or not apply:
                    report['status'] = 'blocked' if pressure or excess else 'ready'
                    # Preview is never a mutation authorization.
                    report['creation_allowed'] = not pressure and not excess
                    report['reason'] = ('protected_or_unowned_capacity' if pressure or excess else 'within_budget')
                    return report
                target = candidates[0]
                token = self._journal(volume, target, 'requested')
                try:
                    self.delete(target)
                    after = {s.snapshot_id for s in self.inventory(volume)}
                    if target.snapshot_id in after:
                        raise RuntimeError('Deleted snapshot still present')
                    self._journal(volume, target, 'deleted', token=token)
                    report['deleted'].append(target.snapshot_id)
                    if set(live) - after != {target.snapshot_id}:
                        raise RuntimeError('Unexpected snapshot disappearance; stop for review')
                except Exception as error:
                    self._journal(volume, target, 'unknown', token=token, detail=type(error).__name__)
                    raise
            raise RuntimeError('Maintenance action limit reached')
        except Exception as error:
            report.update(status='blocked', creation_allowed=False, reason=str(error), error_type=type(error).__name__)
            return report


def managed_creation(coordinator, root, volume, create):
    """Called under the shared gate BEFORE the hourly attempt is claimed."""
    try:
        config = load_config(coordinator.state_db)
    except (OSError, ValueError, KeyError, TypeError):
        return {'status': 'skipped', 'created': False, 'attempted': False,
                'reason': 'retention_policy_unavailable', 'snapshot': None,
                'requires_reconciliation': False}
    manager = SnapshotRetention(coordinator.state_db, config)
    before = manager.run(volume, apply=True, reserve_for_creation=True)
    if not before['creation_allowed']:
        return {'status': 'skipped', 'created': False, 'attempted': False,
                'reason': 'retention_capacity_or_protection', 'retention': before,
                'snapshot': None, 'requires_reconciliation': False}
    result = create(root)
    result['retention'] = before
    if result.get('created') is True:
        result['retention_after_creation'] = manager.run(volume, apply=True)
    return result


def pin_recovery(plan):
    """Pin live engine jobs durably, including manual/legacy callers and crashes."""
    from .snapshots import default_state_db
    state = default_state_db()
    if not policy_path(state).exists() and not policy_required(state):
        return None
    # Missing/broken required policy is a reason to stop, never to write unpinned.
    load_config(state)
    with closing(sqlite3.connect(state.absolute().as_uri()+'?mode=rw',uri=True,timeout=3)) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('''CREATE TABLE IF NOT EXISTS snapshot_recovery_pins (
            job_id TEXT PRIMARY KEY,snapshot_id TEXT NOT NULL,volume_id TEXT NOT NULL,
            state TEXT NOT NULL,created_at TEXT NOT NULL)''')
        db.execute('INSERT INTO snapshot_recovery_pins VALUES(?,?,?,?,?)',
                   (plan.job_id,plan.snapshot.snapshot_id,plan.snapshot.volume_id,'active',datetime.now(timezone.utc).isoformat()))
        db.commit()
    return state


def finish_recovery_pin(state, job_id, *, verified):
    if state is None:
        return
    with closing(sqlite3.connect(state,timeout=3)) as db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('UPDATE snapshot_recovery_pins SET state=? WHERE job_id=?',
                   ('released' if verified else 'review',job_id))
        db.commit()
