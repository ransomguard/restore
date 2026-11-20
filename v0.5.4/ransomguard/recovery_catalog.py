"""Bounded manifests of an explicitly selected VSS directory, never live bytes.

Enumerating a protected directory authorizes no restoration. Returned hashes
describe the selected snapshot's regular default data streams, not a complete
affected-file list or ACL/ADS/EFS backup. Any unsafe entry or limit fails the
whole scan rather than quietly publishing a partial manifest.
"""
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import time

from .recovery import (LocalSnapshotBackend, ManifestEntry, RecoveryValidationError, SnapshotFreshnessError,
                       _assert_node, _check_chain, _aware_utc, build_plan,
                       enumerate_snapshots, select_snapshot, volume_id_for_root)

DEFAULT_MAX_SNAPSHOT_AGE_SECONDS = 7200


def require_fresh_snapshot(snapshot, incident_at, max_age_seconds=DEFAULT_MAX_SNAPSHOT_AGE_SECONDS):
    if type(max_age_seconds) is not int or not 60 <= max_age_seconds <= 86400:
        raise RecoveryValidationError('Snapshot age limit must be an integer between 60 and 86400 seconds')
    age = (_aware_utc(incident_at, 'incident_at') - snapshot.created_at).total_seconds()
    if age <= 0 or age > max_age_seconds:
        raise SnapshotFreshnessError('No sufficiently recent pre-incident snapshot; recovery requires review')
    return age


def catalog_snapshot(snapshot, *, volume_root, protected_root, reference_at,
                     max_age_seconds=DEFAULT_MAX_SNAPSHOT_AGE_SECONDS,
                     max_files=5000, max_file_bytes=512*1024*1024,
                     max_total_bytes=2*1024*1024*1024, max_seconds=30,
                     backend=None, manual_selection=False):
    for name, value, low, high in (
            ('files', max_files, 1, 5000), ('file bytes', max_file_bytes, 1, 512*1024*1024),
            ('total bytes', max_total_bytes, 1, 2*1024*1024*1024), ('seconds', max_seconds, 1, 300)):
        if type(value) is not int or not low <= value <= high:
            raise RecoveryValidationError('Invalid catalog bound: '+name)
    if manual_selection is not True:
        require_fresh_snapshot(snapshot, reference_at, max_age_seconds)
    elif snapshot.created_at >= _aware_utc(reference_at,'reference_at'):
        raise RecoveryValidationError('Manual snapshot must precede the current time')
    shape = build_plan(snapshot, volume_root=volume_root, protected_root=protected_root,
                       manifest=['validation-only.tmp'], incident_at=reference_at)
    if backend is None:
        if os.name != 'nt':
            raise RecoveryValidationError('Live VSS enumeration requires Windows')
        if volume_id_for_root(volume_root) != snapshot.volume_id:
            raise RecoveryValidationError('Volume differs from the snapshot')
        current = select_snapshot(enumerate_snapshots(snapshot.volume_id), volume_id=snapshot.volume_id,
                                  incident_at=reference_at, snapshot_id=snapshot.snapshot_id)
        if current != snapshot:
            raise RecoveryValidationError('Snapshot metadata changed')
        source = Path(snapshot.device_path+'\\')
    elif isinstance(backend, LocalSnapshotBackend):
        source = Path(backend.snapshot_root).absolute()
    else:
        raise RecoveryValidationError('Explicit local test backend required')
    root = _check_chain(source, shape.protected_relative, final_directory=True)
    deadline = time.monotonic()+max_seconds
    pending, entries, seen = [(root, ())], [], set()
    total = visited = 0
    while pending:
        folder, relative = pending.pop()
        _assert_node(folder, directory=True)
        with os.scandir(folder) as listing:
            for item in listing:
                visited += 1
                if visited > max_files*4+100 or time.monotonic() > deadline:
                    raise RecoveryValidationError('Catalog traversal/time limit exceeded; no partial manifest')
                parts = relative+(item.name,)
                entry = ManifestEntry('\\'.join(parts))
                path = folder/item.name
                if item.is_dir(follow_symlinks=False):
                    _assert_node(path, directory=True)
                    pending.append((path, parts))
                    continue
                info = _assert_node(path, directory=False)
                if len(entries) >= max_files or info.st_size > max_file_bytes or total+info.st_size > max_total_bytes:
                    raise RecoveryValidationError('Catalog file/byte limit exceeded; no partial manifest')
                key = entry.relative_path.casefold()
                if key in seen:
                    raise RecoveryValidationError('Duplicate Windows path in catalog')
                digest, count = hashlib.sha256(), 0
                with path.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024*1024), b''):
                        count += len(chunk)
                        if count > max_file_bytes or total+count > max_total_bytes or time.monotonic() > deadline:
                            raise RecoveryValidationError('Catalog read bound exceeded')
                        digest.update(chunk)
                    after = os.fstat(stream.fileno())
                if count != info.st_size or after.st_size != info.st_size or after.st_mtime_ns != info.st_mtime_ns:
                    raise RecoveryValidationError('Snapshot file changed during catalog')
                seen.add(key);total += count
                entries.append(dict(relative_path=entry.relative_path, expected_sha256=digest.hexdigest(), expected_size=count))
    if not entries:
        raise RecoveryValidationError('Protected snapshot directory is empty')
    entries.sort(key=lambda x:x['relative_path'].casefold())
    return dict(schema_version=1, volume_root=shape.volume_root, protected_root=shape.protected_root,
                snapshot_id=snapshot.snapshot_id, snapshot_created_at=snapshot.created_at.isoformat(),
                volume_id=snapshot.volume_id, max_snapshot_age_seconds=max_age_seconds,
                catalog_created_at=_aware_utc(reference_at,'reference_at').isoformat(),
                manifest=entries, catalog_bytes=total, catalog_source='existing_vss_snapshot',
                complete_affected_file_list=False, automatic_activation=False,
                data_scope='regular_default_data_streams_only', operator_review_required=True)


def create_manifest(*, volume_root, protected_root, snapshot_id=None, **limits):
    at = datetime.now(timezone.utc)
    volume = volume_id_for_root(volume_root)
    snapshot = select_snapshot(enumerate_snapshots(volume), volume_id=volume, incident_at=at, snapshot_id=snapshot_id)
    return catalog_snapshot(snapshot, volume_root=volume_root, protected_root=protected_root, reference_at=at, **limits)
