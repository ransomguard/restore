# Owned VSS retention

The default policy retains up to 12 owned snapshots for 24 hours, keeps at least
the newest two owned copies, and uses a 4 GiB shared-volume VSS used/allocated
space budget. Creation requires 512 MiB additional headroom and 2 GiB free space
on the diff-area volume. Cleanup runs every five minutes; creation remains hourly.

Recovery and review protection overrides age, count and space targets. If protected
copies prevent meeting the target, the result is blocked and new creation is
skipped. The result is not reported as a satisfied hard quota. VSS differential
storage is shared; individual snapshot byte sizes are not fabricated. Windows
shadowstorage limits are never resized because that may delete other copies.
Existing Windows/provider eviction and ongoing volume writes remain outside this
application's deletion gate. The policy cannot guarantee survival against those
external actions; missing owned IDs are reported separately from our deletions.

## Ownership and protection

Only successful, verified `snapshot_attempts` creation receipts establish
ownership. ID, volume GUID and creation time must match the current inventory.
Device-object numbers may change across sessions; current metadata is rechecked
immediately before exact-ID deletion. Unknown and reconciled-only copies are not
adopted. No volume-wide, oldest-copy, snapshot-set, or resize deletion is used.

- Unresolved firewall holds, response reservations and queued/review jobs protect
  all existing snapshots at or before the recorded claim time, conservatively.
- Explicit approved manifest IDs are pinned, regardless of age.
- Every live RecoveryEngine job pins its exact snapshot durably. Failure/crash
  leaves that pin; verified success releases it. Pins do not expire by timeout.
- Recovery/response and cleanup share a Windows global mutex. No intake SQLite
  write transaction is held while waiting for that mutex.
- Missing/corrupt protection state blocks deletion and creation. Removing the
  policy file after activation cannot bypass the remembered requirement.
- Deletion intent is persisted first. A timeout with a still-present target is
  never blindly retried. Check `snapshot_deletions` before resolving uncertainty.
- `snapshot_retention_runs` preserves outcomes, including unmet space targets.

## Existing VM setup

Keep the original machine-wide ownership database at
`%ProgramData%\RansomGuard\snapshots.sqlite3`. Never replace it with an empty DB to
claim existing snapshots. Live recovery uses the same path for its pins.

After deploying the source and initializing the collector's existing response
databases, run `deployment/configure_snapshot_retention.py` on the Windows guest
with explicit paths. It requires `--python`, `--config`, `--outbox`, `--holds`,
one or more `--manifest`, the logged-on administrator's `--user-sid`, and a new
`--output` XML path. `--check` validates without writing. The defaults above are
written to the `.retention.json` sidecar. This prepares policy/XML only.

Register the generated XML in elevated PowerShell without embedding a password:

```powershell
$xml = Get-Content -Raw -Encoding UTF8 -LiteralPath 'C:\RansomGuard\runtime\retention-task.xml'
$xml = $xml -replace '^<\?xml[^?]*\?>\s*',''
Register-ScheduledTask -TaskName 'RansomGuard-SnapshotRetention' -Xml $xml
```

The encoding declaration is removed because the task API receives a UTF-16
string. The task uses the interactive user's SID, not the SID of a SYSTEM
deployment agent. It runs while that user is logged on; no autologon/password
change is made. Also update the existing hourly task's executable/module path to
this version, preserving its trigger, state DB and identity. Leaving it pointed
at an old package bypasses the new policy.

The task runs `python -I -m ransomguard`: copying sources or changing its working
directory alone does not update an already installed package. Install the new
version into that exact interpreter. For an offline guest, transfer trusted
setuptools (>=68) and wheel packages prepared on the development host, then:

```powershell
& $python -m pip install --no-index --no-deps --find-links C:\RansomGuard\wheelhouse setuptools wheel
& $python -m pip install --no-index --no-deps --no-build-isolation --editable C:\RansomGuard\restore\v0.5.1
& $python -I -c "import ransomguard; print(ransomguard.__version__, ransomguard.__file__)"
```

Verify version 0.5.1 and the intended source directory before enabling the tasks.
Keep that directory in place for an editable install. Preserve any unrelated
dependencies already installed in the interpreter. Test the actual scheduled
invocation and match its time to a new `snapshot_retention_runs` entry: exit 2
alone does not distinguish a legitimate capacity block from an old CLI error.

Preview or apply independently using the same state:

```powershell
python -m ransomguard snapshot-retention --state-db 'C:\ProgramData\RansomGuard\snapshots.sqlite3' --volume-root 'C:\'
# Add --apply only to perform the reviewed owned-only policy.
```

Exit code 2 means unresolved capacity/protection or another blocked operation;
inspect the JSON reason. It does not authorize dropping protected snapshots or
clearing incident holds. The existing UI layout and network/account policy are
unaffected.

References: [VSS shared storage counters](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/vsswmi/win32-shadowstorage),
[resizing can remove snapshots](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin-resize-shadowstorage).
