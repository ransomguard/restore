# Recovery and evaluation stabilization

This change adds safety checks and validation tools. It does not certify JEV
classification accuracy or expand the live protection scope automatically.

## Snapshot-backed recovery catalogs

Run on the protected Windows guest, using an existing VSS snapshot:

```powershell
python -m ransomguard recovery-catalog --volume-root 'C:\' --protected-root 'C:\ProtectedDocs' --output '.\review-manifest.json'
```

The command enumerates regular file data from VSS, records each relative path,
size and SHA256, and pins the snapshot ID and volume ID. It does not read live
file contents as a trusted baseline. The output path must not already exist.
Default bounds are 5,000 files, 512 MiB per file, 2 GiB total and 30 seconds.
Unsafe entries or exceeded bounds fail the entire catalog, without publishing a
partial success. Reparse points and encrypted files are rejected; this is not
an ACL, alternate-data-stream or EFS backup mechanism.

Review the selected protected directory and manifest before configuring live
response. A catalog is not a complete list of files affected by an incident.
Automatic restoration continues to require explicit approved scope, process
generation evidence and a verified recovery plan.

Automatic template selection now requires a snapshot older than the incident
and at most 7,200 seconds old by default. `max_snapshot_age_seconds` may specify
60–86,400 seconds. A pinned snapshot cannot silently fall back to another one.
An unsuitable snapshot keeps the incident in review and retains its firewall
hold. The existing UI failure channel now also reports selection failures that
have no snapshot ID; it never fabricates a successful restore or recovered files.

## Independently labelled evaluation

```powershell
python -m ransomguard.evaluation --input '.\labelled-results.json' --output '.\evaluation.json'
```

Input is a JSON array. Each row needs `case_id`, `group_id`, `label`
(`benign`/`malicious`), `split` (`development`/`holdout`), `source`
(`representative_labelled`/`harmless_vm_scenario`/`synthetic_fixture`), resolved
`model`, unique `request_id`, and a numeric `score` in [0,1]. Labels must come
from independent ground truth, never from the score being evaluated.

The evaluator rejects duplicate cases/requests, groups crossing the development
and holdout split, mixed resolved models and invalid scores. It reports holdout
confusion counts, benign cases classified malicious, malicious cases released
as benign, and review rate separately. It changes no live policy and always
leaves `calibration_approved` false. A representative corpus, agreed acceptance
criteria and human review are still required. A few harmless VM scenarios are
collection/integration checks, not evidence of production false-positive rates.

## Validation and deployment boundaries

- Guest Python suite: 337 tests passed.
- Actual VSS file test: 30 independently hash-checked CSV files restored,
  including one deliberately deleted file; no manual restoration fallback.
- A ten-minute benign-work interval had no additional dropped/flushed events.
- Backend changes were handed over to the existing resident collector without
  unregistering it. Installed hashes and a complete fresh heartbeat were checked.
- The initial deployment verifier observed a handshake before counter metadata
  arrived; a subsequent read-only check confirmed the installation. The verifier
  now waits for both running state and populated counter metadata.

The kernel/ABI and resident intake implementation were not changed by this
stabilization patch. Existing counters, review holds and live scope remain intact.
The integrated installer is a separate deliverable.
