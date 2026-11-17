# RansomGuard v0.3.0 Observer hotfix (2026-11-09)

This ZIP is a **patch overlay** onto the original VM project, not a full
standalone distribution. It keeps the release/version identifier at 0.3.0.

## Fix summary

- The observer no longer persists or analyzes *its own PID's* write/rename
  events targeting the exact outbox SQLite DB and -wal, -shm, -journal files.
- Both DOS drive paths and native NT volume paths are recognized when Windows
  QueryDosDeviceW can resolve the drive.
- Other processes writing to the DB, and all unrelated file events, remain
  visible. No general process or directory exclusion is added.
- The triage consumer still advances its event sequence when an internal
  outbox event is omitted, avoiding false sequence-gap resets.
- The observer_stopped event now records total decoded events, retained events,
  and self-storage events skipped.
- No JEV, firewall, termination, or VSS live behavior was enabled or changed.

## VM update, without reinstalling the package

1. Make a VMware snapshot / back up the existing project files.
2. Extract the ZIP **into** C:\RG_Test\v0.3.0, preserving its directories.
   Existing ransomguard\cli.py and ransomguard\triage.py will be replaced.
   Other original project files must remain untouched.
3. Open PowerShell in the VM and run:

        cd C:\RG_Test\v0.3.0
        .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p test_observer_filter.py -v
        .\.venv\Scripts\python.exe -m unittest discover -s .\tests -p test_cli_integration.py -v

4. In the first administrator PowerShell window, start an **observe-only** run.
   Invoke the package through Python to guarantee use of the overlaid source:

        cd C:\RG_Test\v0.3.0
        .\.venv\Scripts\python.exe -m ransomguard observe --limit 200 --db .\observe_hotfix.sqlite3 --status-every 50

5. In a second PowerShell window, generate two harmless writes:

        $probe = Join-Path 'C:\RG_Test' ("observe_hotfix_" + [guid]::NewGuid().ToString('N') + ".txt")
        "normal benign file write" | Set-Content -LiteralPath $probe
        "second benign write" | Add-Content -LiteralPath $probe
        $probe

6. If the bounded run has not finished after the TXT writes, stop it with
   Ctrl+C. In the **first** window:

        .\.venv\Scripts\python.exe .\tools\observer_hotfix_check.py .\observe_hotfix.sqlite3

Send the report output. observer_storage_events_skipped should be positive
when the driver delivers the observer's own SQLite I/O under the same PID.
The --limit value still caps all decoded driver events, including filtered
ones, so this smoke test cannot read an unbounded number of events.
The harmless TXT writes should still be visible as file_write_attempted.
Exact numbers depend on VM activity and must be measured.

**Do not add** --authorize-live or --live-track-b for this check.

## Evidence and limits

- Linux/offline: 157 of 157 available non-snapshot unit/integration tests pass,
  including new exact-path matching and observer/triage continuity tests.
- Full test discovery cannot finish from the uploaded ZIP: pyproject.toml
  references top-level create_snapshot.py and vss_recovery.py, but neither
  file was included. Keep those originals in the VM. Upload both if
  the full snapshot test suite needs to be reproduced externally.
- Windows actual path mapping and kernel load are **not** executable in this
  Linux environment. The VM steps above are still required.
