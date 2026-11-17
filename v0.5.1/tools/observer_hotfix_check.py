"""Read-only verification of observer self-storage filtering.

Usage:
    python tools/observer_hotfix_check.py observe_hotfix.sqlite3
"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sqlite3
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python tools/observer_hotfix_check.py OBSERVER_DB.sqlite3")
        return 2
    path = Path(sys.argv[1]).resolve()
    if not path.is_file():
        print(f"Database not found: {path}")
        return 2

    # URI read-only mode avoids creating a fresh SQLite write feedback event.
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as conn:
        counts = Counter()
        last_stop = None
        for kind, encoded in conn.execute("SELECT kind, payload FROM events ORDER BY sequence"):
            counts[kind] += 1
            if kind == "observer_stopped":
                last_stop = json.loads(encoded)
    if last_stop is None:
        print("No observer_stopped record yet. Stop observe with Ctrl+C first.")
        return 1
    summary = {
        "raw_events_read": last_stop.get("events_read"),
        "events_recorded": last_stop.get("events_recorded"),
        "observer_storage_events_skipped": last_stop.get("observer_storage_events_skipped"),
        "kernel_events_saved": counts["kernel_event"],
        "track_b_candidates": counts["track_b_candidate"],
        "triage_resets": counts["triage_reset"],
        "observer_stopped": counts["observer_stopped"],
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
