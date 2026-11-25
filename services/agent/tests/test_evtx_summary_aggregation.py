"""evtx_summary must aggregate across every parsed EVTX file, not just the last.

Root cause (ROCBA disk+memory fusion run auto-e58404ed): investigate_evtx
reassigned ``self.evtx_summary`` per file, so the top-level summary reflected
only the LAST evtx_query. When the last file processed was an empty log
(Intel-GFX-Info%4System.evtx, 0 records), the verdict reported
``records_seen: 0`` even though 20,619 records were actually parsed across
Security.evtx, System.evtx and dozens of Archive-Security logs. This test pins
that the summary now sums across all files, including a trailing empty one.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402


class _FakePy:
    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        return {}


class _MultiFileRust:
    """evtx_query returns a different parse result per evtx_path."""

    def __init__(self, by_path: dict[str, dict]) -> None:
        self._by_path = by_path

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "evtx_query":
            return self._by_path[args["evtx_path"]]
        return {}


def _inv() -> fea.Investigation:
    inv = fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-evtx-agg")
    inv.handle = {"id": "case-test"}
    return inv


def test_evtx_summary_aggregates_across_files_including_trailing_empty() -> None:
    inv = _inv()
    py = _FakePy()
    rust = _MultiFileRust(
        {
            "/case/Security.evtx": {
                "rows": [
                    {
                        "event_id": "4624",
                        "record_id": 1,
                        "channel": "Security",
                        "ts": "2020-10-22T00:00:00Z",
                    }
                ],
                "records_seen": 500,
                "parse_errors": 0,
            },
            "/case/System.evtx": {
                "rows": [
                    {
                        "event_id": "7045",
                        "record_id": 2,
                        "channel": "System",
                        "ts": "2020-10-22T01:00:00Z",
                    }
                ],
                "records_seen": 300,
                "parse_errors": 0,
            },
            # Trailing empty log -- the exact ROCBA failure mode.
            "/case/Intel-GFX-Info%4System.evtx": {
                "rows": [],
                "records_seen": 0,
                "parse_errors": 0,
            },
        }
    )

    inv.investigate_evtx(rust, py, "/case/Security.evtx")
    inv.investigate_evtx(rust, py, "/case/System.evtx")
    inv.investigate_evtx(rust, py, "/case/Intel-GFX-Info%4System.evtx")

    assert inv.evtx_summary is not None
    # Aggregate across all three files, not the trailing-empty last file only.
    assert inv.evtx_summary["records_seen"] == 800  # 500 + 300 + 0
    assert inv.evtx_summary["row_count"] == 2
    seen_ids = {e["event_id"] for e in inv.evtx_summary["top_event_ids"]}
    assert {"4624", "7045"} <= seen_ids
