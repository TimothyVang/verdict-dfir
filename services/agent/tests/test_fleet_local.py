"""fleet_local.py — adapt a local whole-case run into a correlate-ready fleet.

The one-command fleet path runs run-whole-case-local.sh (results.jsonl) and
then needs a fleet.json in the exact shape fleet_correlate.load_verdicts reads.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


fleet_local = _load("fleet_local")


def _write_results(fleet_dir: Path, rows: list[dict]) -> None:
    fleet_dir.mkdir(parents=True, exist_ok=True)
    with (fleet_dir / "results.jsonl").open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


class TestResultsToFleet:
    def test_rows_become_fleet_results(self, tmp_path: Path) -> None:
        case_a = tmp_path / "case-a"
        case_a.mkdir()
        _write_results(
            tmp_path,
            [
                {
                    "host": "mem:base-dc",
                    "verdict": "INDETERMINATE",
                    "manifest_ok": True,
                    "case_dir": str(case_a),
                },
                {
                    "host": "disk:dmz-ftp-cdrive",
                    "verdict": "SUSPICIOUS",
                    "manifest_ok": True,
                    "case_dir": str(tmp_path / "case-b"),
                },
                # A failed target: no case_dir — kept, marked error, skipped
                # downstream by load_verdicts.
                {"host": "mem:broken", "verdict": "ERROR", "error": "boom"},
            ],
        )
        out = fleet_local.results_to_fleet(tmp_path)
        fleet = json.loads((tmp_path / "fleet.json").read_text(encoding="utf-8"))
        assert out == tmp_path / "fleet.json"
        assert fleet["total"] == 3
        by_host = {r["host"]: r for r in fleet["results"]}
        # mem:/disk: labels are stripped to plain host names.
        assert "base-dc" in by_host
        assert by_host["base-dc"]["case_dir"] == str(case_a)
        assert by_host["base-dc"]["status"] == "ok"
        assert by_host["dmz-ftp-cdrive"]["verdict"] == "SUSPICIOUS"
        assert by_host["broken"]["status"] == "error"
        assert "case_dir" not in by_host["broken"] or not by_host["broken"]["case_dir"]

    def test_round_trip_through_fleet_correlate_load_verdicts(self, tmp_path: Path) -> None:
        case_a = tmp_path / "case-a"
        case_a.mkdir()
        (case_a / "verdict.json").write_text(
            json.dumps({"verdict": "SUSPICIOUS", "findings": []}), encoding="utf-8"
        )
        _write_results(
            tmp_path,
            [
                {
                    "host": "disk:base-file-cdrive",
                    "verdict": "SUSPICIOUS",
                    "manifest_ok": True,
                    "case_dir": str(case_a),
                }
            ],
        )
        fleet_local.results_to_fleet(tmp_path)
        fc = _load("fleet_correlate")
        verdicts = fc.load_verdicts(tmp_path)
        assert len(verdicts) == 1
        assert verdicts[0]["_host"] == "base-file-cdrive"
        assert verdicts[0]["verdict"] == "SUSPICIOUS"

    def test_missing_results_jsonl_raises_clean_error(self, tmp_path: Path) -> None:
        import pytest

        with pytest.raises(SystemExit):
            fleet_local.results_to_fleet(tmp_path / "nope")
