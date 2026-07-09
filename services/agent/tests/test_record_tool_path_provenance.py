"""Record-side contract: ``_record_tool`` keeps the signed chain /home-free.

On disk/memory cases ``disk_extract_artifacts`` writes under
``<case_home>/cases/<id>/extracted/...`` and that ABSOLUTE path is recorded in each
tool call's ``arguments`` (the replay-bearing ``*_path`` keys) and its
``extra["artifact_path"]`` display copy. Recorded verbatim, the signed audit chain
leaks ``/home/<user>/...`` and the disk case dir is not publicly committable.

``_record_tool`` is the single choke point every tool site funnels through, so it
relativizes extracted ``*_path`` arguments + the ``artifact_path`` display copy to
``cases/<id>/extracted/...`` (the verifier's ``replay_tool_call`` resolves them back
to absolute before re-dispatch). These tests pin:

- P1: an extracted-style absolute path is recorded /home-free in BOTH the audit
      chain (``tool_call_start`` arguments, ``tool_call_output`` artifact_path) and
      ``self.tool_calls``.
- P2: a ``/evidence/`` source path (documented not-a-/home-leak) is recorded
      verbatim — relativizing it would break replay with no leak to fix.
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

from findevil_agent.case_paths import (  # noqa: E402
    relativize_extracted_path,
    resolve_extracted_path,
)


class _FakePy:
    def __init__(self) -> None:
        self.audits: list[tuple[str, dict]] = []

    def call_tool(self, name: str, args: dict, timeout: float = 600.0) -> dict:
        if name == "audit_append":
            self.audits.append((args["kind"], args["payload"]))
        return {}

    def close(self) -> None:  # pragma: no cover - parity with real client
        pass


def _inv() -> fea.Investigation:
    return fea.Investigation("/tmp/does-not-exist-evidence", case_id="case-paths")


def _records(py: _FakePy, kind: str) -> list[dict]:
    return [payload for k, payload in py.audits if k == kind]


def test_extracted_path_recorded_home_free(monkeypatch, tmp_path: Path) -> None:
    # P1: a recorded extracted-artifact *_path under case_home carries no /home in
    # the audit chain or self.tool_calls — it is stored relative to case_home.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    absolute = str(tmp_path / ".findevil/cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT")
    inv = _inv()
    py = _FakePy()

    tcid = inv._record_tool(
        py,
        "mft_timeline",
        "a" * 64,
        {"artifact_path": absolute, "row_count": 12},
        arguments={"case_id": "case-paths", "mft_path": absolute, "limit": 5000},
    )

    expected_rel = "cases/db256d79/extracted/disk/disk-extract-3bb2/mft/$MFT"

    start = _records(py, "tool_call_start")[0]
    assert start["arguments"]["mft_path"] == expected_rel
    assert "/home/" not in start["arguments"]["mft_path"]
    assert str(tmp_path) not in start["arguments"]["mft_path"]
    # Non-path args untouched.
    assert start["arguments"]["case_id"] == "case-paths"
    assert start["arguments"]["limit"] == 5000

    out = _records(py, "tool_call_output")[0]
    assert out["artifact_path"] == expected_rel
    assert "/home/" not in out["artifact_path"]

    recorded = inv.tool_calls[0]
    assert recorded["tool_call_id"] == tcid
    assert recorded["arguments"]["mft_path"] == expected_rel
    assert recorded["artifact_path"] == expected_rel


def test_evidence_path_recorded_verbatim(monkeypatch, tmp_path: Path) -> None:
    # P2: a /evidence/ source path is NOT under case_home, so it survives verbatim
    # (relativizing it would break replay, and it is documented not-a-/home-leak).
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    inv = _inv()
    py = _FakePy()

    inv._record_tool(
        py,
        "case_open",
        "b" * 64,
        {"artifact_path": "/evidence/SCHARDT.dd"},
        arguments={"case_id": "case-paths", "evidence_path": "/evidence/SCHARDT.dd"},
    )

    start = _records(py, "tool_call_start")[0]
    assert start["arguments"]["evidence_path"] == "/evidence/SCHARDT.dd"
    out = _records(py, "tool_call_output")[0]
    assert out["artifact_path"] == "/evidence/SCHARDT.dd"
    assert inv.tool_calls[0]["arguments"]["evidence_path"] == "/evidence/SCHARDT.dd"


def test_record_and_replay_mirrors_round_trip(monkeypatch, tmp_path: Path) -> None:
    # The script-side record mirror (find_evil_auto._relativize_extracted_path) and
    # the package-side replay helpers (findevil_agent.case_paths) must agree, or the
    # recorded relative path will not resolve back to the file at replay time.
    monkeypatch.setenv("FINDEVIL_HOME", str(tmp_path / ".findevil"))
    env = {"FINDEVIL_HOME": str(tmp_path / ".findevil")}
    absolute = str(tmp_path / ".findevil/cases/x/extracted/disk/dx/registry/SOFTWARE")

    script_rel = fea._relativize_extracted_path(absolute)
    package_rel = relativize_extracted_path(absolute, env=env)
    assert script_rel == package_rel
    assert "/home/" not in script_rel
    # Replay resolves the recorded value back to the exact absolute path.
    assert resolve_extracted_path(script_rel, env=env) == absolute
