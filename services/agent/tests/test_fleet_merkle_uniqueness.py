"""fleet_correlate.merkle_uniqueness — count per-host Merkle roots.

Audit finding: when manifest_finalize runs AFTER verdict.json is written
(manifest_finalized_after_verdict=true), the per-host root lives only in
run.manifest.json, not in verdict.json's cryptographic_attestation — so the
fleet rollup reported 0/0 unique Merkle roots despite real, unique per-host
ed25519 roots. merkle_uniqueness must fall back to the per-host manifest.
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


fleet_correlate = _load("fleet_correlate")


def _host(case_dir: Path, root: str | None, *, in_verdict: bool) -> dict:
    case_dir.mkdir(parents=True, exist_ok=True)
    ca = {"manifest_finalized_after_verdict": not in_verdict}
    if in_verdict and root:
        ca["merkle_root_hex"] = root
    if root:
        (case_dir / "run.manifest.json").write_text(json.dumps({"merkle_root_hex": root}))
    return {"cryptographic_attestation": ca, "_case_dir": str(case_dir)}


def test_falls_back_to_manifest_when_verdict_lacks_root(tmp_path: Path) -> None:
    verdicts = [
        _host(tmp_path / "h1", "aaa111", in_verdict=False),
        _host(tmp_path / "h2", "bbb222", in_verdict=False),
        _host(tmp_path / "h3", "ccc333", in_verdict=False),
    ]
    unique, total = fleet_correlate.merkle_uniqueness(verdicts)
    assert (unique, total) == (3, 3)


def test_still_reads_root_from_verdict_when_present(tmp_path: Path) -> None:
    verdicts = [_host(tmp_path / "h1", "aaa111", in_verdict=True)]
    assert fleet_correlate.merkle_uniqueness(verdicts) == (1, 1)


def test_counts_duplicates_as_non_unique(tmp_path: Path) -> None:
    verdicts = [
        _host(tmp_path / "h1", "same", in_verdict=False),
        _host(tmp_path / "h2", "same", in_verdict=False),
    ]
    assert fleet_correlate.merkle_uniqueness(verdicts) == (1, 2)


def test_missing_root_is_skipped(tmp_path: Path) -> None:
    verdicts = [_host(tmp_path / "h1", None, in_verdict=False)]
    assert fleet_correlate.merkle_uniqueness(verdicts) == (0, 0)
