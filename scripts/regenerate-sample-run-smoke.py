#!/usr/bin/env python3
"""Smoke test: scripts/regenerate-sample-run.py path-scrubbing + custody boundary.

Builds a synthetic run dir (no real evidence) and proves:

- the ``/home/<user>`` machine-path class is scrubbed out of DISPLAY artifacts;
- SHA-256 digests, ISO-8601 timestamps, and enum tokens are left untouched;
- the run-dir absolute prefix is relativized to the repo-relative destination;
- CUSTODY-BOUND artifacts (audit.jsonl, verdict.json, run.manifest.json,
  manifest_verify.json) are copied byte-for-byte and warned about, never scrubbed
  (scrubbing them would break manifest_verify replay);
- the scrub is deterministic (same input -> same output);
- the CLI ``--dry-run`` writes nothing.

Stdlib-only; runs under the same bare python3 as the host engine.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
SCRIPT_PATH = SCRIPTS_DIR / "regenerate-sample-run.py"

# Synthetic, machine-specific provenance the scrub must remove. Not a real path.
FAKE_HOME = "/home/synthuser"
SHA = "a" * 64  # a SHA-256-shaped digest that must survive untouched
TS = "2026-06-12T20:33:02Z"  # an ISO-8601 timestamp that must survive untouched
ENUM = "SUSPICIOUS"  # an enum token that must survive untouched
RECALL = 0.8333  # a scoring number that must survive untouched


def load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("regen_sample_run", SCRIPT_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so the module's @dataclass can resolve cls.__module__.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def build_run_dir(root: Path) -> tuple[Path, str]:
    """Create a synthetic source run dir. Returns (run_dir, run_dir_abs)."""
    run_dir = root / "tmp" / "auto-runs" / "case-xyz"
    run_dir.mkdir(parents=True)
    run_dir_abs = str(run_dir.resolve())
    evidence = f"{FAKE_HOME}/proj/evidence/sample.dd"

    # --- custody-bound artifacts (must be copied verbatim) ---
    (run_dir / "audit.jsonl").write_text(
        json.dumps(
            {
                "seq": 0,
                "ts": TS,
                "kind": "tool_call_start",
                "prev_hash": "",
                "payload": {"arguments": {"image_path": evidence}, "tool": "case_open"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "verdict.json").write_text(
        json.dumps({"verdict": ENUM, "evidence_path": evidence, "output_hash": SHA}),
        encoding="utf-8",
    )
    (run_dir / "run.manifest.json").write_text(
        json.dumps(
            {"audit_log_path": f"{run_dir_abs}/audit.jsonl", "merkle_root_hex": SHA}
        ),
        encoding="utf-8",
    )
    (run_dir / "manifest_verify.json").write_text(
        json.dumps({"overall": True, "_mcp_output_sha256": SHA}),
        encoding="utf-8",
    )

    # --- display artifacts (must be scrubbed) ---
    (run_dir / "REPORT.md").write_text(
        "# Report\n"
        f"Evidence: {evidence}\n"
        f"Verdict artifact: {run_dir_abs}/verdict.json\n"
        f"Verdict: {ENUM}\n"
        f"Output hash: {SHA}\n"
        f"Sealed at: {TS}\n",
        encoding="utf-8",
    )
    (run_dir / "recall-score.json").write_text(
        json.dumps({"recall": RECALL, "evidence_path": evidence, "verdict": ENUM}),
        encoding="utf-8",
    )
    (run_dir / "coverage_manifest.json").write_text(
        json.dumps({"image_path": evidence, "parsed": ["mft", "registry"]}),
        encoding="utf-8",
    )
    return run_dir, run_dir_abs


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


def test_scrub_text_leaves_hash_ts_enum(mod: types.ModuleType) -> None:
    text = f"path {FAKE_HOME}/proj/x.dd hash {SHA} ts {TS} verdict {ENUM} num {RECALL}"
    scrubbed, count = mod.scrub_text(text, home_placeholder="<HOME>")
    assert count == 1, f"expected exactly one /home scrub, got {count}"
    assert "/home/" not in scrubbed and "/Users/" not in scrubbed
    assert "<HOME>/proj/x.dd" in scrubbed, scrubbed
    assert SHA in scrubbed, "SHA digest must be untouched"
    assert TS in scrubbed, "timestamp must be untouched"
    assert ENUM in scrubbed, "enum token must be untouched"
    assert str(RECALL) in scrubbed, "scoring number must be untouched"


def test_scrub_text_deterministic(mod: types.ModuleType) -> None:
    text = f"a {FAKE_HOME}/p/x b {FAKE_HOME}/q/y"
    first = mod.scrub_text(text, home_placeholder="<HOME>")
    second = mod.scrub_text(text, home_placeholder="<HOME>")
    assert first == second, "scrub_text must be deterministic"
    assert first[1] == 2, "both /home prefixes must be counted"


def test_custody_bound_copied_verbatim(mod: types.ModuleType, tmp: Path) -> None:
    run_dir, _ = build_run_dir(tmp / "src_verbatim")
    into = tmp / "dst_verbatim"
    plans = mod.plan_regeneration(run_dir, str(into), repo_root=tmp)
    mod.apply_plans(plans, into.resolve())

    by_name = {p.name: p for p in plans}
    for name in (
        "audit.jsonl",
        "verdict.json",
        "run.manifest.json",
        "manifest_verify.json",
    ):
        plan = by_name[name]
        assert plan.custody_bound, f"{name} must be custody-bound"
        assert plan.scrub_count == 0, f"{name} must never be scrubbed"
        assert _sha(run_dir / name) == _sha(
            into / name
        ), f"{name} must be byte-identical"

    # The custody-bound files that carried a /home path must raise a leak warning.
    for name in ("audit.jsonl", "verdict.json", "run.manifest.json"):
        assert (
            by_name[name].leak_count > 0
        ), f"{name} leak must be reported, not silently dropped"


def test_display_artifacts_scrubbed(mod: types.ModuleType, tmp: Path) -> None:
    run_dir, run_dir_abs = build_run_dir(tmp / "src_display")
    into = tmp / "sub" / "dst_display"  # nested so dest_rel is multi-segment
    plans = mod.plan_regeneration(run_dir, str(into), repo_root=tmp)
    mod.apply_plans(plans, into.resolve())

    report = (into / "REPORT.md").read_text(encoding="utf-8")
    assert (
        "/home/" not in report and "/Users/" not in report
    ), "report still leaks /home"
    assert run_dir_abs not in report, "run-dir absolute prefix must be relativized"
    assert "<HOME>/proj/evidence/sample.dd" in report, report
    assert (
        SHA in report and TS in report and ENUM in report
    ), "hash/ts/enum must survive"

    recall = json.loads((into / "recall-score.json").read_text(encoding="utf-8"))
    assert recall["recall"] == RECALL, "scoring number must be untouched"
    assert "/home/" not in recall["evidence_path"], "recall sidecar still leaks /home"

    coverage = (into / "coverage_manifest.json").read_text(encoding="utf-8")
    assert "/home/" not in coverage, "coverage manifest still leaks /home"

    by_name = {p.name: p for p in plans}
    assert (
        by_name["REPORT.md"].scrub_count >= 2
    ), "report had >=2 machine paths to scrub"
    for name in ("REPORT.md", "recall-score.json", "coverage_manifest.json"):
        assert by_name[name].leak_count == 0, f"{name} must be clean after scrub"


def test_dry_run_writes_nothing(tmp: Path) -> None:
    run_dir, _ = build_run_dir(tmp / "src_dry")
    into = tmp / "dst_dry"
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--from",
            str(run_dir),
            "--into",
            str(into),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert not into.exists(), "--dry-run must not create the destination"
    assert "DRY RUN" in result.stdout, result.stdout
    assert "[SCRUB] REPORT.md" in result.stdout, result.stdout
    assert "WARNING" in result.stdout, "custody-bound leak warning must be printed"


def main() -> int:
    mod = load_module()
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        tests = [
            (
                "scrub_text_leaves_hash_ts_enum",
                lambda: test_scrub_text_leaves_hash_ts_enum(mod),
            ),
            ("scrub_text_deterministic", lambda: test_scrub_text_deterministic(mod)),
            (
                "custody_bound_copied_verbatim",
                lambda: test_custody_bound_copied_verbatim(mod, tmp),
            ),
            (
                "display_artifacts_scrubbed",
                lambda: test_display_artifacts_scrubbed(mod, tmp),
            ),
            ("dry_run_writes_nothing", lambda: test_dry_run_writes_nothing(tmp)),
        ]
        passed = 0
        failed = 0
        for name, fn in tests:
            try:
                fn()
                print(f"  [PASS] {name}")
                passed += 1
            except Exception as exc:  # noqa: BLE001 - smoke reports, never crashes
                print(f"  [FAIL] {name}: {exc}")
                failed += 1
    print(f"\nregenerate-sample-run-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
