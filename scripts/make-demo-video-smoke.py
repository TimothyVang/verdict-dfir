#!/usr/bin/env python3
"""Smoke tests for the Remotion-based demo video builder."""

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER_SCRIPT = REPO_ROOT / "scripts" / "make-demo-video.sh"
PIPER_SCRIPT = REPO_ROOT / "scripts" / "make-demo-video-tts.py"
ELEVENLABS_SCRIPT = REPO_ROOT / "scripts" / "make-demo-video-tts-elevenlabs.py"
REMOTION_DIR = REPO_ROOT / "scripts" / "make-demo-video"
ROOT_TSX = REMOTION_DIR / "src" / "Root.tsx"
PKG_JSON = REMOTION_DIR / "package.json"
BEAT_TSX = REMOTION_DIR / "src" / "beats" / "Beat.tsx"
BEATS_DATA = REMOTION_DIR / "src" / "beats" / "beats-data.ts"
COMPONENTS_DIR = REMOTION_DIR / "src" / "components"

EXPECTED_COMPONENTS = [
    "LogoIntro.tsx",
    "ArchDiagram.tsx",
    "TerminalScene.tsx",
    "ContradictionScene.tsx",
    "HashChainScene.tsx",
    "FleetScene.tsx",
    "ClusterScene.tsx",
    "VerdictScene.tsx",
    "OutroScene.tsx",
    "shared/ChipBadge.tsx",
    "shared/AuditLine.tsx",
]


def beat_timing() -> tuple[list[int], list[int], list[int]]:
    src = BEATS_DATA.read_text(encoding="utf-8")
    numbers = [int(n) for n in re.findall(r"number:\s*(\d+),", src)]
    start_values = [int(n) for n in re.findall(r"startS:\s*(\d+),", src)]
    end_values = [int(n) for n in re.findall(r"endS:\s*(\d+),", src)]
    assert numbers, f"No beat numbers found in {BEATS_DATA}"
    assert start_values, f"No beat start times found in {BEATS_DATA}"
    assert end_values, f"No beat end times found in {BEATS_DATA}"
    assert len(numbers) == len(start_values) == len(end_values), (
        f"Beat metadata lengths disagree: numbers={len(numbers)} "
        f"starts={len(start_values)} ends={len(end_values)}"
    )
    return numbers, start_values, end_values


def test_tts_scripts_syntax() -> None:
    for script in (PIPER_SCRIPT, ELEVENLABS_SCRIPT):
        source = script.read_text(encoding="utf-8")
        ast.parse(source)


def test_remotion_package_has_remotion_dep() -> None:
    pkg = json.loads(PKG_JSON.read_text(encoding="utf-8"))
    deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
    assert "remotion" in deps, f"remotion not in deps: {list(deps.keys())}"
    assert "@remotion/cli" in deps, "@remotion/cli not in deps"


def test_root_tsx_has_register_root() -> None:
    src = ROOT_TSX.read_text(encoding="utf-8")
    assert "registerRoot" in src, "Root.tsx must call registerRoot()"


def test_beat_components_exist() -> None:
    missing = []
    for name in EXPECTED_COMPONENTS:
        path = COMPONENTS_DIR / name
        if not path.exists():
            missing.append(name)
    assert not missing, f"Missing components: {missing}"


def test_beat_dispatch_covers_all_configured_beats() -> None:
    src = BEAT_TSX.read_text(encoding="utf-8")
    numbers, _, _ = beat_timing()
    for n in numbers:
        assert f"case {n}:" in src, f"Beat.tsx missing dispatch for beat {n}"


def test_beat_data_has_ten_beats_and_275s() -> None:
    numbers, _, ends = beat_timing()
    assert numbers == list(range(1, 11)), f"Unexpected beat numbers: {numbers}"
    assert ends[-1] == 275, f"Expected 275s total, got {ends[-1]}s"


# --- Additional videos (explainer, deep-dives, quickstart, contributor call) ---

ADDITIONAL_BEAT_FILES = [
    "explainer-beats.ts",
    "deepdive-beats.ts",
    "quickstart-beats.ts",
    "contributor-beats.ts",
]
ADDITIONAL_COMPOSITIONS = [
    "EducationalExplainer",
    "FeatureDeepDives",
    "Quickstart",
    "ContributorCall",
]


def _timing_for(beats_file: Path) -> tuple[list[int], list[int], list[int]]:
    src = beats_file.read_text(encoding="utf-8")
    numbers = [int(n) for n in re.findall(r"number:\s*(\d+),", src)]
    starts = [int(n) for n in re.findall(r"startS:\s*(\d+),", src)]
    ends = [int(n) for n in re.findall(r"endS:\s*(\d+),", src)]
    return numbers, starts, ends


def test_additional_beat_files_exist_and_are_contiguous() -> None:
    beats_dir = BEATS_DATA.parent
    for name in ADDITIONAL_BEAT_FILES:
        path = beats_dir / name
        assert path.exists(), f"Missing beats file: {path}"
        numbers, starts, ends = _timing_for(path)
        assert numbers, f"No beats found in {name}"
        assert (
            len(numbers) == len(starts) == len(ends)
        ), f"Field counts disagree in {name}"
        assert starts[0] == 0, f"{name}: first beat must start at 0s"
        for i, n in enumerate(numbers):
            assert ends[i] > starts[i], f"{name}: beat {n} has non-positive duration"
            if i > 0:
                assert (
                    starts[i] == ends[i - 1]
                ), f"{name}: beat {n} timing not contiguous"


def test_root_registers_additional_compositions() -> None:
    src = ROOT_TSX.read_text(encoding="utf-8")
    for comp in ADDITIONAL_COMPOSITIONS:
        assert f'id="{comp}"' in src, f"Root.tsx missing composition id={comp}"


def test_builder_knows_additional_compositions() -> None:
    src = BUILDER_SCRIPT.read_text(encoding="utf-8")
    for comp in ADDITIONAL_COMPOSITIONS:
        assert comp in src, f"make-demo-video.sh missing default for {comp}"


def test_beat_timing_is_contiguous_and_positive() -> None:
    numbers, starts, ends = beat_timing()
    assert starts[0] == 0, f"First beat should start at 0s, got {starts[0]}s"
    for index, number in enumerate(numbers):
        assert ends[index] > starts[index], f"Beat {number} has non-positive duration"
        if index > 0:
            assert starts[index] == ends[index - 1], (
                f"Beat {number} starts at {starts[index]}s, "
                f"previous beat ended at {ends[index - 1]}s"
            )


def test_logo_assets_exist() -> None:
    logo = REPO_ROOT / "assets" / "logo" / "logo.svg"
    mark = REPO_ROOT / "assets" / "logo" / "logo-mark.svg"
    assert logo.exists(), f"Missing: {logo}"
    assert mark.exists(), f"Missing: {mark}"


def test_dry_run_uses_active_piper_builder() -> None:
    result = subprocess.run(
        ["bash", str(BUILDER_SCRIPT), "--dry-run"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, f"--dry-run failed:\n{result.stderr[:300]}"
    assert "make-demo-video-tts.py" in result.stdout, result.stdout
    assert "Piper" in result.stdout, result.stdout


def main() -> int:
    tests = [
        ("tts_scripts_syntax", test_tts_scripts_syntax),
        ("remotion_package_has_remotion_dep", test_remotion_package_has_remotion_dep),
        ("root_tsx_has_register_root", test_root_tsx_has_register_root),
        ("beat_components_exist", test_beat_components_exist),
        (
            "beat_dispatch_covers_all_configured_beats",
            test_beat_dispatch_covers_all_configured_beats,
        ),
        ("beat_data_has_ten_beats_and_275s", test_beat_data_has_ten_beats_and_275s),
        (
            "additional_beat_files_exist_and_are_contiguous",
            test_additional_beat_files_exist_and_are_contiguous,
        ),
        (
            "root_registers_additional_compositions",
            test_root_registers_additional_compositions,
        ),
        (
            "builder_knows_additional_compositions",
            test_builder_knows_additional_compositions,
        ),
        (
            "beat_timing_is_contiguous_and_positive",
            test_beat_timing_is_contiguous_and_positive,
        ),
        ("logo_assets_exist", test_logo_assets_exist),
        ("dry_run_uses_active_piper_builder", test_dry_run_uses_active_piper_builder),
    ]
    passed = failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except Exception as exc:
            print(f"  [FAIL] {name}: {exc}")
            failed += 1
    print(f"\nmake-demo-video-smoke: {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
