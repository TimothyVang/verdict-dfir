#!/usr/bin/env python3
"""smoke-regex-tests - regression tests for audit-smoke regexes and
small helper policies.

The audit smokes (divergence-smoke, launcher-smoke, path-existence-
smoke) catch drift in the rest of the codebase, but the smokes
themselves have no automated regression coverage.  If a future
contributor breaks a regex (over-broad / over-narrow / typo), the
smoke would still report "all clean" while silently letting bugs
through.

This script imports each smoke module and runs synthetic positive +
negative cases against its key regexes and small helper policies. Exits
0 if all cases classify correctly, 1 if any case is wrong.

The test fixtures here are derived from the manual negative tests
I ran when each smoke was first shipped (commits 0155503 +
c5bfa1b + e90b4f9).  Each fixture documents WHY it should match
or not match in a comment.

Wall-clock: ~30ms (no subprocess spawn; just regex/helper checks).
Wired into docker/l1-compose.yml after the audit smokes as their
self-test gate.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: str):
    """Import a script module by file path."""
    full = REPO / path
    spec = importlib.util.spec_from_file_location(name, full)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# Test cases:
#   (label, regex_attr, fixture_text, expected_count)
# regex_attr is a dotted path inside the module's DIVERGENCES /
# BAD_BINARY_PATTERNS / etc. structure.

DIVERGENCE_CASES = [
    # (test label, divergence #idx, fixture, expected match count)
    ("rust:1.83-bookworm Docker base", 0, "FROM rust:1.83-bookworm", 1),
    ("rust:1.88-bookworm is allowed", 0, "FROM rust:1.88-bookworm", 0),
    (
        "exec python3 -m findevil_agent.cli active drift",
        1,
        'exec python3 -m findevil_agent.cli "$@"',
        1,
    ),
    (
        "find-evil run active drift",
        1,
        "find-evil run --case foo",
        1,
    ),
    (
        "backticked find-evil run is doc-quote, not drift",
        1,
        "# Comment quoting `find-evil run` from old docs",
        0,
    ),
    (
        "11 typed Rust active drift",
        2,
        "wraps 11 typed Rust MCP tools",
        1,
    ),
    (
        "12 typed Rust active drift",
        2,
        "wraps 12 typed Rust MCP tools",
        1,
    ),
    (
        "13 typed Rust is correct",
        2,
        "wraps 13 typed Rust MCP tools",
        0,
    ),
    (
        "uncommented rmcp = is active drift",
        3,
        'rmcp = "=0.16.0"',
        1,
    ),
    (
        "commented rmcp = is the deliberate marker",
        3,
        '# rmcp = "=0.16.0"  # commented marker',
        0,
    ),
]


LAUNCHER_BAD_BINARY_CASES = [
    # (label, fixture, expected count from BAD_BINARY_PATTERNS combined)
    ("exec claude-code . is bug", "exec claude-code .", 1),
    ("command -v claude-code is bug", "command -v claude-code", 1),
    ("exec claude is correct", "exec claude", 0),
    ("command -v claude is correct", "command -v claude", 0),
    ("comment quoting claude-code-mode.md is OK", "# see claude-code-mode.md", 0),
    ("commented command -v claude-code is OK", "# command -v claude-code", 0),
    (
        "indented commented command -v claude-code is OK",
        "  # command -v claude-code",
        0,
    ),
    (
        "URL path .../claude-code/install is OK",
        "https://docs.anthropic.com/en/docs/claude-code/install",
        0,
    ),
]

LAUNCHER_BAD_INVOCATION_CASES = [
    # (label, fixture, expected count)
    ("exec claude . is bug", "exec claude .", 1),
    ("exec claude is correct", "exec claude", 0),
    (
        'exec claude . " is bug (followed by quote)',
        'exec claude . "interactive"',
        1,
    ),
]

LAUNCHER_TIMEOUT_ENV = "FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS"

LAUNCHER_TIMEOUT_CASES = [
    # (label, env value or None for unset, expected or "platform_default")
    ("unset uses platform default", None, "platform_default"),
    ("integer env override is honored", "7", 7),
    ("invalid env falls back to default", "not-int", "platform_default"),
    ("oversized env clamps to max", "999", "max"),
    ("zero env clamps to one", "0", 1),
]

SMOKE_RUNNER_POLICY_CASE_COUNT = 9

STALE_SMOKE_LABEL_PATTERNS = [
    # Known stale fixed-count phrases removed from active smoke/docs
    # surfaces. This is not a blanket ban on all historical or
    # intentional count-bearing prose.
    ("fleet policy fixed function count", "fleet-policy-smoke (7 functions"),
    ("divergence fixed active count", "divergence-smoke (5 active divergences"),
    ("operator doc fixed path count", "operator docs (~23 currently"),
    ("path smoke fixed false-positive count", "43-of-47 false-positive"),
    ("quickstart fixed smoke-count bump", "QUICKSTART smoke count"),
]

SMOKE_LABEL_POLICY_FILES = [
    "AGENTS.md",
    "CHANGELOG.md",
    "CLAUDE.md",
    "QUICKSTART.md",
    "README.md",
    "docker/l1-compose.yml",
    "docs/README.md",
    "scripts/path-existence-smoke.py",
    "scripts/run-all-smokes.ps1",
    "scripts/run-all-smokes.sh",
]

PATH_EXISTENCE_ALLOW_CASES = [
    # (label, candidate, expected_allowed)
    ("URL is allowed", "https://example.com/x/y", True),
    ("MCP wire identifier tools/list", "tools/list", True),
    ("MCP wire identifier tools/call", "tools/call", True),
    ("Runtime user dir ~/.claude/", "~/.claude/foo", True),
    ("Install path /usr/bin/find-evil", "/usr/bin/find-evil", True),
    ("Live apps/web/ path is NOT allow-listed", "apps/web/lib/foo.ts", False),
    ("Deferred-A2 apps/mcp-widgets/", "apps/mcp-widgets/src/foo.ts", True),
    (
        "Dropped-A2 findevil_agent/cli.py is allow-listed",
        "services/agent/findevil_agent/cli.py",
        True,
    ),
    (
        "OTRF external dataset path",
        "datasets/atomic/windows/credential_access",
        True,
    ),
    (
        "Real local path is NOT allow-listed",
        "scripts/find-evil-auto",
        False,
    ),
    (
        "Real-but-broken path is NOT allow-listed",
        "services/foo/bar.py",
        False,
    ),
    (
        "Ellipsis placeholder path is allow-listed",
        "obsidian-mind/brain/…",
        True,
    ),
    (
        "Mid-path ellipsis placeholder is allow-listed",
        "services/foo/…/bar",
        True,
    ),
]


def _run_divergence_cases(div_smoke) -> list[tuple[str, str]]:
    """Returns list of (label, error) for failing cases."""
    failures = []
    for label, idx, fixture, expected in DIVERGENCE_CASES:
        regex = div_smoke.DIVERGENCES[idx]["regex"]
        actual = len(list(regex.finditer(fixture)))
        if actual != expected:
            failures.append(
                (
                    label,
                    f"expected {expected} match(es), got {actual}",
                )
            )
    return failures


def _run_launcher_cases(launch_smoke) -> list[tuple[str, str]]:
    failures = []
    # Bad-binary patterns (any-of).
    for label, fixture, expected in LAUNCHER_BAD_BINARY_CASES:
        actual = sum(
            len(list(p.finditer(fixture))) for p in launch_smoke.BAD_BINARY_PATTERNS
        )
        if actual != expected:
            failures.append(
                (label, f"expected {expected} bad-binary match(es), got {actual}")
            )
    # Bad-invocation patterns (any-of).
    for label, fixture, expected in LAUNCHER_BAD_INVOCATION_CASES:
        actual = sum(
            len(list(p.finditer(fixture))) for p in launch_smoke.BAD_INVOCATION_PATTERNS
        )
        if actual != expected:
            failures.append(
                (label, f"expected {expected} bad-invocation match(es), got {actual}")
            )
    return failures


def _run_launcher_timeout_cases(launch_smoke) -> list[tuple[str, str]]:
    failures = []
    original = os.environ.get(LAUNCHER_TIMEOUT_ENV)
    platform_default = (
        launch_smoke.WINDOWS_BASH_TIMEOUT_SECONDS
        if launch_smoke.sys.platform == "win32"
        else launch_smoke.DEFAULT_BASH_TIMEOUT_SECONDS
    )
    try:
        for label, raw, expected in LAUNCHER_TIMEOUT_CASES:
            if raw is None:
                os.environ.pop(LAUNCHER_TIMEOUT_ENV, None)
            else:
                os.environ[LAUNCHER_TIMEOUT_ENV] = raw
            if expected == "platform_default":
                expected_value = platform_default
            elif expected == "max":
                expected_value = launch_smoke.MAX_BASH_TIMEOUT_SECONDS
            else:
                expected_value = expected
            actual = launch_smoke._bash_timeout_seconds()
            if actual != expected_value:
                failures.append(
                    (
                        label,
                        f"_bash_timeout_seconds: expected {expected_value}, got {actual}",
                    )
                )
    finally:
        if original is None:
            os.environ.pop(LAUNCHER_TIMEOUT_ENV, None)
        else:
            os.environ[LAUNCHER_TIMEOUT_ENV] = original
    return failures


def _run_smoke_runner_policy_cases(launch_smoke) -> list[tuple[str, str]]:
    failures = []
    runner = (REPO / "scripts/run-all-smokes.ps1").read_text(encoding="utf-8")
    posix_runner = (REPO / "scripts/run-all-smokes.sh").read_text(encoding="utf-8")
    quickstart = (REPO / "QUICKSTART.md").read_text(encoding="utf-8")
    readiness_smoke = (REPO / "scripts/readiness-gate-smoke.py").read_text(
        encoding="utf-8"
    )
    expected_timeout = str(launch_smoke.WINDOWS_BASH_TIMEOUT_SECONDS)
    assignment = f'$env:{LAUNCHER_TIMEOUT_ENV} = "{expected_timeout}"'
    launcher_call = "& $python scripts/launcher-smoke.py"

    guarded_assignment = re.compile(
        rf"if\s*\(\s*-not\s+\$env:{LAUNCHER_TIMEOUT_ENV}\s*\)\s*{{\s*"
        rf"{re.escape(assignment)}\s*}}",
        re.MULTILINE,
    )
    if not guarded_assignment.search(runner):
        failures.append(
            (
                "run-all-smokes.ps1 conditionally sets launcher timeout",
                f"expected guarded {assignment!r} before launcher-smoke",
            )
        )
    if runner.count(assignment) != 1:
        failures.append(
            (
                "run-all-smokes.ps1 preserves caller override",
                f"expected exactly one default assignment, got {runner.count(assignment)}",
            )
        )
    assignment_pos = runner.find(assignment)
    launcher_pos = runner.find(launcher_call)
    if not (0 <= assignment_pos < launcher_pos):
        failures.append(
            (
                "run-all-smokes.ps1 sets timeout before launcher-smoke",
                "expected timeout default to appear before launcher-smoke invocation",
            )
        )
    if LAUNCHER_TIMEOUT_ENV not in quickstart or "Git Bash startup" not in quickstart:
        failures.append(
            (
                "QUICKSTART documents launcher timeout override",
                f"expected {LAUNCHER_TIMEOUT_ENV} and Git Bash startup guidance",
            )
        )
    if not re.search(
        r"readiness-gate-smoke\.py.*Test-CommandAvailable \"uv\"",
        runner,
        re.DOTALL,
    ):
        failures.append(
            (
                "run-all-smokes.ps1 readiness smoke requires uv",
                "expected readiness-gate-smoke prereq to include uv",
            )
        )
    if not re.search(
        r"readiness-gate-smoke\.py.*Test-CommandAvailable \"powershell\".*"
        r"Test-CommandAvailable \"pwsh\"",
        runner,
        re.DOTALL,
    ):
        failures.append(
            (
                "run-all-smokes.ps1 readiness smoke requires PowerShell",
                "expected readiness-gate-smoke prereq to include powershell or pwsh",
            )
        )
    if (
        "command -v uv && (command -v powershell || command -v pwsh)"
        not in posix_runner
    ):
        failures.append(
            (
                "run-all-smokes.sh readiness smoke prereq is explicit",
                "expected POSIX readiness smoke prereq to require uv and PowerShell/pwsh",
            )
        )
    if "uv sync --directory services/agent_mcp --extra dev" not in posix_runner:
        failures.append(
            (
                "run-all-smokes.sh footer uses service uv sync",
                "expected footer to use per-service uv sync command",
            )
        )
    if '"overall": manifest_overall' not in readiness_smoke:
        failures.append(
            (
                "readiness-gate-smoke manifest fixture is not inverted",
                "expected manifest_verify.json fixture to write overall=manifest_overall",
            )
        )
    return failures


def _run_smoke_label_policy_cases() -> list[tuple[str, str]]:
    failures = []
    source_texts = [
        (rel, (REPO / rel).read_text(encoding="utf-8"))
        for rel in SMOKE_LABEL_POLICY_FILES
    ]
    for label, needle in STALE_SMOKE_LABEL_PATTERNS:
        matches = [rel for rel, text in source_texts if needle in text]
        if matches:
            failures.append(
                (
                    label,
                    f"unexpected stale label {needle!r} in {', '.join(matches)}",
                )
            )
    return failures


def _run_path_existence_cases(pes_smoke) -> list[tuple[str, str]]:
    failures = []
    for label, candidate, expected_allowed in PATH_EXISTENCE_ALLOW_CASES:
        actual = pes_smoke._is_allowed(candidate)
        if actual != expected_allowed:
            failures.append(
                (
                    label,
                    f"_is_allowed({candidate!r}): expected {expected_allowed}, got {actual}",
                )
            )
    return failures


def main() -> int:
    print("=" * 60)
    print("Find Evil! - smoke-regex-tests")
    print("=" * 60)

    div_smoke = _load("div_smoke", "scripts/divergence-smoke.py")
    launch_smoke = _load("launch_smoke", "scripts/launcher-smoke.py")
    pes_smoke = _load("pes_smoke", "scripts/path-existence-smoke.py")

    all_failures: list[tuple[str, str, str]] = []

    div_failures = _run_divergence_cases(div_smoke)
    print(
        f"divergence-smoke regexes: {len(DIVERGENCE_CASES) - len(div_failures)}"
        f" / {len(DIVERGENCE_CASES)} passed"
    )
    for label, err in div_failures:
        all_failures.append(("divergence-smoke", label, err))

    launcher_failures = _run_launcher_cases(launch_smoke)
    launcher_timeout_failures = _run_launcher_timeout_cases(launch_smoke)
    runner_policy_failures = _run_smoke_runner_policy_cases(launch_smoke)
    n_launcher = (
        len(LAUNCHER_BAD_BINARY_CASES)
        + len(LAUNCHER_BAD_INVOCATION_CASES)
        + len(LAUNCHER_TIMEOUT_CASES)
        + SMOKE_RUNNER_POLICY_CASE_COUNT
    )
    all_launcher_failures = (
        launcher_failures + launcher_timeout_failures + runner_policy_failures
    )
    print(
        f"launcher-smoke regexes/timeouts/runner policies: "
        f"{n_launcher - len(all_launcher_failures)}"
        f" / {n_launcher} passed"
    )
    for label, err in all_launcher_failures:
        all_failures.append(("launcher-smoke", label, err))

    smoke_label_failures = _run_smoke_label_policy_cases()
    print(
        f"smoke-label policies:    "
        f"{len(STALE_SMOKE_LABEL_PATTERNS) - len(smoke_label_failures)}"
        f" / {len(STALE_SMOKE_LABEL_PATTERNS)} passed"
    )
    for label, err in smoke_label_failures:
        all_failures.append(("smoke-label policies", label, err))

    pes_failures = _run_path_existence_cases(pes_smoke)
    print(
        f"path-existence-smoke allow-list: "
        f"{len(PATH_EXISTENCE_ALLOW_CASES) - len(pes_failures)}"
        f" / {len(PATH_EXISTENCE_ALLOW_CASES)} passed"
    )
    for label, err in pes_failures:
        all_failures.append(("path-existence-smoke", label, err))

    print()
    if all_failures:
        print(f"FAIL - {len(all_failures)} regex test case(s) failed:")
        for smoke, label, err in all_failures:
            print(f"  [{smoke}] {label}: {err}")
        print()
        print("To fix: a regex in the named smoke has drifted.  Read")
        print("the test fixture comment in scripts/smoke-regex-tests.py")
        print("for what the regex is supposed to match (or not match).")
        print("=" * 60)
        return 1

    total = (
        len(DIVERGENCE_CASES)
        + n_launcher
        + len(STALE_SMOKE_LABEL_PATTERNS)
        + len(PATH_EXISTENCE_ALLOW_CASES)
    )
    print("=" * 60)
    print(f"OK - all {total} regex test cases pass.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
