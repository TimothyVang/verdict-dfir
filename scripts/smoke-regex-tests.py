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
import tempfile
import textwrap
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
        "13 typed Rust active drift",
        2,
        "wraps 13 typed Rust MCP tools",
        1,
    ),
    (
        "20-tool label active drift",
        2,
        "rust-mcp-smoke (20-tool dispatch + error paths)",
        1,
    ),
    (
        "20/20 shipped active drift",
        2,
        "Tool surface (20/20 shipped)",
        1,
    ),
    (
        "31 typed Rust is correct",
        2,
        "wraps 31 typed Rust MCP tools",
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

SMOKE_RUNNER_POLICY_CASE_COUNT = 15

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

STALE_RELEASE_DOC_PATTERNS = [
    (
        "SRL fixed 28-target heading",
        "SRL-2018 (28 targets)",
    ),
    (
        "SRL fixed 28-target completion claim",
        "Every one of the 28 targets",
    ),
    (
        "SRL fixed 28/28 manifest claim",
        "manifest_ok:    28 / 28",
    ),
    (
        "release-only remote flow",
        "push to the `release` remote and open a PR in `TimothyVang/verdict-dfir`; do not use `origin`",
    ),
    (
        "sans-hackathon marked superseded for release operations",
        "`TimothyVang/dev-verdict-github` remote is superseded for release operations",
    ),
    (
        "branch protection individual l0 workflow context",
        "required_status_checks[contexts][]=l0-static / workflow-lint",
    ),
    (
        "ci checklist individual required context list",
        "returns the full list: `l0-static / workflow-lint`",
    ),
]

RELEASE_DOC_POLICY_FILES = [
    ".github/CODEOWNERS",
    "CHANGELOG.md",
    "docs/runbooks/ci-smoke-checklist.md",
    "docs/runbooks/github-remote-bootstrap.md",
    "docs/using/whole-case-local-run.md",
    "scripts/setup-branch-protection.sh",
]

RELEASE_POLICY_REQUIRED_STRINGS = [
    (
        "branch protection requires code owner reviews",
        "scripts/setup-branch-protection.sh",
        "required_pull_request_reviews[require_code_owner_reviews]=true",
    ),
    (
        "CODEOWNERS protects workflow changes",
        ".github/CODEOWNERS",
        ".github/workflows/** @TimothyVang",
    ),
    (
        "CODEOWNERS protects L1 compose gates",
        ".github/CODEOWNERS",
        "docker/l1-compose.yml @TimothyVang",
    ),
    (
        "CODEOWNERS protects L1 Dockerfile gate",
        ".github/CODEOWNERS",
        "docker/*.Dockerfile @TimothyVang",
    ),
    (
        "CODEOWNERS protects smoke policy checks",
        ".github/CODEOWNERS",
        "scripts/*smoke*.py @TimothyVang",
    ),
    (
        "CODEOWNERS protects readiness gate implementation",
        ".github/CODEOWNERS",
        "scripts/readiness-gate.ps1 @TimothyVang",
    ),
    (
        "CODEOWNERS protects CODEOWNERS policy",
        ".github/CODEOWNERS",
        ".github/CODEOWNERS @TimothyVang",
    ),
    (
        "CODEOWNERS protects L3 evidence validator",
        ".github/CODEOWNERS",
        "scripts/validate-l3-evidence.py @TimothyVang",
    ),
    (
        "CODEOWNERS protects L3 golden runner",
        ".github/CODEOWNERS",
        "scripts/l3-run-goldens.sh @TimothyVang",
    ),
    (
        "CODEOWNERS protects submission validator",
        ".github/CODEOWNERS",
        "scripts/validate-submission-assets.py @TimothyVang",
    ),
    (
        "CODEOWNERS protects benchmark conversion",
        ".github/CODEOWNERS",
        "scripts/json-to-benchmark-csv.py @TimothyVang",
    ),
    (
        "CODEOWNERS protects tool count guard",
        ".github/CODEOWNERS",
        "scripts/tool-count-guard.py @TimothyVang",
    ),
    (
        "CODEOWNERS protects release evidence docs",
        ".github/CODEOWNERS",
        "docs/release-evidence/** @TimothyVang",
    ),
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
    (
        "Gitignored n8n-references clone is allow-listed",
        "n8n-references/n8n/LICENSE.md",
        True,
    ),
    (
        "Docker runner host output dir ./out/ is allow-listed",
        "./out/",
        True,
    ),
    (
        "Docker runner host output dir ./out is allow-listed",
        "./out",
        True,
    ),
    (
        "Reduced-source docs/plans/ is allow-listed",
        "docs/plans/",
        True,
    ),
    (
        "Lookalike ./output IS still checked (not allow-listed)",
        "./output/foo",
        False,
    ),
]

READINESS_PACKET_REQUIRED_DOC_STRINGS = [
    "manifest_verify.json",
    "verdict.json",
    "expert_signoff.json",
    "customer_release_gate.final.json",
    "REPORT.html",
    "REPORT.pdf",
    "readiness-summary.json",
    "packet/readiness-packet-manifest.json",
]

READINESS_PACKET_FORBIDDEN_DOC_STRINGS = [
    "findings.json           ",
    "report.md               ",
    "└── readiness-packet-manifest.json",
]

ARCHITECTURE_REQUIRED_FLOW_STRINGS = [
    "Contradiction --> Verifier",
    "Verifier --> Judge",
    "Judge --> Correlator",
]

ARCHITECTURE_FORBIDDEN_FLOW_STRINGS = [
    "Contradiction --> Judge",
    "Judge --> Verifier",
]

GLOSSARY_FORBIDDEN_STRINGS = [
    "**`tool_call_id`** | A SHA-256 over a tool's raw output.",
]

GLOSSARY_REQUIRED_STRINGS = [
    "**`tool_call_id`** | Opaque current-case tool execution identifier",
    "**`output_hash` / `_meta.output_sha256`** | SHA-256 digest of the tool's raw output",
]

SAMPLE_RUN_DOC_FORBIDDEN_STRINGS = [
    "All six runs return `overall: true`",
    "The heavy render artifacts (`REPORT.pdf`, `REPORT.html`, `figures/`, `timeline.*`) are omitted",
    "their\n> `audit.jsonl`, `run.manifest.json`, `verdict.json`, `manifest_verify.json`, and `REPORT.md`",
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
    l1_compose = (REPO / "docker/l1-compose.yml").read_text(encoding="utf-8")
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
    readiness_uv_command = (
        "uv run --directory services/agent python ../../scripts/readiness-gate-smoke.py"
    )
    if readiness_uv_command not in runner:
        failures.append(
            (
                "run-all-smokes.ps1 readiness smoke uses service uv",
                "expected readiness smoke to run under services/agent Python 3.11",
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
    if readiness_uv_command not in posix_runner:
        failures.append(
            (
                "run-all-smokes.sh readiness smoke uses service uv",
                "expected readiness smoke to run under services/agent Python 3.11",
            )
        )
    if "scripts/find-evil-run-smoke.py" in runner:
        failures.append(
            (
                "run-all-smokes.ps1 does not call retired smoke",
                "expected Windows runner to use verdict-smoke.py, not find-evil-run-smoke.py",
            )
        )
    if not re.search(
        r"if\s+\[\s+-f\s+scripts/demo-script-smoke\.py\s+\]\s+&&\s+"
        r"\[\s+-f\s+docs/demo-script-a2\.md\s+\];\s+then",
        l1_compose,
    ):
        failures.append(
            (
                "docker l1 demo-script smoke requires demo script",
                "expected L1 Docker to skip demo-script-smoke when docs/demo-script-a2.md is absent",
            )
        )
    windows_expected_smokes = [
        "scripts/verdict-smoke.py",
        "scripts/trace-finding-smoke.py",
        "scripts/install-bootstrap-smoke.py",
        "scripts/grounding-smoke.py",
    ]
    for smoke_path in windows_expected_smokes:
        if smoke_path not in runner:
            failures.append(
                (
                    f"run-all-smokes.ps1 includes {smoke_path}",
                    "expected Windows runner to mirror the POSIX CI-predictor smoke surface",
                )
            )
    referenced_scripts = set(re.findall(r"scripts/[A-Za-z0-9_-]+\.py", runner))
    missing_scripts = sorted(
        rel for rel in referenced_scripts if not (REPO / rel).is_file()
    )
    if missing_scripts:
        failures.append(
            (
                "run-all-smokes.ps1 references existing smoke scripts",
                f"missing script reference(s): {', '.join(missing_scripts)}",
            )
        )
    if "uv sync --directory services/agent --extra dev" not in posix_runner:
        failures.append(
            (
                "run-all-smokes.sh footer uses agent service uv sync",
                "expected footer to mention services/agent uv sync command",
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


def _run_release_doc_policy_cases() -> list[tuple[str, str]]:
    failures = []
    source_texts = [
        (rel, (REPO / rel).read_text(encoding="utf-8"))
        for rel in RELEASE_DOC_POLICY_FILES
    ]
    for label, needle in STALE_RELEASE_DOC_PATTERNS:
        matches = [rel for rel, text in source_texts if needle in text]
        if matches:
            failures.append(
                (
                    label,
                    f"unexpected stale release-doc claim {needle!r} in {', '.join(matches)}",
                )
            )
    for label, rel, needle in RELEASE_POLICY_REQUIRED_STRINGS:
        text = (REPO / rel).read_text(encoding="utf-8")
        if needle not in text:
            failures.append(
                (
                    label,
                    f"expected release policy string {needle!r} in {rel}",
                )
            )
    return failures


def _run_path_existence_cases(pes_smoke) -> list[tuple[str, str]]:
    failures = []
    for label, candidate, expected_allowed in PATH_EXISTENCE_ALLOW_CASES:
        actual = pes_smoke._is_allowed(candidate, "docs/README.md")
        if actual != expected_allowed:
            failures.append(
                (
                    label,
                    f"_is_allowed({candidate!r}): expected {expected_allowed}, got {actual}",
                )
            )
    return failures


def _run_readiness_packet_doc_cases() -> list[tuple[str, str]]:
    failures = []
    runbook = (REPO / "docs/runbooks/readiness-packet-windows.md").read_text(
        encoding="utf-8"
    )
    for needle in READINESS_PACKET_REQUIRED_DOC_STRINGS:
        if needle not in runbook:
            failures.append(
                (
                    f"readiness packet docs include {needle}",
                    "expected Windows runbook to mirror readiness-gate.ps1 packet schema",
                )
            )
    for needle in READINESS_PACKET_FORBIDDEN_DOC_STRINGS:
        if needle in runbook:
            failures.append(
                (
                    f"readiness packet docs omit stale {needle.strip()}",
                    "expected Windows runbook not to list stale packet paths",
                )
            )
    return failures


def _run_architecture_flow_policy_cases() -> list[tuple[str, str]]:
    failures = []
    architecture = (REPO / "docs/architecture.md").read_text(encoding="utf-8")
    for needle in ARCHITECTURE_REQUIRED_FLOW_STRINGS:
        if needle not in architecture:
            failures.append(
                (
                    f"architecture diagram includes {needle}",
                    "expected verifier to run before judge in the public trust-boundary diagram",
                )
            )
    for needle in ARCHITECTURE_FORBIDDEN_FLOW_STRINGS:
        if needle in architecture:
            failures.append(
                (
                    f"architecture diagram omits stale {needle}",
                    "expected diagram not to place judge before verifier",
                )
            )
    return failures


def _run_sample_run_doc_cases() -> list[tuple[str, str]]:
    failures = []
    sample_readme_path = REPO / "docs/sample-run/README.md"
    compliance_path = REPO / "SUBMISSION_COMPLIANCE.md"
    if not sample_readme_path.exists() and not compliance_path.exists():
        release_surface = (REPO / "docs/release-surface.md").read_text(encoding="utf-8")
        for needle in ("`docs/sample-run/`", "`docs/reports/`"):
            if needle not in release_surface:
                failures.append(
                    (
                        f"release surface documents omitted {needle}",
                        "expected reduced source layout to explain generated artifact omissions",
                    )
                )
        return failures

    sample_readme = (
        sample_readme_path.read_text(encoding="utf-8")
        if sample_readme_path.exists()
        else ""
    )
    compliance = (
        compliance_path.read_text(encoding="utf-8") if compliance_path.exists() else ""
    )
    combined = f"{sample_readme}\n{compliance}"
    for needle in SAMPLE_RUN_DOC_FORBIDDEN_STRINGS:
        if needle in combined:
            failures.append(
                (
                    f"sample-run docs omit stale phrase {needle[:48]!r}",
                    "expected sample-run inventory and report-presence wording to match committed artifacts",
                )
            )
    if "All seven runs return `overall: true`" not in sample_readme:
        failures.append(
            (
                "sample-run README uses seven-run verification count",
                "expected all-seven wording for committed individual runs",
            )
        )
    # SUBMISSION_COMPLIANCE.md (a Devpost-submission artifact) was removed from the
    # public release; the REPORT.md-presence qualification now lives in the committed
    # sample-run README. Assert it across the combined sample-run docs (case-folded,
    # since the phrase opens a sentence: "Partial runs can omit it by policy.").
    if (
        "`REPORT.md`" not in combined
        or "partial runs can omit it by policy" not in combined.lower()
    ):
        failures.append(
            (
                "sample-run docs qualify REPORT.md presence",
                "expected committed sample-run layout to avoid claiming every run has REPORT.md",
            )
        )
    return failures


def _run_glossary_tool_call_id_policy_cases() -> list[tuple[str, str]]:
    failures = []
    glossary = (REPO / "docs/glossary.md").read_text(encoding="utf-8")
    for needle in GLOSSARY_FORBIDDEN_STRINGS:
        if needle in glossary:
            failures.append(
                (
                    "glossary does not define tool_call_id as content hash",
                    f"unexpected stale glossary definition {needle!r}",
                )
            )
    for needle in GLOSSARY_REQUIRED_STRINGS:
        if needle not in glossary:
            failures.append(
                (
                    f"glossary includes {needle.split('|', 1)[0].strip()}",
                    "expected separate opaque id and output hash definitions",
                )
            )
    return failures


def _run_tool_count_guard_cases(tool_count_guard) -> list[tuple[str, str]]:
    failures = []
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        (root / "services/mcp/src").mkdir(parents=True)
        (root / "services/agent_mcp/findevil_agent_mcp/tools").mkdir(parents=True)
        (root / "docs").mkdir()
        (root / "scripts/make-demo-video/src/components").mkdir(parents=True)

        (root / "services/mcp/src/server.rs").write_text(
            textwrap.dedent(
                """
                fn build_registry() -> Vec<ToolEntry> {
                    vec![
                        ToolEntry { name: "case_open", handler: |args| dispatch_case_open(args) },
                        ToolEntry { name: "evtx_query", handler: |args| dispatch_evtx_query(args) },
                    ]
                }
                """
            ),
            encoding="utf-8",
        )
        (root / "services/agent_mcp/findevil_agent_mcp/tools/__init__.py").write_text(
            textwrap.dedent(
                """
                _MODULES: tuple[str, ...] = (
                    "audit_append",
                )
                """
            ),
            encoding="utf-8",
        )
        good_docs = {
            "CLAUDE.md": "3 product tools: 2 Rust tools + 1 Python tool.\n",
            "README.md": "3 product tools: 2 Rust DFIR + 1 Python.\n",
            "INSTALL.md": "3 product tools: findevil-mcp has 2 DFIR tools; findevil-agent-mcp has 1 Python tool.\n",
            "docs/architecture.md": "Tool count: 3 (2 Rust DFIR + 1 Python).\n",
            "docs/reference/mcp-and-tools.md": "3 product tools: 2 Rust tools + 1 Python tool.\n",
            "scripts/make-demo-video/src/components/ArchPoster.tsx": "const total = 3; const rust = 2; const python = 1;\n",
        }
        for rel, text in good_docs.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

        errors = tool_count_guard.validate_counts(
            root,
            expected_rust=2,
            expected_python=1,
        )
        if errors:
            failures.append(
                (
                    "tool-count guard accepts matching code and docs",
                    "; ".join(errors),
                )
            )

        (root / "README.md").write_text(
            "4 product tools: 2 Rust DFIR + 2 Python.\n",
            encoding="utf-8",
        )
        errors = tool_count_guard.validate_counts(
            root,
            expected_rust=2,
            expected_python=1,
        )
        if not any("README.md" in error for error in errors):
            failures.append(
                (
                    "tool-count guard rejects stale README count",
                    f"expected README.md mismatch, got {errors!r}",
                )
            )
        (root / "README.md").write_text(
            "3 product tools: 2 Rust tools + 1 Python tool. Stale: 4 product tools.\n",
            encoding="utf-8",
        )
        errors = tool_count_guard.validate_counts(
            root,
            expected_rust=2,
            expected_python=1,
        )
        if not any("product total claim 4" in error for error in errors):
            failures.append(
                (
                    "tool-count guard rejects conflicting README count",
                    f"expected conflicting README.md count, got {errors!r}",
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
    tool_count_guard = _load("tool_count_guard", "scripts/tool-count-guard.py")

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

    release_doc_failures = _run_release_doc_policy_cases()
    print(
        f"release-doc policies:    "
        f"{len(STALE_RELEASE_DOC_PATTERNS) + len(RELEASE_POLICY_REQUIRED_STRINGS) - len(release_doc_failures)}"
        f" / {len(STALE_RELEASE_DOC_PATTERNS) + len(RELEASE_POLICY_REQUIRED_STRINGS)} passed"
    )
    for label, err in release_doc_failures:
        all_failures.append(("release-doc policies", label, err))

    pes_failures = _run_path_existence_cases(pes_smoke)
    print(
        f"path-existence-smoke allow-list: "
        f"{len(PATH_EXISTENCE_ALLOW_CASES) - len(pes_failures)}"
        f" / {len(PATH_EXISTENCE_ALLOW_CASES)} passed"
    )
    for label, err in pes_failures:
        all_failures.append(("path-existence-smoke", label, err))

    readiness_doc_failures = _run_readiness_packet_doc_cases()
    readiness_total = len(READINESS_PACKET_REQUIRED_DOC_STRINGS) + len(
        READINESS_PACKET_FORBIDDEN_DOC_STRINGS
    )
    print(
        f"readiness-packet docs:       "
        f"{readiness_total - len(readiness_doc_failures)} / {readiness_total} passed"
    )
    for label, err in readiness_doc_failures:
        all_failures.append(("readiness-packet docs", label, err))

    architecture_flow_failures = _run_architecture_flow_policy_cases()
    architecture_flow_total = len(ARCHITECTURE_REQUIRED_FLOW_STRINGS) + len(
        ARCHITECTURE_FORBIDDEN_FLOW_STRINGS
    )
    print(
        f"architecture verifier/judge flow: "
        f"{architecture_flow_total - len(architecture_flow_failures)}"
        f" / {architecture_flow_total} passed"
    )
    for label, err in architecture_flow_failures:
        all_failures.append(("architecture verifier/judge flow", label, err))

    glossary_failures = _run_glossary_tool_call_id_policy_cases()
    glossary_total = len(GLOSSARY_FORBIDDEN_STRINGS) + len(GLOSSARY_REQUIRED_STRINGS)
    print(
        f"glossary tool_call_id policy: "
        f"{glossary_total - len(glossary_failures)} / {glossary_total} passed"
    )
    for label, err in glossary_failures:
        all_failures.append(("glossary tool_call_id policy", label, err))

    sample_doc_failures = _run_sample_run_doc_cases()
    sample_total = len(SAMPLE_RUN_DOC_FORBIDDEN_STRINGS) + 2
    print(
        f"sample-run doc policies:     "
        f"{sample_total - len(sample_doc_failures)} / {sample_total} passed"
    )
    for label, err in sample_doc_failures:
        all_failures.append(("sample-run doc policies", label, err))

    tool_count_failures = _run_tool_count_guard_cases(tool_count_guard)
    tool_count_total = 3
    print(
        f"tool-count guard policies:   "
        f"{tool_count_total - len(tool_count_failures)} / {tool_count_total} passed"
    )
    for label, err in tool_count_failures:
        all_failures.append(("tool-count guard", label, err))

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
        + len(STALE_RELEASE_DOC_PATTERNS)
        + len(RELEASE_POLICY_REQUIRED_STRINGS)
        + len(PATH_EXISTENCE_ALLOW_CASES)
        + readiness_total
        + architecture_flow_total
        + glossary_total
        + sample_total
        + tool_count_total
    )
    print("=" * 60)
    print(f"OK - all {total} regex test cases pass.")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
