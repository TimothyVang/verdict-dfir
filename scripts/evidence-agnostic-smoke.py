#!/usr/bin/env python3
"""Evidence-agnostic guard (CLAUDE.md hard rule enforcement).

VERDICT must work for ANY evidence name and type in ``/evidence`` — not just the
image it was last tested on. This smoke fails if production code, docstrings, or
finding descriptions hard-code values keyed to one specific image (the NIST
"Hacking Case" / SCHARDT.dd it was tuned on) or reference golden/benchmark IDs.

Scope: ``scripts/`` and ``services/`` ``.py``/``.rs`` PRODUCTION code. Test files,
``goldens/``, build output, and this script are excluded (benchmark coupling is
allowed there). Detection must key on general DFIR signatures; descriptions must
report what was actually parsed — see CLAUDE.md "Evidence-agnostic (hard rule)".

Run: ``python scripts/evidence-agnostic-smoke.py`` (exit 1 on any violation).
Part of ``scripts/run-all-smokes.sh``.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Image-specific patterns that must never appear in production detection code.
# Each is keyed to the one SCHARDT / NIST Hacking Case image and generalizes
# nothing on any other evidence.
PATTERNS: list[tuple[str, str]] = [
    (r"SCHARDT", "image name (use a generic path / $FINDEVIL_EVIDENCE_ROOT)"),
    (r"[Mm]r\.?\s?[Ee]vil|MR-EVIL", "one image's username/hostname"),
    (r"anonyymizer", "one user's misspelling (use the general 'anonym' root)"),
    (r"\bnhc-\d{2,}\b", "golden/benchmark ID (use general technique language)"),
    (r"NIST Hacking Case", "benchmark name (describe the artifact, not the benchmark)"),
    (r'"4\.12\."', "version/IP fragment from one image (not a DFIR signature)"),
    (
        r'"temp on"|"cd drive"',
        "one image's LECmd drive-label text (gate on drive-type instead)",
    ),
]

# --- Anti-enumeration / anti-fabrication finding policy -------------------
#
# A second, custody-neutral gate: guard a finding DESCRIPTION (given its cited
# evidence text) against three fabrication classes the product safety boundary
# forbids. This is a pre-render policy spec, exercised by the fixtures below so a
# future regex drift fails the gate instead of silently passing.
#
#   (a) anti-enumeration  - a tool-absence claim stated as a finding without an
#       artifact-class / coverage qualifier ("Volatility not found" is a
#       non-finding; "memory artifact class not available" is a coverage note).
#   (b) fabricated CVE     - a CVE identifier in the description that is not
#       traceable to the finding's cited tool output.
#   (c) asserted attribution - actor identity, nation-state, or intent that host
#       artifacts cannot prove (CLAUDE.md: do not assert attribution/intent).
#
# Patterns are general DFIR signatures, never image-specific literals (consistent
# with the evidence-agnostic hard rule above).

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# General tool/scanner-name signatures (not image-specific). Used only to detect
# a tool-absence claim; the bare word "tool" is included on purpose.
_TOOL_NAME = (
    r"volatility|vol_\w+|hayabusa|yara|plaso|log2timeline|sigma|capa|malfind|"
    r"suricata|zeek|nfdump|sleuthkit|autopsy|velociraptor|prefetch|amcache|"
    r"shimcache|antivirus|edr|scanner|tool"
)
# Finding-style absence verbs (a non-finding dressed as a finding). Coverage
# vocabulary ("not available / not parsed / not collected / out of scope") is
# deliberately excluded - that is the safe way to express absence.
_ABSENCE = (
    r"not\s+found|not\s+present|absent|is\s+missing|was\s+not\s+detected|"
    r"were\s+not\s+detected|could\s+not\s+be\s+found|wasn't\s+found"
)
_TOOL_ABSENCE_RE = re.compile(
    rf"(?:{_TOOL_NAME})\b[^.]*?\b(?:{_ABSENCE})\b"
    rf"|\b(?:{_ABSENCE})\b[^.]*?(?:{_TOOL_NAME})\b",
    re.IGNORECASE,
)
# An absence phrase is a legitimate coverage note when scoped to an artifact
# class / coverage rather than to a tool.
_COVERAGE_QUALIFIER_RE = re.compile(
    r"artifact\s+class|artifacts?\b|coverage|evidence\s+class|"
    r"not\s+(?:available|parsed|collected|in\s+scope)|out\s+of\s+scope",
    re.IGNORECASE,
)
# Asserted attribution / actor identity / intent - forbidden from host artifacts.
_ATTRIBUTION_RES = [
    re.compile(r"\bAPT[\s-]?\d{1,3}\b"),
    re.compile(
        r"\b(?:Lazarus|Sandworm|Fancy\s+Bear|Cozy\s+Bear|Equation\s+Group|"
        r"Wizard\s+Spider|Conti|Carbanak|FIN\d{1,2})\b"
    ),
    re.compile(r"attribut(?:ed|ion)\s+to\b", re.IGNORECASE),
    re.compile(r"threat\s+actor\s+(?:is\b|named\b|identified\b|[\"'])", re.IGNORECASE),
    re.compile(r"nation[\s-]?state|state[\s-]?sponsored", re.IGNORECASE),
    re.compile(
        r"the\s+attacker\s+intend|attacker'?s?\s+intent|motivated\s+by|"
        r"in\s+order\s+to\s+(?:steal|exfiltrate|sabotage)",
        re.IGNORECASE,
    ),
]


def anti_fabrication_violations(description: str, cited_text: str = "") -> list[str]:
    """Classify a finding description against the anti-fabrication policy.

    Returns a list of violation labels (empty list == the description is clean).
    ``cited_text`` is the finding's cited tool-output text; a CVE present there is
    traceable and allowed.
    """
    violations: list[str] = []

    # (b) Fabricated/uncited CVE.
    cited_lower = cited_text.lower()
    for cve in _CVE_RE.findall(description):
        if cve.lower() not in cited_lower:
            violations.append(f"uncited CVE {cve}")

    # (a) Tool-absence claim without an artifact-class / coverage qualifier.
    if _TOOL_ABSENCE_RE.search(description) and not _COVERAGE_QUALIFIER_RE.search(
        description
    ):
        violations.append("tool-absence claim stated as a finding")

    # (c) Asserted attribution / actor identity / intent.
    for rx in _ATTRIBUTION_RES:
        if rx.search(description):
            violations.append("asserted attribution/actor/intent")
            break

    return violations


# (label, description, cited_text, expect_violation)
ANTI_FAB_CASES: list[tuple[str, str, str, bool]] = [
    (
        "uncited CVE in description fails",
        "Host exploited CVE-2023-1234 for initial access.",
        "",
        True,
    ),
    (
        "CVE present in cited tool output passes",
        "Host exploited CVE-2021-34527 for initial access.",
        "yara match: rule references CVE-2021-34527 spoolsv",
        False,
    ),
    (
        "asserted actor name fails",
        "The intrusion is attributed to the Lazarus Group operators.",
        "",
        True,
    ),
    (
        "asserted APT number fails",
        "Activity consistent with APT29 tradecraft.",
        "",
        True,
    ),
    (
        "categorized coverage note passes",
        "The memory artifact class was not available in this case's coverage.",
        "",
        False,
    ),
    (
        "tool-absence stated as finding fails",
        "Volatility was not found, so the host has no injected processes.",
        "",
        True,
    ),
    (
        "coverage-qualified tool absence passes",
        "The YARA artifact class was not found in this case's coverage.",
        "",
        False,
    ),
    (
        "clean finding passes",
        "EVTX 4625 events precede a 4624 logon from the same source IP.",
        "evtx_query returned EventID 4625 then EventID 4624",
        False,
    ),
]


def _run_anti_fab_self_test() -> list[str]:
    """Run ANTI_FAB_CASES; return a list of failure messages (empty == pass)."""
    failures: list[str] = []
    for label, desc, cited, expect in ANTI_FAB_CASES:
        got = bool(anti_fabrication_violations(desc, cited))
        if got != expect:
            failures.append(
                f"  {label}: expected violation={expect}, got {got}"
                f" ({anti_fabrication_violations(desc, cited)})"
            )
    return failures


INCLUDE_DIRS = ("scripts", "services")
EXCLUDE_DIR_PARTS = {
    "tests",
    "test",
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    "goldens",
    "migrations",
}
EXCLUDE_FILES = {"evidence-agnostic-smoke.py"}
EXTS = {".py", ".rs"}


def _eligible(path: Path) -> bool:
    if path.suffix not in EXTS or path.name in EXCLUDE_FILES:
        return False
    parts = {p.lower() for p in path.relative_to(REPO).parts}
    if parts & EXCLUDE_DIR_PARTS:
        return False
    # A *_test.rs / test_*.py file outside a tests/ dir is still test code.
    name = path.name.lower()
    return not (
        name.startswith("test_")
        or name.endswith("_test.py")
        or name.endswith("_test.rs")
    )


def main() -> int:
    compiled = [(re.compile(p), why) for p, why in PATTERNS]
    violations: list[str] = []
    scanned = 0
    for inc in INCLUDE_DIRS:
        for path in sorted((REPO / inc).rglob("*")):
            if not path.is_file() or not _eligible(path):
                continue
            scanned += 1
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for lineno, line in enumerate(lines, 1):
                for rx, why in compiled:
                    if rx.search(line):
                        rel = path.relative_to(REPO)
                        violations.append(
                            f"  {rel}:{lineno}: {why}\n      {line.strip()[:120]}"
                        )

    failed = False

    print("=== evidence-agnostic smoke ===")
    print(
        f"  scanned {scanned} production .py/.rs files under {', '.join(INCLUDE_DIRS)}/"
    )
    if violations:
        print(
            f"  FAIL: {len(violations)} image-specific literal(s) in production code:\n"
        )
        print("\n".join(violations))
        print(
            "\n  Fix: key detection on general DFIR signatures, describe what was actually\n"
            "  parsed, and keep golden/benchmark coupling under goldens/ and tests only.\n"
            "  See CLAUDE.md 'Evidence-agnostic (hard rule)'."
        )
        failed = True
    else:
        print("  PASS: no image-specific hard-coding in production code.")

    print("=== anti-enumeration / anti-fabrication finding policy ===")
    af_failures = _run_anti_fab_self_test()
    if af_failures:
        print(
            f"  FAIL: {len(af_failures)} anti-fabrication policy case(s) misclassified:\n"
        )
        print("\n".join(af_failures))
        print(
            "\n  Fix: a pattern in anti_fabrication_violations() has drifted. The policy\n"
            "  rejects uncited CVEs, tool-absence claims, and asserted attribution/intent."
        )
        failed = True
    else:
        print(
            f"  PASS: {len(ANTI_FAB_CASES)} anti-fabrication policy cases classify correctly"
        )

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
