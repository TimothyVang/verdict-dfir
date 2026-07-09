"""Curated benign-exoneration library (deterministic, HOLD-only).

Focused submodule of :mod:`findevil_agent.correlator`. The benign-explanation
gate in the facade guards the INCRIMINATION direction (a confident execution
claim that recorded NO benign alternative is the "too clean" tell, downgraded).
This library guards the EXONERATION direction: when a finding's
counter_hypothesis is used to benign-CLEAR it, the clearance must be
evidence-bound and curated. It can only HOLD (refuse to soften / clear); it
never raises confidence and never auto-clears — consistent with SOUL.md
"presumption of benignity until the evidence defeats it" applied in reverse:
a malicious finding is not exonerated on a hand-wave.

Four curated constraints (all general DFIR signatures, evidence-agnostic):
  (1) NON-CLEARABLE signatures — credential-dumping, log/event-log clearing,
      backup/shadow-copy destruction, and defense-tool impairment may NEVER be
      benign-cleared, regardless of any counter_hypothesis text.
  (2) VERBATIM-EVIDENCE requirement — a benign clearance must quote specific
      evidence text (a path, hash, timestamp, event ID, registry key, quoted
      excerpt, or tool-call ref), not a bare assertion.
  (3)/(4) LEGITIMATE-TOOL / VENDOR demotion — a "it's a signed/legitimate
      tool" demotion of a maliciously-used dual-use tool (LOLBin) stays a HOLD,
      not a clear (legit-tool-mimic).

Pure logic — no LLM calls, no I/O. Deterministic given the same inputs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from findevil_agent.events import Finding

# (name, text-signature, mitre-prefixes) — signatures that may never be benign
# cleared. Curated general DFIR patterns, never image-specific literals.
_NON_CLEARABLE: tuple[tuple[str, re.Pattern[str], tuple[str, ...]], ...] = (
    (
        "credential-dumping",
        re.compile(
            r"\b(?:lsass\s?(?:dump|\.dmp)|dump\w*\s+lsass|mimikatz|sekurlsa|"
            r"secretsdump|ntds\.dit|dcsync|comsvcs\s?\.?\s?dll\s?,?\s?minidump|"
            r"procdump\w*\s+\S*lsass|sam\s?hive\s+(?:dump|extract\w*)|"
            r"credential\s?dump\w*)\b",
            re.IGNORECASE,
        ),
        ("T1003",),
    ),
    (
        "event-log-clearing",
        re.compile(
            r"\b(?:1102|wevtutil\s+cl\b|clear-?eventlog|"
            r"(?:event|security|audit)\s?log\w*\s+(?:was\s+)?clear\w*|"
            r"clear\w*\s+(?:the\s+)?(?:event|security|audit)\s?log)\b",
            re.IGNORECASE,
        ),
        ("T1070.001",),
    ),
    (
        "backup-inhibition",
        re.compile(
            r"\b(?:vssadmin\s+delete\s+shadows?|wbadmin\s+delete|"
            r"shadow\s?cop\w*\s+delet\w*|delet\w*\s+shadow\s?cop\w*|"
            r"bcdedit\w*\s+\S*recoveryenabled\s+no)\b",
            re.IGNORECASE,
        ),
        ("T1490",),
    ),
    (
        "defense-impairment",
        re.compile(
            r"\b(?:disab\w*\s+(?:windows\s+)?(?:defender|antivirus|\bav\b)|"
            r"(?:defender|antivirus)\s+disab\w*|set-mppreference\s+\S*-disable|"
            r"stop\w*\s+windefend|tamper\s?protection\s+disab\w*)\b",
            re.IGNORECASE,
        ),
        ("T1562",),
    ),
)

# Dual-use / living-off-the-land (LOLBin) and admin-tool names. Naming one of
# these as the benign explanation for a maliciously-used tool is a
# legit-tool-mimic clearance -> HOLD. Curated general signatures.
_LEGIT_TOOL_RE = re.compile(
    r"\b(?:psexec\w*|psexesvc|wmic|wmiexec|powershell|pwsh|certutil|bitsadmin|"
    r"rundll32|regsvr32|mshta|cscript|wscript|schtasks|sc\.exe|reg\.exe|"
    r"net1?\.exe|at\.exe|wevtutil|msbuild|installutil|regasm|regsvcs|mavinject|"
    r"esentutl|forfiles|sysinternals)\b",
    re.IGNORECASE,
)

# "It's signed / legitimate / a trusted vendor" demotion language. Used to clear
# a finding by appeal to provenance rather than evidence -> HOLD.
_VENDOR_DEMOTION_RE = re.compile(
    r"\b(?:digitally\s+signed|code[\s-]?signed|signed\s+(?:binary|tool|driver|"
    r"executable|by)|trusted\s+publisher|authenticode|valid\s+signature|"
    r"legitimate(?:ly)?|legit|known[\s-]?good|whitelist\w*|allow[\s-]?list\w*|"
    r"vendor[\s-]?signed|microsoft[\s-]?signed|official\s+(?:vendor|tool|build))\b",
    re.IGNORECASE,
)

# Verbatim-evidence tokens: a benign clearance must cite at least one of these
# concrete references, not a bare assertion. General forensic citation shapes,
# evidence-agnostic.
_VERBATIM_EVIDENCE_RE = re.compile(
    r"\"[^\"]+\""  # double-quoted excerpt
    r"|'[^']+'"  # single-quoted excerpt
    r"|[A-Za-z]:\\[^\s]+"  # windows path (drive-letter)
    r"|(?:/[^\s/]+){2,}"  # unix path (>=2 segments)
    r"|\b[0-9a-f]{12,}\b"  # hash-like hex run
    r"|\b\d{4}-\d{2}-\d{2}(?:t[\d:]+z?)?"  # iso date / timestamp
    r"|\b(?:eid|event\s?id)\s*\d+\b"  # event id reference
    r"|\b(?:4\d{3}|1102|7045)\b"  # specific event ids
    r"|\bhk(?:lm|cu|cr|u)\b|\\run\b"  # registry hive / run key
    r"|\btc-[0-9a-z]"  # tool_call id ref
    r"|tool[_\s]?call",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class BenignClearanceDecision:
    """Whether a benign clearance (exoneration) of a finding is admissible.

    ``state`` is one of ``"admissible"``, ``"no_clearance"`` (no
    counter_hypothesis to evaluate), ``"hold_non_clearable"``,
    ``"hold_legit_tool_mimic"``, or ``"hold_no_verbatim_evidence"``. ``signature``
    names the matched non-clearable class when applicable. The decision NEVER
    clears or raises a finding — an inadmissible clearance is a HOLD (keep the
    malicious reading), never a downgrade-to-benign.
    """

    finding_id: str
    admissible: bool
    state: str
    reason: str
    signature: str | None = None

    @property
    def benign_hold(self) -> bool:
        """True when a benign clearance was actively REFUSED (a HOLD)."""
        return self.state.startswith("hold_")


def _match_non_clearable(text: str, mitre: str | None) -> str | None:
    """Name of the non-clearable signature this finding matches, else None."""
    for name, rx, prefixes in _NON_CLEARABLE:
        if rx.search(text):
            return name
        if mitre and prefixes and mitre.startswith(prefixes):
            return name
    return None


def evaluate_benign_clearance(finding: Finding) -> BenignClearanceDecision:
    """Decide whether a benign clearance of ``finding`` is admissible.

    Deterministic and HOLD-only: it never clears, softens, or raises a finding —
    it only reports whether a benign clearance MAY apply, refusing
    (``hold_*``) credential-dump / log-clear / destruction signatures, bare
    assertions, and legit-tool / vendor-signed demotions.
    """
    text = finding.description.lower()
    clearance = (finding.counter_hypothesis or "").strip()

    # (1) Non-clearable signatures win regardless of any clearance text.
    sig = _match_non_clearable(text, finding.mitre_technique)
    if sig is not None:
        return BenignClearanceDecision(
            finding_id=finding.finding_id,
            admissible=False,
            state="hold_non_clearable",
            reason=(
                f"{sig} is a non-clearable signature; a benign clearance is refused "
                "(HOLD) — this class may never be benign-cleared"
            ),
            signature=sig,
        )

    # No clearance asserted — nothing to admit or refuse.
    if not clearance:
        return BenignClearanceDecision(
            finding_id=finding.finding_id,
            admissible=False,
            state="no_clearance",
            reason="no benign clearance asserted",
        )

    # (3)/(4) Legit-tool-mimic / vendor-signed demotion.
    if _LEGIT_TOOL_RE.search(clearance) or _VENDOR_DEMOTION_RE.search(clearance):
        return BenignClearanceDecision(
            finding_id=finding.finding_id,
            admissible=False,
            state="hold_legit_tool_mimic",
            reason=(
                "benign clearance rests on a legitimate-tool / vendor-signed demotion; "
                "a signed legit tool used maliciously stays a HOLD, not a clear"
            ),
        )

    # (2) Verbatim-evidence requirement.
    if not _VERBATIM_EVIDENCE_RE.search(clearance):
        return BenignClearanceDecision(
            finding_id=finding.finding_id,
            admissible=False,
            state="hold_no_verbatim_evidence",
            reason=(
                "benign clearance cites no verbatim evidence (bare assertion); a "
                "clearance must quote specific evidence text"
            ),
        )

    return BenignClearanceDecision(
        finding_id=finding.finding_id,
        admissible=True,
        state="admissible",
        reason="benign clearance is evidence-bound and not a legit-tool / vendor mimic",
    )
