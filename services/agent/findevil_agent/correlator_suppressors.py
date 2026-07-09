"""Counter-evidence false-positive suppressors (deterministic, downgrade/HOLD/NOTE-only).

Focused submodule of :mod:`findevil_agent.correlator`. Where the corroboration
gate family asks "is this claim corroborated?", these suppressors ask the
complementary question — "does a BORING explanation fit?" — and, when one does,
demote or annotate the finding so an analyst is not chasing a known-benign tell.
All three are downgrade-only and evidence-agnostic:

  1. **Known-good-hash whitelist.** A finding whose asserted file hash is on a
     curated known-good list (a built-in set of trivially-benign content hashes
     plus an operator-extensible env hook) describes a legitimate file -> DEMOTE.
  2. **Legitimate-system-path masquerade check.** A core Windows system binary
     observed in its CANONICAL system directory (e.g. ``svchost.exe`` in
     ``\\Windows\\System32``) is the real OS instance, not a masquerade -> DEMOTE.
     If the SAME binary name is seen in a NON-canonical path, that is the actual
     masquerade and the finding is LEFT ALONE (never demoted).
  3. **Process-frequency / baseline NOTE.** A subject process on the standard
     Windows baseline has a high base rate; the finding is annotated (NOTE-only,
     confidence unchanged) so the analyst confirms THIS instance before asserting.

Hard safety rail: the demoting suppressors (1) and (2) NEVER fire on a
non-clearable signature (credential-dumping, log/event-log clearing,
backup/shadow-copy destruction, defense-tool impairment) — those classes are
never benign-cleared, so a System32 path or a coincidental known-good hash must
not soften them. The non-clearable library is reused from
:mod:`findevil_agent.correlator_benign`.

Opt-in via ``FIND_EVIL_REQUIRE_FP_SUPPRESSORS=1`` (default-OFF) so live behavior
is unchanged until rollout. Custody-neutral: no audit-chain / manifest / scoring
edits. Pure logic — no I/O beyond reading env flags; deterministic.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from findevil_agent.correlator_benign import _match_non_clearable
from findevil_agent.events import Finding

# --- (1) Known-good-hash whitelist ----------------------------------------
#
# Built-in curated set: trivially-benign content hashes (an empty / zero-length
# artifact) across MD5 / SHA-1 / SHA-256. These are universal, verifiable
# constants — a finding claiming a running implant whose hash is the empty-file
# hash is self-contradictory. NOT image-specific (evidence-agnostic). Operators
# extend with their own known-good corpus (e.g. an NSRL export) via the env hook
# below; kept to an env var so the module stays I/O-free on the custody path.
_BUILTIN_KNOWN_GOOD: frozenset[str] = frozenset(
    {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # empty SHA-256
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # empty SHA-1
        "d41d8cd98f00b204e9800998ecf8427e",  # empty MD5
    }
)

# Hash shapes: MD5 (32), SHA-1 (40), SHA-256 (64) hex runs.
_HASH_RE = re.compile(r"\b(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\b", re.IGNORECASE)
_HASH_ONLY_RE = re.compile(r"(?:[0-9a-f]{64}|[0-9a-f]{40}|[0-9a-f]{32})\Z", re.IGNORECASE)

# --- (2) Legitimate-system-path map ---------------------------------------
#
# Core Windows system binaries mapped to their canonical directory suffix(es).
# General DFIR knowledge, never image-specific. A path that ends exactly with
# ``<canonical-dir>\<binary>`` is the real OS instance; the same name elsewhere is
# the masquerade tell.
_SYSTEM_BINARIES: dict[str, tuple[str, ...]] = {
    "svchost.exe": (r"\windows\system32",),
    "lsass.exe": (r"\windows\system32",),
    "services.exe": (r"\windows\system32",),
    "winlogon.exe": (r"\windows\system32",),
    "wininit.exe": (r"\windows\system32",),
    "csrss.exe": (r"\windows\system32",),
    "smss.exe": (r"\windows\system32",),
    "spoolsv.exe": (r"\windows\system32",),
    "taskhostw.exe": (r"\windows\system32",),
    "dwm.exe": (r"\windows\system32",),
    "conhost.exe": (r"\windows\system32",),
    "userinit.exe": (r"\windows\system32",),
    "explorer.exe": (r"\windows",),  # Explorer lives in \Windows, not System32
    "rundll32.exe": (r"\windows\system32", r"\windows\syswow64"),
    "regsvr32.exe": (r"\windows\system32", r"\windows\syswow64"),
}

_WIN_PATH_RE = re.compile(r"[a-z]:\\[^\s\"';,]+", re.IGNORECASE)

# --- (3) Process-frequency baseline ---------------------------------------
#
# Ubiquitous Windows processes (high base rate). Restricted to well-formed image
# names so generic prose ("operating system", "registry hive") never trips the
# note. NOTE-only; never changes confidence.
_BASELINE_PROCESSES: frozenset[str] = frozenset(_SYSTEM_BINARIES) | {
    "memcompression",
    "fontdrvhost.exe",
    "searchindexer.exe",
    "runtimebroker.exe",
    "ctfmon.exe",
    "sihost.exe",
    "lsm.exe",
}
_BASELINE_RE = re.compile(
    r"\b(" + "|".join(re.escape(n) for n in sorted(_BASELINE_PROCESSES)) + r")\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class FpSuppressionDecision:
    """Recommended counter-evidence FP action for a finding.

    ``action`` is ``"demote"`` (a boring explanation fits — lower one tier),
    ``"note"`` (high-base-rate annotation, confidence unchanged), or ``"none"``.
    ``suppressor`` names which fired ("known_good_hash" | "system_path_legit" |
    "process_baseline" | None). Downgrade/HOLD/NOTE-only — never raises or clears.
    """

    finding_id: str
    action: str
    suppressor: str | None
    reason: str


def fp_suppressors_active() -> bool:
    """Opt-in, default-OFF (custody-neutral, downgrade/HOLD/NOTE-only)."""
    return os.environ.get("FIND_EVIL_REQUIRE_FP_SUPPRESSORS") == "1"


def _known_good_hashes() -> frozenset[str]:
    extra = os.environ.get("FIND_EVIL_KNOWN_GOOD_HASHES", "")
    parsed = {
        tok.strip().lower()
        for tok in re.split(r"[,\s]+", extra)
        if tok.strip() and _HASH_ONLY_RE.match(tok.strip())
    }
    return _BUILTIN_KNOWN_GOOD | parsed


def _extract_hashes(finding: Finding) -> set[str]:
    blobs = [finding.description]
    for av in getattr(finding, "asserted_values", None) or []:
        blobs.append(str(getattr(av, "expected", "")))
    found: set[str] = set()
    for blob in blobs:
        for m in _HASH_RE.finditer(blob or ""):
            found.add(m.group().lower())
    return found


def _system_path_state(text: str) -> tuple[str | None, str | None]:
    """Return ``("masquerade"|"legit"|None, binary|None)`` for system binaries in text.

    ``"masquerade"`` wins whenever ANY system binary appears in a non-canonical
    path (a suspicious tell that must not be suppressed); ``"legit"`` only when
    every system-binary path seen is canonical.
    """
    paths = [m.group().lower() for m in _WIN_PATH_RE.finditer(text)]
    legit_binary: str | None = None
    for binary, dirs in _SYSTEM_BINARIES.items():
        to_binary = [p for p in paths if p.endswith("\\" + binary)]
        if not to_binary:
            continue
        canonical = [p for p in to_binary if any(p.endswith(d + "\\" + binary) for d in dirs)]
        if len(canonical) != len(to_binary):
            return "masquerade", binary
        if canonical and legit_binary is None:
            legit_binary = binary
    if legit_binary is not None:
        return "legit", legit_binary
    return None, None


def _baseline_process(text: str) -> str | None:
    m = _BASELINE_RE.search(text)
    return m.group(1).lower() if m else None


def evaluate_fp_suppressors(finding: Finding) -> FpSuppressionDecision:
    """Decide the counter-evidence FP action for ``finding`` (deterministic).

    Precedence: known-good hash (demote) > legitimate system path (demote) >
    process baseline (note) > none. The two demoting suppressors are HARD-REFUSED
    on a non-clearable signature so a System32 path or coincidental known-good
    hash can never soften a credential-dump / log-clear / destruction finding.
    """
    fid = finding.finding_id
    text = finding.description.lower()
    non_clearable = _match_non_clearable(text, finding.mitre_technique)
    demote_allowed = non_clearable is None

    if demote_allowed:
        good = _known_good_hashes()
        hit = sorted(h for h in _extract_hashes(finding) if h in good)
        if hit:
            return FpSuppressionDecision(
                fid,
                "demote",
                "known_good_hash",
                f"asserted hash {hit[0]} is on the known-good whitelist (benign file)",
            )

        state, binary = _system_path_state(text)
        if state == "legit":
            return FpSuppressionDecision(
                fid,
                "demote",
                "system_path_legit",
                (
                    f"{binary} observed in its canonical system path — the legitimate "
                    "OS instance, not a masquerade"
                ),
            )

    baseline = _baseline_process(text)
    if baseline is not None:
        return FpSuppressionDecision(
            fid,
            "note",
            "process_baseline",
            (
                f"subject process {baseline} is on the standard Windows baseline "
                "(high base rate); confirm THIS instance is malicious before asserting"
            ),
        )

    return FpSuppressionDecision(fid, "none", None, "no boring explanation fits")
