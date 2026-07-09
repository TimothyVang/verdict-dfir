#!/usr/bin/env python3
"""report-escalation-linter - deterministic restricted-conclusions report linter.

A customer-facing report (and the verdict.json it renders from) must not smuggle
an unbacked escalation *conclusion* past the confidence taxonomy. The QA gate in
`find_evil_auto.build_report_qa_signoff` already blocks the *exoneration*
direction (`no_forbidden_unqualified_language`: "host is clean", "evidence is
absent") and gates execution/exfiltration *wording* on per-finding corroboration.
This linter is the mirror image on the *overclaim* side: a compiled list of
banned escalation terms (e.g. "compromised", "pass-the-hash", "exfiltration
confirmed", "attacker", "proves", "definitely", "clearly") may only appear in a
Finding or narrative block when that record is backed by >=2 distinct artifact
classes, and even then it should carry a hedge verb ("consistent with",
"suggests", "cannot exclude").

Beyond that banned-vocabulary gate, this linter carries a deterministic,
clause-local **tool-semantics over-read** table. It flags a clause where the
*cited* artifact cannot support the claim verb (ShimCache/AppCompatCache or
Amcache cited as execution, netscan/ARP cited as file movement, a private
RFC1918 address cited as an external C2 endpoint, $MFT-only cited as user
access), plus PID/row-count claims absent from the cited tool output. Each rule
keys on a general DFIR signature (artifact name + claim verb), never an
image-specific literal, and is a non-failing **warning** (it never flips the
verdict). A clause that names a corroborating stronger artifact for the verb
(Prefetch/4688 for execution, USN-journal/$MFT for movement, LNK/Shellbags for
access) or negates the claim is not flagged.

The check is a pure deterministic linter over rendered output: it never touches
the audit chain, the manifest, or `verify_finding`, and it never changes scoring
math. The banned list is kept general (no image-specific literals) so the
evidence-agnostic gate stays satisfied.

Run standalone (it self-tests against synthetic fixtures and exits non-zero on a
policy regression):

    python3 scripts/report-escalation-linter.py

Or lint a rendered verdict.json (exit non-zero only on a hard FAIL; over-reads
print as warnings):

    python3 scripts/report-escalation-linter.py path/to/verdict.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field

# Banned escalation terms — general DFIR *overclaim* vocabulary, never an
# image-specific literal. Each entry is matched as a whole prose word/phrase
# (word-boundary aware, hyphen/underscore-internal matches are ignored) so a
# machine identifier or filename can never trip the gate. Keep this list keyed
# on conclusion-escalation language, not on artifact names.
BANNED_ESCALATION_TERMS: tuple[str, ...] = (
    "compromised",
    "compromise confirmed",
    "confirmed compromise",
    "breach confirmed",
    "confirmed breach",
    "pass-the-hash",
    "pass the hash",
    "exfiltration confirmed",
    "confirmed exfiltration",
    "data was exfiltrated",
    "data exfiltrated",
    "attacker",
    "adversary confirmed",
    "malware confirmed",
    "confirmed malware",
    "backdoor confirmed",
    "proves",
    "proven",
    "definitely",
    "definitively",
    "clearly shows",
    "undeniably",
    "beyond doubt",
)

# Hedge verbs / scoped-conclusion phrasing. A backed escalation claim must still
# be phrased as a scoped inference, not a bare assertion.
HEDGE_TERMS: tuple[str, ...] = (
    "consistent with",
    "suggests",
    "suggestive of",
    "indicative of",
    "appears to",
    "may have",
    "likely",
    "possible",
    "possibly",
    "cannot exclude",
    "cannot rule out",
    "hypothesis",
    "inferred",
    "potential",
)

# Conclusions naming a hard escalation require corroboration from at least this
# many distinct artifact classes (mirrors the SOUL.md >=2-artifact-class rule).
MIN_ARTIFACT_CLASSES = 2


# Clause-local tool-semantics over-read floor. A rule fires when, within a single
# clause, the cited weak artifact (named in the clause or in the record's
# cited-tool metadata) is paired with a claim verb the artifact cannot support
# and no corroborating stronger artifact is present. Each rule keys on a general
# DFIR signature (artifact name + claim verb) and is emitted as a warning.
@dataclass(frozen=True)
class OverReadRule:
    """One clause-local artifact-cannot-support-verb over-read rule."""

    name: str
    artifact_terms: tuple[str, ...]
    verb_terms: tuple[str, ...]
    corroborator_terms: tuple[str, ...]
    message: str


# Per-rule term vocabularies. Kept as packed module-level constants (fmt: skip)
# so the dense DFIR signal lists stay compact and readable. Each is a general
# DFIR signature list — artifact names or claim verbs — never an image literal.
# fmt: off
_EXECUTION_VERBS = (
    "executed", "execution", "was run", "were run", "code execution",
    "process execution", "proof of execution", "evidence of execution",
)
_EXECUTION_CORROBORATORS = (
    "prefetch", "4688", "process creation", "process-creation", "sysmon",
    "userassist", "wmi process",
)
_SHIMCACHE_ARTIFACTS = (
    "shimcache", "shim cache", "appcompatcache", "appcompat cache",
    "application compatibility cache",
)
_NETSCAN_ARTIFACTS = (
    "netscan", "arp", "arp cache", "arp table", "arp entry", "netstat",
)
_FILE_MOVEMENT_VERBS = (
    "files were moved", "file was moved", "files moved", "moved files",
    "copied files", "files copied", "data was moved", "data moved",
    "transferred files", "file transfer", "data transfer", "staged files",
    "files staged", "exfiltrated files", "lateral file copy", "file copy",
)
_FILE_MOVEMENT_CORROBORATORS = (
    "usnjrnl", "usn journal", "usn-journal", "$j", "mft", "master file table",
    "$logfile", "prefetch", "shellbag",
)
_MFT_ARTIFACTS = (
    "$mft", "mft", "mft-only", "master file table", "mft record", "mft entry",
    "mft timeline",
)
_MFT_ACCESS_VERBS = (
    "was opened", "were opened", "file was opened", "user opened", "opened by",
    "opened the file", "was accessed", "were accessed", "user accessed",
    "accessed by", "double-clicked", "interactively opened", "viewed the file",
)
_MFT_CORROBORATORS = (
    "lnk", "shellbag", "shellbags", "jumplist", "jump list", "jumplists",
    "recentdocs", "recent docs", "userassist", "prefetch", "browser history",
    "mru",
)
# External-C2 / internet-egress claim vocabulary. Paired with a private address
# in the same clause, this is the RFC1918-cannot-be-external-C2 over-read.
EXTERNAL_C2_TERMS = (
    "external c2", "external command and control", "command and control",
    "command-and-control", "c2 server", "c2 channel", "c2 beacon",
    "external server", "external host", "external ip", "external address",
    "internet-facing", "remote c2", "attacker-controlled server",
    "attacker infrastructure",
)
# Negation cues. If any appears in a clause, the clause-local verb/IP rules are
# suppressed for that clause (favour precision: a negated claim such as
# "ShimCache does not prove execution" is not an over-read).
NEGATION_TERMS = (
    "not", "no", "never", "without", "cannot", "can't", "isn't", "wasn't",
    "weren't", "doesn't", "didn't", "rather than", "instead of",
)
# fmt: on

OVERREAD_RULES: tuple[OverReadRule, ...] = (
    OverReadRule(
        name="shimcache-not-execution",
        artifact_terms=_SHIMCACHE_ARTIFACTS,
        verb_terms=_EXECUTION_VERBS,
        corroborator_terms=_EXECUTION_CORROBORATORS,
        message=(
            "ShimCache/AppCompatCache records path presence + last-modified, "
            "not execution; cite Prefetch/4688/Sysmon-1 for an execution claim"
        ),
    ),
    OverReadRule(
        name="amcache-not-execution",
        artifact_terms=("amcache",),
        verb_terms=_EXECUTION_VERBS,
        corroborator_terms=_EXECUTION_CORROBORATORS,
        message=(
            "Amcache records program presence/install metadata, not execution; "
            "cite Prefetch/4688/Sysmon-1 for an execution claim"
        ),
    ),
    OverReadRule(
        name="netscan-not-file-movement",
        artifact_terms=_NETSCAN_ARTIFACTS,
        verb_terms=_FILE_MOVEMENT_VERBS,
        corroborator_terms=_FILE_MOVEMENT_CORROBORATORS,
        message=(
            "netscan/ARP shows network endpoints, not file movement; cite "
            "USN-journal/$MFT/filesystem artifacts for a files-moved claim"
        ),
    ),
    OverReadRule(
        name="mft-not-access",
        artifact_terms=_MFT_ARTIFACTS,
        verb_terms=_MFT_ACCESS_VERBS,
        corroborator_terms=_MFT_CORROBORATORS,
        message=(
            "$MFT records file existence/timestamps, not user access; cite "
            "LNK/Shellbags/JumpLists/RecentDocs/UserAssist for an access claim"
        ),
    ),
)

# Clause boundaries that never fall inside a dotted IPv4 address or a decimal:
# split only on a terminator followed by whitespace, on newlines, and on a
# space-delimited dash.
_CLAUSE_BOUNDARY = re.compile(r"(?<=[.;!?])\s+|\n+|\s[—–-]\s")

# A standalone IPv4 literal (not embedded in a longer digit/dot run).
_IPV4 = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")

# Claimed PID, e.g. "PID 1234", "pid=1234", "process id: 1234".
_CLAIMED_PID = re.compile(
    r"\b(?:pid|process\s+id)\b\s*[#:=]?\s*(\d{1,7})", re.IGNORECASE
)

# Claimed row count, e.g. "9 connections", "3 processes".
_CLAIMED_COUNT = re.compile(
    r"\b(\d{1,6})\s+("
    r"connections?|processes?|rows?|events?|entries?|sessions?|hits?|"
    r"matches|records?|files?|logons?|packets?|flows?|detections?|alerts?"
    r")\b",
    re.IGNORECASE,
)


def _word_hits(text: str, terms: tuple[str, ...]) -> list[str]:
    """Return the terms that appear as whole prose words/phrases in ``text``.

    Word-boundary aware and hyphen/underscore tolerant: a term is only a hit
    when it is not embedded inside a longer identifier token. ``pass-the-hash``
    itself is allowed to match because the dashes are part of the term.
    """
    lowered = text.lower()
    hits: list[str] = []
    for term in terms:
        if not term:
            continue
        pattern = rf"(?<![\w-]){re.escape(term)}(?![\w-])"
        if re.search(pattern, lowered):
            hits.append(term)
    return hits


def escalation_hits(text: str) -> list[str]:
    """Banned escalation terms present in ``text`` (sorted, de-duplicated)."""
    return sorted(set(_word_hits(text or "", BANNED_ESCALATION_TERMS)))


def has_hedge(text: str) -> bool:
    """True when ``text`` carries any scoped/hedge phrasing."""
    return bool(_word_hits(text or "", HEDGE_TERMS))


def record_text(record: dict) -> str:
    """Concatenate the customer-visible prose fields of a report record."""
    return " ".join(
        str(record.get(key) or "")
        for key in ("text", "description", "title", "summary", "headline")
    )


def record_artifact_classes(record: dict) -> set[str]:
    """Distinct corroborating artifact classes a record claims, normalized."""
    classes: set[str] = set()
    for key in (
        "artifact_classes",
        "corroborating_artifact_classes",
        "artifact_classes_observed",
    ):
        value = record.get(key)
        if isinstance(value, (list, tuple, set)):
            classes.update(
                str(item).strip().lower() for item in value if str(item).strip()
            )
        elif isinstance(value, str) and value.strip():
            classes.add(value.strip().lower())
    return classes


def _clauses(text: str) -> list[str]:
    """Split prose into clause-local units (IPv4/decimal-safe boundaries)."""
    return [part.strip() for part in _CLAUSE_BOUNDARY.split(text or "") if part.strip()]


def _record_artifact_blob(record: dict) -> str:
    """Cited-tool/artifact tokens from a record, for substring keying.

    Built from machine-named cited-tool fields (tool names, artifact path,
    artifact classes); matched by substring because these are identifiers like
    ``mft_timeline`` where ``mft`` is a semantic sub-token.
    """
    tokens: list[str] = []
    cited_keys = ("replay_tool_name", "tool", "tool_name", "cited_tool", "source_tool")
    for key in cited_keys:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            tokens.append(value.strip().lower())
    path = record.get("artifact_path")
    if isinstance(path, str) and path.strip():
        tokens.append(path.strip().lower())
    tokens.extend(record_artifact_classes(record))
    return " ".join(tokens)


def _blob_contains(blob: str, terms: tuple[str, ...]) -> bool:
    """True when any term is a substring of the cited-tool token blob."""
    return any(term and term in blob for term in terms)


def _rule_overreads(clause: str, blob: str) -> list[str]:
    """Artifact-cannot-support-verb messages for a single clause."""
    messages: list[str] = []
    for rule in OVERREAD_RULES:
        if not _word_hits(clause, rule.verb_terms):
            continue
        artifact_cited = bool(
            _word_hits(clause, rule.artifact_terms)
        ) or _blob_contains(blob, rule.artifact_terms)
        if not artifact_cited:
            continue
        corroborated = bool(
            _word_hits(clause, rule.corroborator_terms)
        ) or _blob_contains(blob, rule.corroborator_terms)
        if corroborated:
            continue
        messages.append(rule.message)
    return messages


def _private_ipv4(octets: tuple[int, int, int, int]) -> bool:
    """True for RFC1918, loopback, or link-local IPv4 (non-routable)."""
    a, b, _c, _d = octets
    if any(octet > 255 for octet in octets):
        return False
    return (
        a == 10
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or a == 127
        or (a == 169 and b == 254)
    )


def _ipv4_literals(text: str) -> list[tuple[int, int, int, int]]:
    """Standalone, in-range IPv4 literals in ``text``."""
    found: list[tuple[int, int, int, int]] = []
    for match in _IPV4.finditer(text):
        octets = tuple(int(group) for group in match.groups())
        if all(octet <= 255 for octet in octets):
            found.append(octets)  # type: ignore[arg-type]
    return found


def _rfc1918_overreads(clause: str) -> list[str]:
    """Flag a private address cited as an external C2 / internet endpoint."""
    ips = _ipv4_literals(clause)
    if not ips:
        return []
    private = [ip for ip in ips if _private_ipv4(ip)]
    if not private:
        return []
    # A routable public IP in the same clause may be the external peer instead.
    if any(not _private_ipv4(ip) for ip in ips):
        return []
    if not _word_hits(clause, EXTERNAL_C2_TERMS):
        return []
    shown = ".".join(str(octet) for octet in private[0])
    return [
        f"private/RFC1918 address ({shown}) cited for an external C2/internet "
        "claim: a non-routable address cannot itself be the external "
        "command-and-control endpoint"
    ]


_OUTPUT_KEYS = (
    "tool_output", "cited_tool_output", "cited_output", "evidence_excerpt",
    "tool_output_excerpt",
)  # fmt: skip


def _gather_output_text(record: dict) -> str:
    """Cited tool-output text from a record (string or serialized list/dict)."""
    parts: list[str] = []
    for key in _OUTPUT_KEYS:
        value = record.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, (list, dict)):
            parts.append(json.dumps(value, sort_keys=True, default=str))
    return "\n".join(parts)


def _cited_row_count(record: dict) -> int | None:
    """Explicit row count of the cited tool output, if the record states one."""
    value = record.get("cited_row_count")
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    for key in ("tool_output", "cited_output", "cited_tool_output"):
        listing = record.get(key)
        if isinstance(listing, list):
            return len(listing)
    return None


def _pid_mismatches(text: str, output: str) -> list[str]:
    """Flag claimed PIDs absent from the cited tool output."""
    if not output:
        return []
    messages: list[str] = []
    seen: set[str] = set()
    for match in _CLAIMED_PID.finditer(text):
        pid = match.group(1)
        if pid in seen:
            continue
        if not re.search(rf"(?<!\d){re.escape(pid)}(?!\d)", output):
            seen.add(pid)
            messages.append(
                f"claimed PID {pid} is absent from the cited tool output; a "
                "PID not present in the cited evidence cannot anchor the claim"
            )
    return messages


def _row_count_mismatches(text: str, record: dict) -> list[str]:
    """Flag a numeric row-count claim that disagrees with the cited output."""
    actual = _cited_row_count(record)
    if actual is None:
        return []
    raw_noun = record.get("cited_row_noun")
    noun = (
        raw_noun.strip().lower().rstrip("s")
        if isinstance(raw_noun, str) and raw_noun.strip()
        else None
    )
    claims = [
        (int(number), unit.lower().rstrip("s"))
        for number, unit in _CLAIMED_COUNT.findall(text)
    ]
    if not claims:
        return []
    if noun is not None:
        candidates = [claim for claim in claims if claim[1] == noun]
    elif len(claims) == 1:
        candidates = claims
    else:
        # Ambiguous (several countable nouns, no disambiguating noun): skip.
        candidates = []
    messages: list[str] = []
    seen: set[int] = set()
    for value, unit in candidates:
        if value != actual and value not in seen:
            seen.add(value)
            messages.append(
                f"claimed count of {value} {unit} does not match the {actual} "
                "row(s) in the cited tool output"
            )
    return messages


def overread_warnings(text: str, record: dict | None = None) -> list[str]:
    """Clause-local tool-semantics over-read warnings for one record.

    Deterministic and order-stable. Verb/IP rules are suppressed on any clause
    with a negation cue; PID/row-count checks compare the full prose against the
    record's cited tool output.
    """
    record = record or {}
    blob = _record_artifact_blob(record)
    messages: list[str] = []
    seen: set[str] = set()

    def _add(items: list[str]) -> None:
        for item in items:
            if item not in seen:
                seen.add(item)
                messages.append(item)

    for clause in _clauses(text):
        if _word_hits(clause, NEGATION_TERMS):
            continue
        _add(_rule_overreads(clause, blob))
        _add(_rfc1918_overreads(clause))
    # PID + row-count claims are compared against the record-level cited output.
    _add(_pid_mismatches(text, _gather_output_text(record)))
    _add(_row_count_mismatches(text, record))
    return messages


@dataclass(frozen=True)
class LintResult:
    """Outcome of linting a set of report records."""

    ok: bool
    fails: list[tuple[str, list[str]]] = field(default_factory=list)
    warns: list[tuple[str, str]] = field(default_factory=list)
    overreads: list[tuple[str, str]] = field(default_factory=list)

    def summary(self) -> str:
        if self.fails:
            return f"{len(self.fails)} unbacked escalation conclusion(s)"
        parts: list[str] = []
        if self.warns:
            parts.append(f"{len(self.warns)} unhedged escalation conclusion(s)")
        if self.overreads:
            parts.append(f"{len(self.overreads)} tool-semantics over-read(s)")
        return ", ".join(parts) if parts else "no restricted-conclusion violations"


def lint_records(records: list[dict]) -> LintResult:
    """Lint report records for unbacked / unhedged escalation conclusions.

    Hard FAIL: a banned escalation term in a record backed by fewer than
    ``MIN_ARTIFACT_CLASSES`` distinct artifact classes (the conclusion is not
    earned by the cited evidence). WARN: a banned escalation term that *is*
    backed by >=2 classes but is phrased as a bare assertion (no hedge verb).
    """
    fails: list[tuple[str, list[str]]] = []
    warns: list[tuple[str, str]] = []
    overreads: list[tuple[str, str]] = []
    for index, record in enumerate(records or []):
        if not isinstance(record, dict):
            continue
        record_id = str(
            record.get("id") or record.get("finding_id") or f"record-{index}"
        )
        text = record_text(record)
        # Over-read floor runs on every record and only produces warnings.
        for message in overread_warnings(text, record):
            overreads.append((record_id, message))
        hits = escalation_hits(text)
        if not hits:
            continue
        if len(record_artifact_classes(record)) < MIN_ARTIFACT_CLASSES:
            fails.append((record_id, hits))
        elif not has_hedge(text):
            warns.append(
                (
                    record_id,
                    "escalation conclusion is backed but unhedged: " + ", ".join(hits),
                )
            )
    return LintResult(ok=not fails, fails=fails, warns=warns, overreads=overreads)


def lint_verdict(verdict: dict) -> LintResult:
    """Extract findings + attack-story narrative from a verdict.json-like dict."""
    records: list[dict] = []
    for finding in verdict.get("findings", []) or []:
        if isinstance(finding, dict):
            records.append(
                {"id": str(finding.get("finding_id") or "finding"), **finding}
            )
    attack_story = verdict.get("attack_story")
    if isinstance(attack_story, dict):
        for key in ("headline", "customer_summary"):
            text = attack_story.get(key)
            if isinstance(text, str) and text.strip():
                records.append({"id": f"attack_story.{key}", "text": text})
    return lint_records(records)


def _fixtures() -> list[tuple[str, bool]]:
    unbacked = lint_records(
        [
            {
                "id": "f-exfil-unbacked",
                "description": "Exfiltration confirmed: the host exfiltrated data.",
                "artifact_classes": ["network"],
            }
        ]
    )
    backed_hedged = lint_records(
        [
            {
                "id": "f-exfil-backed",
                "description": (
                    "Findings are consistent with exfiltration confirmed by both "
                    "network capture and on-disk staging artifacts."
                ),
                "artifact_classes": ["network", "disk/filesystem"],
            }
        ]
    )
    backed_unhedged = lint_records(
        [
            {
                "id": "f-exfil-unhedged",
                "description": "Exfiltration confirmed across network and disk evidence.",
                "artifact_classes": ["network", "disk/filesystem"],
            }
        ]
    )
    clean = lint_records(
        [
            {
                "id": "f-clean",
                "description": (
                    "EVTX 1102 records suggest the security log was cleared; "
                    "corroborate before escalation."
                ),
                "artifact_classes": ["evtx"],
            }
        ]
    )
    identifier_safe = lint_records(
        [
            {
                "id": "f-identifier",
                "description": "Artifact path compromised-host_log.evtx parsed cleanly.",
                "artifact_classes": ["evtx"],
            }
        ]
    )

    checks: list[tuple[str, bool]] = [
        ("unbacked escalation conclusion FAILs", not unbacked.ok),
        (
            "unbacked failure names the offending term",
            any("exfiltration confirmed" in terms for _, terms in unbacked.fails),
        ),
        (
            "backed + hedged escalation PASSes",
            backed_hedged.ok
            and not backed_hedged.warns
            and not backed_hedged.overreads,
        ),
        (
            "backed but unhedged escalation WARNs (not FAIL)",
            backed_unhedged.ok and bool(backed_unhedged.warns),
        ),
        (
            "hedged scoped lead with no banned term PASSes",
            clean.ok and not clean.warns and not clean.overreads,
        ),
        (
            "banned term inside an identifier token is ignored",
            identifier_safe.ok and not identifier_safe.warns,
        ),
        ("clean verdict extraction PASSes", lint_verdict({"findings": []}).ok),
    ]
    checks.extend(_overread_fixtures())
    return checks


# Over-read fixtures: (label, expect_substring_or_None, text, fields). A non-None
# expect must fire and contain that substring; None means the corroborated /
# negated / matching case must NOT warn. General DFIR signatures, no image literal.
# fmt: off
_OVERREAD_FIXTURES: tuple[tuple[str, str | None, str, dict], ...] = (
    ("ShimCache cited as execution WARNs (over-read)", "ShimCache",
     "ShimCache shows the malicious binary was executed on the host.",
     {"artifact_classes": ["registry"]}),
    ("ShimCache + Prefetch corroborated execution does NOT warn", None,
     "Prefetch and ShimCache together show the binary was executed.",
     {"artifact_classes": ["registry", "execution"]}),
    ("Amcache cited as execution WARNs (over-read)", "Amcache",
     "Amcache indicates the dropped tool was executed.",
     {"artifact_classes": ["registry"]}),
    ("netscan/ARP cited as file movement WARNs (over-read)", "file movement",
     "The netscan output shows files were moved to the staging share.",
     {"artifact_classes": ["network"]}),
    ("USN-journal-corroborated file movement does NOT warn", None,
     "USN journal and netscan together show files were moved off the host.",
     {"artifact_classes": ["network", "filesystem"]}),
    ("private RFC1918 address cited as external C2 WARNs (over-read)", "10.10.5.5",
     "The host beaconed to an external C2 at 10.10.5.5 every hour.",
     {"artifact_classes": ["network"]}),
    ("external claim with a public peer IP does NOT warn", None,
     "External C2 at 203.0.113.8 contacted from internal 10.10.5.5.",
     {"artifact_classes": ["network"]}),
    ("$MFT-only cited as user access WARNs (over-read)", "user access",
     "$MFT timestamps show the sensitive document was opened by the user.",
     {"artifact_classes": ["filesystem"]}),
    ("LNK-corroborated access does NOT warn", None,
     "LNK files and $MFT show the document was opened by the user.",
     {"artifact_classes": ["filesystem", "lnk"]}),
    ("careful MFT finding (negated + corroborated) does NOT warn", None,
     ("Hacking-tool artifacts recovered from the MFT. File presence itself is "
      "not an execution claim. Corroborates the Prefetch execution findings "
      "for the same toolset."),
     {"artifact_classes": ["filesystem"], "replay_tool_name": "mft_timeline"}),
    ("claimed PID absent from cited output WARNs (over-read)", "PID 6666",
     "Suspicious activity is attributed to PID 6666.",
     {"tool_output": "PID 1234 svchost.exe\nPID 5678 explorer.exe",
      "artifact_classes": ["memory"]}),
    ("claimed PID present in cited output does NOT warn", None,
     "Suspicious activity is attributed to PID 6666.",
     {"tool_output": "PID 6666 evil.exe\nPID 1234 svchost.exe",
      "artifact_classes": ["memory"]}),
    ("row-count claim disagreeing with cited output WARNs (over-read)", "9 connection",
     "netscan returned 9 connections to the host.",
     {"cited_row_count": 3, "artifact_classes": ["network"]}),
    ("row-count claim matching cited output does NOT warn", None,
     "netscan returned 3 connections to the host.",
     {"cited_row_count": 3, "artifact_classes": ["network"]}),
    ("noun-disambiguated row-count mismatch WARNs on the right noun", "2 connection",
     "The scan saw 5 processes and 2 connections.",
     {"cited_row_count": 7, "cited_row_noun": "connection",
      "artifact_classes": ["network"]}),
)
# fmt: on


def _overread_fixtures() -> list[tuple[str, bool]]:
    """Evaluate the clause-local over-read fixture table into smoke checks."""
    results: list[tuple[str, bool]] = []
    for label, expect, text, fields in _OVERREAD_FIXTURES:
        messages = [
            msg
            for _, msg in lint_records([{"id": "f", "text": text, **fields}]).overreads
        ]
        if expect is None:
            results.append((label, not messages))
        else:
            results.append((label, any(expect in msg for msg in messages)))
    return results


def _run_self_test() -> int:
    checks = _fixtures()
    print("=" * 60)
    print("Find Evil! - restricted-conclusions report linter smoke")
    print(f"  banned escalation terms: {len(BANNED_ESCALATION_TERMS)}")
    print(f"  hedge terms: {len(HEDGE_TERMS)}")
    print(f"  over-read rules: {len(OVERREAD_RULES)} + RFC1918/PID/row-count")
    print("=" * 60)
    failures = 0
    for label, ok in checks:
        marker = "OK  " if ok else "FAIL"
        print(f"  [{marker}] {label}")
        failures += 0 if ok else 1
    print("=" * 60)
    if failures:
        print(f"FAIL - {failures} restricted-conclusion linter checks failed.")
        return 1
    print(f"OK - all {len(checks)} restricted-conclusion linter checks pass.")
    return 0


def _lint_file(path: str) -> int:
    """Lint a rendered verdict.json. Exit non-zero only on a hard FAIL."""
    try:
        with open(path, encoding="utf-8") as handle:
            verdict = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"error: cannot read verdict json {path!r}: {exc}", file=sys.stderr)
        return 2
    result = lint_verdict(verdict if isinstance(verdict, dict) else {})
    print(f"{path}: {result.summary()}")
    for record_id, hits in result.fails:
        print(f"  FAIL  {record_id}: unbacked escalation -> {', '.join(hits)}")
    for record_id, message in result.warns:
        print(f"  WARN  {record_id}: {message}")
    for record_id, message in result.overreads:
        print(f"  WARN  {record_id}: over-read -> {message}")
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Restricted-conclusions + clause-local over-read linter."
    )
    parser.add_argument(
        "verdict",
        nargs="?",
        help="optional verdict.json to lint; omit to run the built-in self-test",
    )
    args = parser.parse_args(argv)
    return _lint_file(args.verdict) if args.verdict else _run_self_test()


if __name__ == "__main__":
    sys.exit(main())
