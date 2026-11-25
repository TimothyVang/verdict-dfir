"""Deterministic, LLM-free entailment check.

A Finding cites a ``tool_call_id``; the verifier already proves that citation
reproduces (re-run output SHA-256 matches). That proves the finding points at
real, unchanged evidence — it does NOT prove the model READ that evidence
right. This module closes that gap for **structured-value claims**: given the
values a finding asserts (:class:`findevil_agent.events.AssertedValue`) and the
re-run output JSON, it re-extracts each asserted value with a pure parser and
confirms it is actually present. No model, so no shared model blind spot.

Scope (by design): structured-value claims only — registry, EVTX, prefetch,
MFT, USN, amcache/shimcache/LNK fields, anything the typed parsers emit as
named fields. Purely interpretive claims ("this PowerShell is malicious") have
no deterministic ground truth to diff and are out of scope.

The path grammar and match semantics live in ``tests/test_entailment.py`` —
those tests are the spec.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from findevil_agent.events import AssertedValue

# A path segment: a key, then zero or more ``[*]`` / ``[<int>]`` index ops.
_SEGMENT = re.compile(r"^([^\[\].]+)((?:\[\*\]|\[\d+\])*)$")
_INDEX = re.compile(r"\[(\*|\d+)\]")

# Anchor-class token shapes (eviltrace grounding transparency). A HARD anchor is
# a high-specificity identifier — a wrong one is laundering, not a near-miss — so
# its non-entailment gates (reject). Everything else CORROBORATES (supports).
_HASH = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")
_IPV4 = re.compile(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$")
# A filename leaf: a basename with an extension and no path separators (a full
# path is corroborating context; the bare filename it ends in is the anchor).
_FILENAME = re.compile(r"^[^\\/]+\.[A-Za-z0-9][A-Za-z0-9_-]{0,7}$")


@dataclass(frozen=True)
class MatchedValue:
    """The actual value the deterministic parser read out of the evidence for a
    satisfied assertion. ``actual`` is the real leaf from the tool output (for a
    ``contains`` match it is the full evidence string, not just the asserted
    substring), so the recorded fact is **server-read, not model-transcribed**.
    """

    path: str
    expected: str
    actual: str
    match: str


@dataclass(frozen=True)
class EntailmentResult:
    """Outcome of checking a finding's asserted values against tool output.

    ``hard_failures`` is the subset of ``failures`` whose asserted value
    classified as a HARD anchor (filename/hash/byte-size/IP) — grounding
    transparency for the report. ``identity_failures`` is the narrower subset
    that are forgery-resistant IDENTITY anchors (cryptographic hash, IP
    address): for those a wrong value has no legitimate near-miss reading, so
    the verifier rejects outright regardless of confidence tier. (A filename or
    byte-size miss stays on the existing tier contract: CONFIRMED rejects, a
    lower tier downgrades.) ``multiplicity_demotions`` lists the paths of count
    claims ("two variants") that entailed FEWER leaves than they asserted; the
    single real line is genuine, so the verifier demotes the finding below
    CONFIRMED rather than rejecting it.
    """

    passed: bool
    reason: str
    failures: list[str] = field(default_factory=list)
    matched: list[MatchedValue] = field(default_factory=list)
    hard_failures: list[str] = field(default_factory=list)
    identity_failures: list[str] = field(default_factory=list)
    multiplicity_demotions: list[str] = field(default_factory=list)


def anchor_class(av: AssertedValue) -> str:
    """Classify one asserted value as a ``"hard"`` anchor or ``"corroborating"``.

    HARD anchors are high-specificity identifiers — filenames, hashes,
    byte-sizes, IP addresses — where a wrong value is laundering, not a
    near-miss, so non-entailment must gate. CORROBORATING values (paths,
    timestamps, plain strings, record co-location constraints) only support.

    Pure and LLM-free: the decision is a function of the asserted token shape
    and match mode, so it replays identically in the offline verifier.
    """
    # Timestamps and record co-location are supporting context by construction.
    if av.match in ("iso_ts", "record"):
        return "corroborating"
    # A byte-size / integer identifier asserted with the int matcher is hard.
    if av.match == "int":
        return "hard"
    token = av.expected.strip()
    if _HASH.match(token) or _IPV4.match(token) or _is_ipv6(token):
        return "hard"
    if _FILENAME.match(token):
        return "hard"
    return "corroborating"


def is_identity_anchor(av: AssertedValue) -> bool:
    """True if the asserted value is a forgery-resistant IDENTITY anchor — a
    cryptographic hash or an IP address. These are the hard anchors with no
    legitimate near-miss reading, so a non-entailment must reject the finding
    outright (the verifier's cross-tier gate), unlike a filename/byte-size miss
    which stays on the existing per-tier downgrade contract."""
    if av.match in ("iso_ts", "record", "int"):
        return False
    token = av.expected.strip()
    return bool(_HASH.match(token) or _IPV4.match(token) or _is_ipv6(token))


def _is_ipv6(token: str) -> bool:
    """True if ``token`` parses as an IPv6 address. Uses stdlib ``ipaddress`` so
    the full address grammar (compression, embedded IPv4, zones) is handled
    without a hand-rolled regex."""
    if ":" not in token:
        return False
    try:
        ipaddress.IPv6Address(token.split("%", 1)[0])
    except ValueError:
        return False
    return True


def check_entailment(
    asserted_values: list[AssertedValue], parsed_output: dict[str, Any]
) -> EntailmentResult:
    """Confirm every asserted value is actually present in ``parsed_output``.

    Passes vacuously when there are no assertions (backward compatible: a
    finding that declares nothing structured is not gated here). For each
    satisfied assertion the matched evidence leaf is captured in
    :attr:`EntailmentResult.matched` — the extractive guarantee: what gets
    recorded is the value the parser read from the evidence, not the value the
    model typed.
    """
    failures: list[str] = []
    hard_failures: list[str] = []
    identity_failures: list[str] = []
    matched: list[MatchedValue] = []
    multiplicity_demotions: list[str] = []
    for av in asserted_values:
        leaves = _resolve(av.path, parsed_output)
        hits = _all_matches(av.expected, leaves, av.match)
        if not hits:
            failures.append(av.path)
            if anchor_class(av) == "hard":
                hard_failures.append(av.path)
            if is_identity_anchor(av):
                identity_failures.append(av.path)
            continue
        # At least one leaf entails. Multiplicity guard: a count claim must be
        # backed by at least that many distinct entailed leaves; otherwise the
        # over-count is demoted (the single real line still stands).
        if av.count is not None and len(hits) < av.count:
            multiplicity_demotions.append(av.path)
        hit = hits[0]
        matched.append(
            MatchedValue(
                path=av.path,
                expected=av.expected,
                actual="" if hit is None else str(hit),
                match=av.match,
            )
        )
    if failures:
        return EntailmentResult(
            passed=False,
            reason="asserted value not found in tool output for: " + ", ".join(failures),
            failures=failures,
            matched=matched,
            hard_failures=hard_failures,
            identity_failures=identity_failures,
            multiplicity_demotions=multiplicity_demotions,
        )
    return EntailmentResult(
        passed=True,
        reason="all asserted values present in tool output",
        matched=matched,
        multiplicity_demotions=multiplicity_demotions,
    )


def _all_matches(expected: str, leaves: list[Any], mode: str) -> list[Any]:
    """Every leaf that matches, in order. Empty list means none did — both the
    "asserted field not present" signal and the input to the multiplicity count
    (how many distinct supporting lines actually entail the claim). A satisfied
    assertion may legitimately match a leaf whose value is ``None``, so a count
    of matches, not a ``None`` sentinel, is what distinguishes "no match"."""
    return [leaf for leaf in leaves if _matches(expected, leaf, mode)]


# Sentinel: a satisfied assertion may legitimately match a leaf whose value is
# ``None``, so "no leaf matched" cannot be signalled with ``None``.
_NO_MATCH = object()


def check_expectation(
    expectation: AssertedValue, parsed_output: dict[str, Any]
) -> EntailmentResult:
    """Refute a finding's falsifiable PREDICTION against its cited output.

    Inverse polarity of :func:`check_entailment`. An ``AssertedValue`` is refuted
    when its value is ABSENT; an *expectation* is refuted only when the cited
    output reaches the predicted ``path`` and every leaf there CONTRADICTS the
    prediction (a present-but-conflicting value). Path-absent means there is no
    contradicting evidence, so the prediction stands — refutation requires a
    present, conflicting leaf, never mere absence. Reuses the same path resolver
    and matchers as the entailment check; no new engine.

    Returns ``passed=True`` when consistent or silent (path absent / any leaf
    matches), ``passed=False`` (refuted) when the path is reached but no leaf
    matches the prediction.
    """
    leaves = _resolve(expectation.path, parsed_output)
    if not leaves:
        # No leaf at the predicted path: no evidence that contradicts the
        # prediction, so the finding is not refuted.
        return EntailmentResult(passed=True, reason="expectation path not present in tool output")
    hit = _first_match(expectation.expected, leaves, expectation.match)
    if hit is _NO_MATCH:
        return EntailmentResult(
            passed=False,
            reason=(
                f"expectation contradicted by cited output: predicted "
                f"{expectation.path}={expectation.expected!r} ({expectation.match}) "
                "but the output holds a conflicting value"
            ),
            failures=[expectation.path],
        )
    return EntailmentResult(
        passed=True,
        reason="expectation consistent with cited output",
        matched=[
            MatchedValue(
                path=expectation.path,
                expected=expectation.expected,
                actual="" if hit is None else str(hit),
                match=expectation.match,
            )
        ],
    )


def _first_match(expected: str, leaves: list[Any], mode: str) -> Any:
    """Return the first leaf that matches, or ``_NO_MATCH`` if none do."""
    for leaf in leaves:
        if _matches(expected, leaf, mode):
            return leaf
    return _NO_MATCH


def entailment_slice(result: EntailmentResult) -> dict[str, Any]:
    """The minimal, JSON-serializable record of an entailment outcome to persist
    into the signed audit chain: the value the parser READ from the evidence for
    each satisfied assertion, plus the pass flag and any failures. Small by
    design — the full tool output is never persisted, only this slice.
    """
    return {
        "passed": result.passed,
        "matched": [
            {"path": m.path, "expected": m.expected, "actual": m.actual, "match": m.match}
            for m in result.matched
        ],
        "failures": list(result.failures),
    }


def recheck_entailment_slice(slice_: Any) -> bool | str:
    """Offline re-verification of a persisted :func:`entailment_slice`.

    Re-runs the matcher over the **sealed** matched values — no tool re-run —
    and confirms each still satisfies its assertion and the recorded outcome is
    internally consistent. ``manifest_verify`` calls this so a third party can
    re-confirm, offline, that the evidence values sealed into the signed chain
    actually entail the findings. Returns ``True`` or a reason string.

    Scope (honest): this re-checks the sealed slice for tamper/consistency; it
    does not re-extract from the original full output, which is not persisted.
    """
    if not isinstance(slice_, dict):
        return "entailment slice is not an object"
    for m in slice_.get("matched") or []:
        if not isinstance(m, dict):
            return "entailment slice has a malformed matched entry"
        path = str(m.get("path", "?"))
        expected = str(m.get("expected", ""))
        actual = m.get("actual", "")
        mode = str(m.get("match", "exact"))
        if mode == "record":
            try:
                constraints = json.loads(expected)
            except (ValueError, TypeError):
                return f"record slice expected is not JSON at {path}"
            text = str(actual).lower()
            if not isinstance(constraints, dict) or not all(
                str(v).strip().lower() in text for v in constraints.values()
            ):
                return f"sealed record value no longer satisfies the assertion at {path}"
        elif not _matches(expected, actual, mode):
            return f"sealed value no longer satisfies the assertion at {path}"
    if slice_.get("passed") and slice_.get("failures"):
        return "entailment slice marked passed but lists failures"
    return True


def _resolve(path: str, obj: Any) -> list[Any]:
    """Resolve a dotted/wildcard path to the SET of leaf values it reaches.

    Returns an empty list if any segment is malformed or the path reaches
    nothing — which the caller treats as "asserted field not in the output".
    """
    nodes: list[Any] = [obj]
    for raw in path.split("."):
        m = _SEGMENT.match(raw)
        if not m:
            return []
        key, brackets = m.group(1), m.group(2)
        nxt: list[Any] = []
        for node in nodes:
            if not isinstance(node, dict) or key not in node:
                continue
            current: list[Any] = [node[key]]
            for idx in _INDEX.findall(brackets):
                stepped: list[Any] = []
                for c in current:
                    if not isinstance(c, list):
                        continue
                    if idx == "*":
                        stepped.extend(c)
                    else:
                        i = int(idx)
                        if 0 <= i < len(c):
                            stepped.append(c[i])
                current = stepped
            nxt.extend(current)
        nodes = nxt
    return nodes


def _matches(expected: str, leaf: Any, mode: str) -> bool:
    if mode == "record":
        return _matches_record(expected, leaf)
    if mode == "int":
        try:
            return _to_int(expected) == _to_int(leaf)
        except (ValueError, TypeError):
            return False
    if mode == "iso_ts":
        e, lf = _to_dt(expected), _to_dt(leaf)
        return e is not None and lf is not None and e == lf
    leaf_str = "" if leaf is None else str(leaf)
    if mode == "contains":
        return expected.strip().lower() in leaf_str.lower()
    # exact
    return leaf_str.strip() == expected.strip()


def _matches_record(expected: str, leaf: Any) -> bool:
    """Co-location: ``leaf`` is one record (a dict); ``expected`` is a JSON
    object of ``{field: substring}`` constraints that must ALL hold within this
    same record. Binding the fields to one record is the point — it stops a
    claim assembled from values that live in different rows.
    """
    if not isinstance(leaf, dict):
        return False
    try:
        constraints = json.loads(expected)
    except (ValueError, TypeError):
        return False
    if not isinstance(constraints, dict) or not constraints:
        return False
    for key, want in constraints.items():
        if key not in leaf:
            return False
        if str(want).strip().lower() not in str(leaf[key]).lower():
            return False
    return True


def _to_int(value: Any) -> int:
    if isinstance(value, bool):  # bool is an int subclass; reject it explicitly
        raise ValueError("bool is not an integer match")
    if isinstance(value, int):
        return value
    return int(str(value).strip(), 0)  # base 0 accepts "0x.." hex and decimal


def _to_dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)
