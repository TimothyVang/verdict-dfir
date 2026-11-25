"""Tests for the ``accuracy_compare`` MCP shim.

The shim is a READ-ONLY, audit-chained *diagnostic* that grades a finished Case
directory against a curated ground-truth golden. Per CLAUDE.md, optional scoring
sidecars are never evidence and never create Findings — so this tool must NOT emit
a ``finding_approved`` record. When given an ``audit_log_path`` it appends a single
non-Finding ``accuracy_diagnostic`` record to the hash chain.

These tests pin the boundary: input validation (extra=forbid), output shape, and
that the appended record's kind is NOT ``finding_approved``. The scoring math
itself is covered by ``services/agent/tests/test_accuracy.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from findevil_agent.crypto.audit_log import AuditLog
from pydantic import ValidationError

from findevil_agent_mcp.tools.accuracy_compare import (
    SPEC,
    AccuracyCompareInput,
    AccuracyCompareOutput,
)

_REPO_ROOT = Path(__file__).resolve().parents[3]
_NIST_GOLDEN = _REPO_ROOT / "goldens" / "nist-hacking-case" / "expected-findings.json"

# Seven of 14 SCHARDT ground-truth claims (50% recall, below the 71% min).
_SEVEN_OF_FOURTEEN = [
    {
        "finding_id": "r-001",
        "description": "Dual-boot XP install linked-list recent searches hacking tools",
    },
    {
        "finding_id": "r-002",
        "description": "USB device insertion history external drive connected staging",
    },
    {"finding_id": "r-003", "description": "Recovered deleted email discussing the intrusion plan"},
    {
        "finding_id": "r-004",
        "description": "Hacking tool artifacts Program Files downloaded applications",
    },
    {"finding_id": "r-005", "description": "Prefetch evidence hacking tool execution"},
    {"finding_id": "r-006", "description": "Internet history indicating downloads illicit content"},
    {
        "finding_id": "r-007",
        "description": "Shellbag entries navigation removable media holding staged files",
    },
]


def _case_dir(tmp_path: Path, verdict: str, findings: list[dict]) -> Path:
    d = tmp_path / "case"
    d.mkdir(parents=True, exist_ok=True)
    (d / "verdict.json").write_text(
        json.dumps({"case_id": "nist-hacking-case", "verdict": verdict, "findings": findings}),
        encoding="utf-8",
    )
    return d


class TestRegistration:
    def test_tool_name_is_accuracy_compare(self) -> None:
        assert SPEC.name == "accuracy_compare"

    def test_in_registry(self) -> None:
        from findevil_agent_mcp.tools import all_specs

        names = {s.name for s in all_specs()}
        assert "accuracy_compare" in names


class TestInputValidation:
    def test_extra_forbid_rejects_unknown_fields(self) -> None:
        with pytest.raises(ValidationError):
            AccuracyCompareInput(case_dir="/x", bogus_field="nope")  # type: ignore[call-arg]

    def test_case_dir_required(self) -> None:
        with pytest.raises(ValidationError):
            AccuracyCompareInput()  # type: ignore[call-arg]

    def test_golden_path_optional(self) -> None:
        inp = AccuracyCompareInput(case_dir="/x")
        assert inp.golden_path is None
        assert inp.audit_log_path is None


class TestOutputShape:
    async def test_seven_of_fourteen_schardt(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert isinstance(result, AccuracyCompareOutput)
        assert result.expected_n == 14
        assert result.recalled_n == 7
        assert result.recall_percent == 50
        assert result.verdict_match is True
        assert result.pass_ is False  # 50% < 71% min_recall
        # the diagnostic carries precision / F1 / hallucination + negative coverage
        assert 0 <= result.precision_percent <= 100
        assert result.negative_coverage["coverage_percent"] == 100
        # no audit_log_path given -> nothing appended, no record kind reported
        assert result.audit_record_kind is None

    async def test_output_extra_forbid(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert result.model_config.get("extra") == "forbid"


class TestNonFindingAuditRecord:
    async def test_appends_non_finding_diagnostic_record(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        audit_path = tmp_path / "audit.jsonl"
        result = await SPEC.handler(
            AccuracyCompareInput(
                case_dir=str(case_dir),
                golden_path=str(_NIST_GOLDEN),
                audit_log_path=str(audit_path),
            )
        )
        # The shim reports which kind it appended, and it is NOT a Finding.
        assert result.audit_record_kind == "accuracy_diagnostic"
        assert result.audit_record_kind != "finding_approved"

        # Inspect the chain directly: exactly one record, non-Finding kind.
        records = list(AuditLog(audit_path).iter_records())
        assert len(records) == 1
        rec = records[0]
        assert rec.kind == "accuracy_diagnostic"
        assert rec.kind != "finding_approved"
        # The record carries the scalar scores (a diagnostic, not a claim).
        assert rec.payload["recall_percent"] == 50
        assert rec.payload["pass"] is False
        # It must NOT smuggle a finding_id citation (it is not a Finding).
        assert "finding_id" not in rec.payload
        assert "tool_call_id" not in rec.payload

    async def test_no_audit_path_writes_nothing(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        # No audit.jsonl created anywhere under the case dir.
        assert not (case_dir / "audit.jsonl").exists()


class TestGoldenResolution:
    async def test_missing_golden_raises_clear_error(self, tmp_path: Path) -> None:
        # A case dir whose case_id has no matching goldens/<id> and no override.
        d = tmp_path / "unknown"
        d.mkdir()
        (d / "verdict.json").write_text(
            json.dumps({"case_id": "no-such-golden-xyz", "verdict": "NO_EVIL", "findings": []}),
            encoding="utf-8",
        )
        with pytest.raises(FileNotFoundError):
            await SPEC.handler(AccuracyCompareInput(case_dir=str(d)))


class TestZeroFindingRunStillReturns:
    """A scored run with no findings must still produce output, not a ValidationError.

    ``accuracy.score`` reports ``precision_percent`` / ``f1`` / ``hallucination_rate``
    as None when the denominator is zero — nothing matched and nothing was provably
    wrong. The tests above never drive a *scored* zero-finding case to output
    construction (the one ``findings: []`` case takes the no-golden-found path and
    never reaches ``score()``), so the shim's non-Optional output fields went
    unexercised on exactly the run this scorer change exists to reward: a complete,
    correct, zero-finding true-negative.
    """

    _BENIGN_GOLDEN = _REPO_ROOT / "goldens" / "synthetic-benign" / "expected-findings.json"

    def _ready_benign_golden(self, tmp_path: Path) -> Path:
        data = json.loads(self._BENIGN_GOLDEN.read_text(encoding="utf-8"))
        data["scoring_status"] = "ready"
        data.pop("not_ready_reason", None)
        path = tmp_path / "synthetic-benign-ready.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def _benign_case(self, tmp_path: Path) -> Path:
        d = tmp_path / "benign"
        d.mkdir(parents=True, exist_ok=True)
        (d / "verdict.json").write_text(
            json.dumps(
                {
                    "case_id": "synthetic-benign",
                    "verdict": "NO_EVIL",
                    "findings": [],
                    "tool_calls": [{"tool_call_id": "tc-1", "tool": "case_open"}],
                }
            ),
            encoding="utf-8",
        )
        return d

    async def test_clean_true_negative_run_returns_unmeasured_metrics(self, tmp_path: Path) -> None:
        out = await SPEC.handler(
            AccuracyCompareInput(
                case_dir=str(self._benign_case(tmp_path)),
                golden_path=str(self._ready_benign_golden(tmp_path)),
            )
        )
        assert isinstance(out, AccuracyCompareOutput)
        # The run is a genuine PASS ...
        assert out.pass_ is True
        assert out.run_completed is True
        assert out.run_incomplete_reasons == []
        # ... and the unmeasurable metrics travel as null, not as a perfect score.
        assert out.precision_percent is None
        assert out.f1 is None
        assert out.hallucination_rate is None

    async def test_incomplete_zero_finding_run_reports_its_reasons(self, tmp_path: Path) -> None:
        d = tmp_path / "broken"
        d.mkdir(parents=True, exist_ok=True)
        (d / "verdict.json").write_text(
            json.dumps(
                {
                    "case_id": "synthetic-benign",
                    "verdict": "NO_EVIL",
                    "findings": [],
                    "heartbeat": {"terminated_partial": True},
                }
            ),
            encoding="utf-8",
        )
        out = await SPEC.handler(
            AccuracyCompareInput(
                case_dir=str(d),
                golden_path=str(self._ready_benign_golden(tmp_path)),
            )
        )
        assert out.pass_ is False
        assert out.run_completed is False
        assert out.run_incomplete_reasons != []

    async def test_not_ready_golden_is_rejected_without_an_audit_record(
        self, tmp_path: Path
    ) -> None:
        audit_path = tmp_path / "audit.jsonl"

        with pytest.raises(
            ValueError,
            match=r"scoring_status=not_ready.*not scoreable",
        ):
            await SPEC.handler(
                AccuracyCompareInput(
                    case_dir=str(self._benign_case(tmp_path)),
                    golden_path=str(self._BENIGN_GOLDEN),
                    audit_log_path=str(audit_path),
                )
            )

        assert not audit_path.exists()

    async def test_not_ready_refusal_is_typed_so_a_caller_can_route_it(
        self, tmp_path: Path
    ) -> None:
        """The shim must let an MCP caller tell "excluded by key" from "broken key".

        Both used to surface as a bare ValueError, so a caller had to string-match
        the message to know whether the engine had actually been assessed. The
        typed refusal carries the key's own declaration instead.
        """
        from findevil_agent.accuracy import GoldenNotScoreable

        declared = json.loads(self._BENIGN_GOLDEN.read_text(encoding="utf-8"))
        audit_path = tmp_path / "audit.jsonl"

        with pytest.raises(GoldenNotScoreable) as excinfo:
            await SPEC.handler(
                AccuracyCompareInput(
                    case_dir=str(self._benign_case(tmp_path)),
                    golden_path=str(self._BENIGN_GOLDEN),
                    audit_log_path=str(audit_path),
                )
            )

        assert excinfo.value.case_id == "synthetic-benign"
        assert excinfo.value.reason == declared["not_ready_reason"]
        # Still no audit record: an exclusion is not a diagnostic result.
        assert not audit_path.exists()
