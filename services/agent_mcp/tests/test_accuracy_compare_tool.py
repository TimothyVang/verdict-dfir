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

    async def test_surfaces_scope_caveats(self, tmp_path: Path) -> None:
        # The diagnostic carries the golden's epistemic class so a public-documented
        # (possibly training-contaminated) recall number is never read as proof.
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert result.validation_class == "public-documented"
        assert result.corpus_identity == "public"
        assert result.contamination_caveat  # non-empty for a public-documented corpus
        assert result.does_not_measure  # non-empty list of scope caveats

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


class TestContentAddressedCacheKey:
    """The diagnostic surfaces a content-addressed key so a 'live' number cannot be
    silently faked: identical inputs replay the same key, any drift flips it."""

    async def test_output_carries_sha256_cache_key(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        result = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert isinstance(result.cache_key, str)
        assert len(result.cache_key) == 64
        assert all(c in "0123456789abcdef" for c in result.cache_key)

    async def test_identical_inputs_replay_same_key(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        first = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        second = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert first.cache_key == second.cache_key

    async def test_edited_verdict_flips_key(self, tmp_path: Path) -> None:
        case_dir = _case_dir(tmp_path, "CONFIRMED_EVIL", _SEVEN_OF_FOURTEEN)
        before = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        # Hand-edit verdict.json — the key must change, so a stale number cannot be
        # passed off as tied to the new artifact.
        (case_dir / "verdict.json").write_text(
            json.dumps(
                {
                    "case_id": "nist-hacking-case",
                    "verdict": "CONFIRMED_EVIL",
                    "findings": _SEVEN_OF_FOURTEEN[:6],
                }
            ),
            encoding="utf-8",
        )
        after = await SPEC.handler(
            AccuracyCompareInput(case_dir=str(case_dir), golden_path=str(_NIST_GOLDEN))
        )
        assert before.cache_key != after.cache_key


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
