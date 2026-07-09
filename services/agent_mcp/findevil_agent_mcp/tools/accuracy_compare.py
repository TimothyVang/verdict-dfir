"""``accuracy_compare`` tool — read-only ground-truth accuracy diagnostic.

Wraps :func:`findevil_agent.accuracy.score` — the same pure scoring core the
hyphenated ``scripts/score-recall.py`` maintainer CLI uses. Given a finished Case
directory's ``verdict.json`` and a curated ground-truth golden
(``goldens/<id>/expected-findings.json``), it returns TP/FP/FN counts, precision /
recall / F1, hallucination rate, verdict consistency, and negative-assertion
coverage (the planted-bait claims the run was required to avoid).

It is a DIAGNOSTIC, not a Finding. Per CLAUDE.md's safety boundary, optional
automation / scoring sidecars are never evidence and never create Findings — so
this tool must never emit a ``finding_approved`` record. When given an
``audit_log_path`` it appends exactly one non-Finding ``accuracy_diagnostic``
record to the hash chain (scalar scores only, no ``finding_id`` / ``tool_call_id``
citation), so the score is attestable without ever masquerading as a Case Finding.

Read-only: it reads ``verdict.json`` + the golden and (optionally) appends to the
audit log. It never mutates evidence and never touches ``verdict.json``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from findevil_agent.accuracy import cache_key, resolve_golden, score
from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field

from findevil_agent_mcp.tools._base import ToolSpec

# Non-Finding audit-record kind. Deliberately NOT ``finding_approved`` — a scoring
# diagnostic is never a Finding and must never satisfy a Finding citation.
DIAGNOSTIC_KIND = "accuracy_diagnostic"


class AccuracyCompareInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_dir: str = Field(
        ...,
        description=(
            "Absolute path to a finished Case directory containing verdict.json "
            "(the run's scoped Verdict + Findings)."
        ),
    )
    golden_path: str | None = Field(
        default=None,
        description=(
            "Optional explicit path to the ground-truth golden "
            "(goldens/<case-id>/expected-findings.json, or its parent dir). When "
            "omitted, the golden is resolved from the verdict.json case_id under "
            "the repo's goldens/ directory."
        ),
    )
    audit_log_path: str | None = Field(
        default=None,
        description=(
            "Optional absolute path to the Case audit.jsonl. When given, a single "
            "non-Finding 'accuracy_diagnostic' record (scalar scores only) is "
            "appended to the hash chain. This tool NEVER emits a finding_approved "
            "record — it is a diagnostic, not a Finding."
        ),
    )
    coverage_manifest_path: str | None = Field(
        default=None,
        description=(
            "Optional path to coverage_manifest.json. Reserved for cross-checking "
            "scored artifact classes against attempted/parsed coverage; not "
            "required for scoring."
        ),
    )


class AccuracyCompareOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str | None
    case_dir: str
    golden: str
    expected_n: int
    recalled_n: int
    recall_percent: int
    min_recall_percent: int
    run_finding_n: int
    extra_n: int
    false_positives_n: int
    fp_planted: int
    precision_percent: int
    precision_scored: bool
    exhaustive: bool
    f1: float
    hallucination_rate: float
    negative_coverage: dict[str, Any]
    validation_class: str = Field(
        ...,
        description=(
            "Epistemic class of the golden's corpus: 'synthetic', "
            "'public-documented', or 'held-out'. Drives contamination_caveat."
        ),
    )
    corpus_identity: str = Field(
        ...,
        description="Short corpus label for the report ('synthetic' | 'public' | 'held-out').",
    )
    contamination_caveat: str = Field(
        ...,
        description=(
            "Non-empty ONLY for a public-documented corpus: the case is a published "
            "walkthrough whose answer may be in model training data, so recall here "
            "can reflect memorization, not from-scratch detection. Empty otherwise."
        ),
    )
    does_not_measure: list[str] = Field(
        ...,
        description=(
            "Scope caveats: what this accuracy score does NOT measure (custody "
            "integrity, generalization, absent artifact classes, train-set recall)."
        ),
    )
    run_verdict: str | None
    golden_verdict: str | None
    verdict_match: bool
    # ``pass`` is a Python keyword, so the wire field is ``pass`` via alias.
    pass_: bool = Field(..., alias="pass")
    matched: list[dict[str, Any]]
    unmatched: list[dict[str, Any]]
    extra: list[dict[str, Any]]
    false_positives: list[dict[str, Any]]
    planted_bait: list[dict[str, Any]]
    audit_record_kind: str | None = Field(
        default=None,
        description=(
            "Kind of the audit record appended ('accuracy_diagnostic'), or null "
            "when no audit_log_path was given. Never 'finding_approved'."
        ),
    )
    cache_key: str = Field(
        ...,
        description=(
            "Content-addressed sha256 of the exact inputs that determine this score "
            "(the run's verdict.json + the golden). Identical inputs replay this key "
            "bit-identically; any drift in verdict.json or the golden flips it, so a "
            "'live' number can only be replayed when it ties to the same artifacts."
        ),
    )


def _resolve_golden(case_dir: Path, override: str | None) -> Path | None:
    """Resolve the golden without depending on the process CWD.

    The shared ``resolve_golden`` looks under a relative ``goldens/`` directory.
    An MCP server's CWD is not guaranteed to be the repo root, so when no explicit
    override is given we also try the repo's ``goldens/`` resolved from this
    module's location (services/agent_mcp/.../tools -> repo root).
    """
    found = resolve_golden(case_dir, override)
    if found is not None or override is not None:
        return found
    # Fallback: anchor goldens/ at the repo root relative to this file.
    repo_root = Path(__file__).resolve().parents[4]
    verdict = case_dir / "verdict.json"
    if not verdict.is_file():
        return None
    try:
        import json

        cid = json.loads(verdict.read_text(encoding="utf-8")).get("case_id")
    except (OSError, ValueError):
        cid = None
    if cid:
        cand = repo_root / "goldens" / str(cid) / "expected-findings.json"
        if cand.is_file():
            return cand
    return None


async def _handle(inp: BaseModel) -> AccuracyCompareOutput:
    assert isinstance(inp, AccuracyCompareInput)
    case_dir = Path(inp.case_dir)
    if not (case_dir / "verdict.json").is_file():
        raise FileNotFoundError(f"{case_dir}/verdict.json not found")

    golden_path = _resolve_golden(case_dir, inp.golden_path)
    if golden_path is None:
        raise FileNotFoundError(
            f"no expected-findings.json golden found for {case_dir}; pass golden_path explicitly"
        )

    result = score(case_dir, golden_path)
    # Content-addressed key over the exact scored inputs. The scoring math is
    # unchanged — this only ties the returned number to specific artifacts so a
    # hand-edited verdict.json or swapped golden produces a different key.
    score_cache_key = cache_key(case_dir, golden_path)

    audit_record_kind: str | None = None
    if inp.audit_log_path:
        # Append a NON-Finding diagnostic record. Scalar scores only — no
        # finding_id / tool_call_id, so it can never be mistaken for or satisfy a
        # Finding citation.
        payload = {
            "case_id": result["case_id"],
            "case_dir": result["case_dir"],
            "golden": result["golden"],
            "expected_n": result["expected_n"],
            "recalled_n": result["recalled_n"],
            "recall_percent": result["recall_percent"],
            "precision_percent": result["precision_percent"],
            "f1": result["f1"],
            "hallucination_rate": result["hallucination_rate"],
            "fp_planted": result["fp_planted"],
            "negative_coverage": result["negative_coverage"],
            "verdict_match": result["verdict_match"],
            "pass": result["pass"],
        }
        AuditLog(Path(inp.audit_log_path)).append(DIAGNOSTIC_KIND, payload)
        audit_record_kind = DIAGNOSTIC_KIND

    return AccuracyCompareOutput(
        case_id=result["case_id"],
        case_dir=result["case_dir"],
        golden=result["golden"],
        expected_n=result["expected_n"],
        recalled_n=result["recalled_n"],
        recall_percent=result["recall_percent"],
        min_recall_percent=result["min_recall_percent"],
        run_finding_n=result["run_finding_n"],
        extra_n=result["extra_n"],
        false_positives_n=result["false_positives_n"],
        fp_planted=result["fp_planted"],
        precision_percent=result["precision_percent"],
        precision_scored=result["precision_scored"],
        exhaustive=result["exhaustive"],
        f1=result["f1"],
        hallucination_rate=result["hallucination_rate"],
        negative_coverage=result["negative_coverage"],
        validation_class=result["validation_class"],
        corpus_identity=result["corpus_identity"],
        contamination_caveat=result["contamination_caveat"],
        does_not_measure=result["does_not_measure"],
        run_verdict=result["run_verdict"],
        golden_verdict=result["golden_verdict"],
        verdict_match=result["verdict_match"],
        **{"pass": result["pass"]},
        matched=result["matched"],
        unmatched=result["unmatched"],
        extra=result["extra"],
        false_positives=result["false_positives"],
        planted_bait=result["planted_bait"],
        audit_record_kind=audit_record_kind,
        cache_key=score_cache_key,
    )


SPEC = ToolSpec(
    name="accuracy_compare",
    description=(
        "Read-only ground-truth ACCURACY DIAGNOSTIC for a finished Case. Scores the "
        "run's verdict.json against a curated golden (goldens/<id>/"
        "expected-findings.json) and returns TP/FP/FN counts, precision / recall / "
        "F1, hallucination_rate, verdict consistency, and negative-assertion "
        "coverage (the planted-bait claims a correct run must NOT assert). "
        "Matching is description-token coverage, not byte-equality, so a verbose-"
        "but-correct run finding still scores against a concise ground-truth claim. "
        "This is a DIAGNOSTIC, NEVER a Finding: it does not emit finding_approved "
        "and never satisfies a Finding citation (optional scoring sidecars are not "
        "evidence). When audit_log_path is given, it appends exactly one non-Finding "
        "'accuracy_diagnostic' record (scalar scores only) to the hash chain so the "
        "score is attestable. Inputs: case_dir (required, has verdict.json), "
        "golden_path (optional override), audit_log_path (optional, to record the "
        "diagnostic). On error: verdict.json or the golden was not found — pass "
        "golden_path explicitly."
    ),
    input_model=AccuracyCompareInput,
    output_model=AccuracyCompareOutput,
    handler=_handle,
)

__all__ = ["DIAGNOSTIC_KIND", "SPEC", "AccuracyCompareInput", "AccuracyCompareOutput"]
