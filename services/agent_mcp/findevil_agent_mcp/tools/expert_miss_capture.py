"""``expert_miss_capture`` tool — append expert edits to the miss ledger."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from pathlib import Path
from typing import Literal

from findevil_agent.crypto.audit_log import AuditLog
from pydantic import BaseModel, ConfigDict, Field, field_validator

from findevil_agent_mcp.tools._base import ToolSpec

EditType = Literal["connector", "playbook", "rule", "qa", "escalation", "language"]


class ExpertMissCaptureInput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    case_id: str = Field(..., min_length=1)
    finding_id: str | None = Field(default=None)
    edit_type: EditType
    edit_text: str = Field(..., min_length=1, max_length=4000)
    expert_name: str | None = Field(default=None)
    ledger_path: str = Field(..., description="Absolute path to expert_misses.jsonl.")

    @field_validator("ledger_path")
    @classmethod
    def _ledger_path_is_absolute(cls, value: str) -> str:
        if not Path(value).is_absolute():
            raise ValueError("ledger_path must be absolute")
        return value


class ExpertMissCaptureOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    seq: int
    ts: str
    line_hash: str
    prev_hash: str
    github_issue_url: str | None


def _github_case_label(case_id: str) -> str:
    if os.environ.get("FINDEVIL_MISS_GH_REDACT") == "1":
        digest = hashlib.sha256(case_id.encode("utf-8")).hexdigest()[:12]
        return f"case_sha256_prefix={digest}"
    return f"case_id={case_id}"


def _maybe_create_github_issue(args: ExpertMissCaptureInput) -> str | None:
    if os.environ.get("FINDEVIL_MISS_GH_ENABLED") != "1":
        return None
    gh = shutil.which("gh")
    if gh is None:
        return None

    case_label = _github_case_label(args.case_id)
    title = f"Expert miss: {args.edit_type} for {case_label}"
    body_lines = [
        f"Edit type: {args.edit_type}",
        f"Case: {case_label}",
        f"Finding: {args.finding_id or 'case-level'}",
        f"Expert: {args.expert_name or 'unspecified'}",
        "",
        args.edit_text,
    ]
    try:
        result = subprocess.run(
            [
                gh,
                "issue",
                "create",
                "--label",
                f"miss/{args.edit_type}",
                "--title",
                title,
                "--body",
                "\n".join(body_lines),
            ],
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    url = result.stdout.strip().splitlines()[0] if result.stdout.strip() else ""
    return url if url.startswith(("http://", "https://")) else None


async def _handle(inp: BaseModel) -> ExpertMissCaptureOutput:
    assert isinstance(inp, ExpertMissCaptureInput)
    payload = {
        "case_id": inp.case_id,
        "finding_id": inp.finding_id,
        "edit_type": inp.edit_type,
        "edit_text": inp.edit_text,
        "expert_name": inp.expert_name,
    }
    log = AuditLog(Path(inp.ledger_path))
    record = log.append("expert_miss", payload)
    github_issue_url = _maybe_create_github_issue(inp)
    return ExpertMissCaptureOutput(
        seq=record.seq,
        ts=record.ts,
        line_hash=log.last_hash,
        prev_hash=record.prev_hash,
        github_issue_url=github_issue_url,
    )


SPEC = ToolSpec(
    name="expert_miss_capture",
    description=(
        "Record a human expert's required correction to the auto-drafted report as a "
        "hash-chained kind='expert_miss' ledger entry. Use before shipping a corrected "
        "packet whenever the expert changes the PDF for connector, playbook, rule, QA, "
        "escalation, or language reasons. The ledger_path must be an absolute path to "
        "expert_misses.jsonl. If FINDEVIL_MISS_GH_ENABLED=1 and gh is on PATH, the tool "
        "also attempts to open a GitHub issue labeled miss/<edit_type>; GitHub failure "
        "does not fail the capture."
    ),
    input_model=ExpertMissCaptureInput,
    output_model=ExpertMissCaptureOutput,
    handler=_handle,
)

__all__ = [
    "SPEC",
    "ExpertMissCaptureInput",
    "ExpertMissCaptureOutput",
]
