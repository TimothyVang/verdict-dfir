"""Planted AI-integration artifact detection -> ai_assessment degree AI-present.

The medium-volt pack plants an AI-helper (collect_helper.ps1 with an embedded
provider key + a prompt-as-code, and a ~/.ollama/history local-LLM disk trace).
The oracle expects ai_assessment.degree == "AI-present" and forbids
"AI-orchestrated" (seeded ai_writing_style / slopsquatted_dep_name decoys must
not raise the degree). assess_ai_helper is a pure function over [{path, text}].
"""

from __future__ import annotations

import sys
from pathlib import Path

_SCRIPTS = Path(__file__).resolve().parents[3] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import find_evil_auto as fea  # noqa: E402

_PS1 = (
    '# helper\n$ApiKey = "sk-ant-api03-LABONLY-NOT-A-REAL-KEY-0000000000"\n'
    '$PromptAsCode = "You are a DFIR helper. Summarize enumeration steps."\n'
    '$DecoyPackage = "reqeusts"\n'
)
_OLLAMA = "# trace\n>>> summarize lateral movement indicators\n>>> draft a portproxy command\n"


def test_ai_helper_files_yield_ai_present() -> None:
    files = [
        {"path": "C_temp/collect_helper.ps1", "text": _PS1},
        {"path": "Users/Public/.ollama/history", "text": _OLLAMA},
    ]
    a = fea.assess_ai_helper(files)
    assert a is not None
    assert a["degree"] == "AI-present"
    assert a["present"] is True
    inds = set(a["indicators"])
    assert "embedded_api_key" in inds
    assert "prompts_as_code" in inds
    assert "local_llm_disk_trace" in inds


def test_never_emits_ai_orchestrated() -> None:
    # even with the seeded slopsquat/writing-style decoys present, degree must
    # never be AI-orchestrated.
    files = [{"path": "C_temp/collect_helper.ps1", "text": _PS1}]
    a = fea.assess_ai_helper(files)
    assert a is None or a["degree"] != "AI-orchestrated"


def test_decoy_only_does_not_assert_ai() -> None:
    # a file with only a slopsquatted dep name (no real AI integration) must not
    # by itself produce an AI assessment.
    files = [{"path": "notes.txt", "text": 'pkg = "reqeusts"  # looks AI-ish\n'}]
    a = fea.assess_ai_helper(files)
    assert a is None or a["degree"] != "AI-orchestrated"


def test_no_ai_files_returns_none() -> None:
    assert fea.assess_ai_helper([{"path": "readme.txt", "text": "nothing here"}]) is None
