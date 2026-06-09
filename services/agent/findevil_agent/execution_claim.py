"""Single source of truth for "is this Finding an execution claim?".

Two gates ask this question and MUST agree, or a finding can pass one while the
other would flag it:

- ``correlator._is_execution_claim`` — the verdict-time SOUL.md gate that
  downgrades execution claims lacking >=2 artifact classes (runs under the 3.11+
  agent venv).
- ``find_evil_auto._claims_execution`` — the report-QA gate that blocks the
  customer PDF on uncorroborated execution wording (runs inline under the bare
  3.10 host engine, which cannot import ``findevil_agent`` — the "3.10-engine
  import trap").

Because of that import split the engine cannot import this module at runtime; it
inlines a byte-identical mirror of the token set + MITRE prefixes below, and
``tests/test_execution_claim.py`` imports the engine module under the agent venv
and asserts the two predicates agree on a battery of cases. This module is the
canonical definition; the engine mirror and that parity test are the enforcement.

Pure stdlib, no I/O, deterministic. 3.10-compatible on purpose.
"""

from __future__ import annotations

import re

# MITRE ATT&CK technique prefixes that mark a Finding as an execution claim even
# when the prose carries no execution verb (e.g. a T1053 scheduled-task finding).
EXECUTION_MITRE_PREFIXES: tuple[str, ...] = (
    "T1059",  # Command and Scripting Interpreter
    "T1106",  # Native API
    "T1129",  # Shared Modules
    "T1203",  # Exploitation for Client Execution
    "T1543",  # Create or Modify System Process
    "T1547",  # Boot or Logon Autostart Execution
    "T1053",  # Scheduled Task/Job
)

# Execution verbs/phrases, word-boundary anchored so an "execute_shell" mention
# inside a narrative block does not accidentally trigger. This is the UNION of
# what both gates historically matched, so neither under- nor over-detects
# relative to the other.
EXECUTION_TOKENS: tuple[str, ...] = (
    r"\bexecut(?:ed|ion|ing)\b",
    r"\bran\b",
    r"\brun count\b",
    r"\bprocess creation\b",
    r"\binvok(?:ed|ation|ing)\b",
    r"\blaunch(?:ed|ing)\b",
    r"\bspawn(?:ed|ing)\b",
    r"\bstarted\b",
)
EXECUTION_RE = re.compile("|".join(EXECUTION_TOKENS), re.IGNORECASE)


def text_claims_execution(text: str | None) -> bool:
    """True if the prose contains an execution verb/phrase."""
    return bool(text and EXECUTION_RE.search(text))


def mitre_claims_execution(mitre_technique: str | None) -> bool:
    """True if the MITRE technique id is an execution technique."""
    return bool(mitre_technique and mitre_technique.startswith(EXECUTION_MITRE_PREFIXES))


def is_execution_claim(text: str | None, mitre_technique: str | None = None) -> bool:
    """Unified execution-claim predicate: execution prose OR an execution MITRE id."""
    return text_claims_execution(text) or mitre_claims_execution(mitre_technique)
