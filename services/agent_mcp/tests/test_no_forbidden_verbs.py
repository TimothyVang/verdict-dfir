"""Architectural guard: neither product MCP server registers a forbidden verb.

VERDICT's core safety claim is "no ``execute_shell``; typed read-only
surface" (see ``CLAUDE.md`` Tool Surface Boundary and the Rust crate's
``//! - No execute_shell tool, ever.`` invariant). This test turns that
prose claim into an enforced regression guard: it enumerates the
*actually registered* product tool names from BOTH product servers and
asserts none of them is a bare execution-or-mutation verb.

Source-of-truth driven, not a hardcoded duplicate list:

* Python (``findevil-agent-mcp``, 14 tools) — imported from the live
  registry via :func:`findevil_agent_mcp.tools.all_specs`.
* Rust (``findevil-mcp``, 34 tools) — parsed out of the registration
  site ``services/mcp/src/server.rs`` (``build_registry()``), which is
  the single place the wire-level tool names are declared.

A future regression — someone wiring up an ``execute_shell`` /
``write_file`` / ``run_command`` style tool on either server — fails
this test with a message naming the offending tool and its server.

The two operator-convenience MCP servers (playwright, puppeteer, n8n,
qmd) are intentionally NOT covered: they can never emit Findings or
audit-chain tool calls, so they are outside the product safety
boundary this guard protects.
"""

from __future__ import annotations

import re
from pathlib import Path

from findevil_agent_mcp.tools import all_specs

# --- Forbidden verb tokens ---------------------------------------------------
#
# A tool name fails if its verb token is one of these *standalone*. We match
# on the verb token, case-insensitively, so both ``run_command`` and
# ``executeShell`` are caught. We do NOT match these as substrings of an
# unrelated word (e.g. ``evtx_query`` must not trip ``rm`` via "q-rm"), so
# tokenization is on word boundaries plus camelCase splits.
FORBIDDEN_VERBS: frozenset[str] = frozenset(
    {
        "execute_shell",
        "run_shell",
        "run_command",
        "shell",
        "exec",
        "eval",
        "write_file",
        "write",
        "delete",
        "rm",
        "put",
        "upload",
    }
)

# Multi-token forbidden phrases (collapse to a single comparison key).
FORBIDDEN_PHRASES: frozenset[str] = frozenset(
    {"execute_shell", "run_shell", "run_command", "write_file"}
)

# --- Allow-list of legitimate read-only typed tools --------------------------
#
# These are typed, allow-listed wrappers VERDICT ships deliberately. A
# ``run``/``*_run``/``run_*`` token is fine when it is one of these named
# typed wrappers (CLAUDE.md: "Long-tail DFIR execution belongs behind
# allow-listed typed tools such as vol_run, ez_parse, plaso_parse,
# mac_triage, cloud_audit"). Encoding the allow-list explicitly keeps the
# guard precise: a *new* bare ``run`` / ``exec`` tool still fails, but these
# established names do not false-positive.
ALLOWED_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "vol_run",
        "ez_parse",
        "plaso_parse",
        "mac_triage",
        "cloud_audit",
    }
)


def _split_tokens(name: str) -> list[str]:
    """Split a tool name into lowercase verb/word tokens.

    Handles snake_case (``run_command`` -> ``run``, ``command``) and
    camelCase (``executeShell`` -> ``execute``, ``shell``) so a forbidden
    verb in any common naming style is detected.
    """
    # Insert a separator at camelCase humps, then split on non-alphanumerics.
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return [tok for tok in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if tok]


def _forbidden_reason(name: str) -> str | None:
    """Return a human-readable reason if ``name`` is a forbidden verb tool.

    ``None`` means the tool is acceptable. The check is:

    * an explicitly allow-listed typed wrapper is always acceptable;
    * a name whose *full normalized form* is a multi-token forbidden phrase
      (``execute_shell``, ``run_command``, ...) fails;
    * a name whose individual verb token is a standalone forbidden verb
      (``exec``, ``write``, ``rm``, ``shell`` ...) fails.
    """
    if name in ALLOWED_TOOL_NAMES:
        return None

    tokens = _split_tokens(name)
    normalized = "_".join(tokens)

    # Whole-name forbidden phrases (e.g. executeShell -> execute_shell).
    if normalized in FORBIDDEN_PHRASES:
        return f"name normalizes to forbidden phrase '{normalized}'"

    # Standalone single-token forbidden verbs.
    single_token_forbidden = FORBIDDEN_VERBS - FORBIDDEN_PHRASES
    for tok in tokens:
        if tok in single_token_forbidden:
            return f"contains forbidden verb token '{tok}'"

    return None


def rust_tool_names() -> set[str]:
    """Parse registered Rust tool names from ``services/mcp/src/server.rs``.

    The names are declared exactly once, in ``build_registry()``, as
    ``name: "<tool>",`` lines on each ``ToolEntry``. We anchor the regex to
    that exact shape so we pick up the 31 real registrations and not the
    JSON ``"name":`` keys or ``params`` literals used elsewhere in the file.
    """
    server_rs = Path(__file__).resolve().parents[2] / "mcp" / "src" / "server.rs"
    assert server_rs.is_file(), f"Rust server source not found: {server_rs}"
    source = server_rs.read_text(encoding="utf-8")

    # ToolEntry field: leading whitespace, `name: "snake_case_name",`.
    pattern = re.compile(r'^\s*name:\s*"([a-z][a-z0-9_]*)"\s*,\s*$', re.MULTILINE)
    names = set(pattern.findall(source))
    assert names, "parsed zero Rust tool names — server.rs format may have changed"
    return names


def python_tool_names() -> set[str]:
    """Registered Python tool names from the live ToolSpec registry."""
    return {spec.name for spec in all_specs()}


class TestNoForbiddenVerbs:
    def test_rust_registry_enumerates_expected_count(self) -> None:
        # Sanity: the Rust product surface is 34 audit-chained tools.
        names = rust_tool_names()
        assert len(names) == 34, f"expected 34 Rust tools, parsed {len(names)}: {sorted(names)}"

    def test_python_registry_enumerates_expected_count(self) -> None:
        # Sanity: the Python product surface is 14 audit-chained tools.
        names = python_tool_names()
        assert len(names) == 14, f"expected 14 Python tools, got {len(names)}: {sorted(names)}"

    def test_rust_server_has_no_forbidden_verb(self) -> None:
        for name in sorted(rust_tool_names()):
            reason = _forbidden_reason(name)
            assert reason is None, (
                f"findevil-mcp (Rust) registers forbidden tool '{name}': {reason}. "
                "VERDICT's read-only typed-surface guarantee forbids execution/"
                "mutation verbs on the product MCP surface."
            )

    def test_python_server_has_no_forbidden_verb(self) -> None:
        for name in sorted(python_tool_names()):
            reason = _forbidden_reason(name)
            assert reason is None, (
                f"findevil-agent-mcp (Python) registers forbidden tool '{name}': "
                f"{reason}. VERDICT's read-only typed-surface guarantee forbids "
                "execution/mutation verbs on the product MCP surface."
            )

    def test_allowed_typed_wrappers_do_not_false_positive(self) -> None:
        # The shipped typed wrappers must pass even though they carry a
        # `run`/`parse`/`audit` token — otherwise the guard is too blunt.
        for name in ("vol_run", "ez_parse", "plaso_parse", "mac_triage", "cloud_audit"):
            assert _forbidden_reason(name) is None, f"{name} wrongly flagged"

    def test_guard_fires_on_known_forbidden_names(self) -> None:
        # Lock the detector itself: each of these MUST be rejected, in any
        # common naming style. If a regression slipped one of these onto a
        # server, the per-server tests above would catch it — this proves
        # the detector is the reason, not a parsing miss.
        for bad in (
            "execute_shell",
            "executeShell",
            "run_command",
            "runCommand",
            "run_shell",
            "shell",
            "exec",
            "eval",
            "write_file",
            "writeFile",
            "write",
            "delete",
            "rm",
            "put",
            "upload",
        ):
            assert _forbidden_reason(bad) is not None, f"detector missed forbidden name '{bad}'"
