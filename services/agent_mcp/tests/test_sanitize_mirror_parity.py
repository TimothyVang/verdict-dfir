"""Mirror-EQUIVALENCE test for the two MCP-output sanitizers.

The evidence-content sanitizer exists in two hand-maintained mirrors that must
neutralize the *identical* set of chat/role control tokens and strip the
*identical* set of invisible/BIDI (Trojan-Source) Unicode code points:

  - Rust:   ``services/mcp/src/sanitize.rs``         (findevil-mcp boundary)
  - Python: ``findevil_agent_mcp.sanitize``          (findevil-agent-mcp boundary)

Until now the two were kept in sync only by review. A control token or an
invisible-codepoint range added to one mirror but not the other would diverge
silently: one MCP surface would neutralize an injection the other would let
through, and a ``verify_finding`` replay across surfaces would stop reproducing
the same ``output_sha256``. This test fails the moment either mirror gains or
loses a token or a code point the other does not.

The Python mirror exposes ``ROLE_TOKENS`` and ``_is_invisible`` as importable
symbols, so its sets are read directly. The Rust mirror has no Python-importable
surface, so its sets are parsed out of the ``sanitize.rs`` source text (the token
tuple list and the ``matches!`` code-point arms). Parsing the source -- rather
than refactoring either module -- is deliberate: the test must keep working
without touching production code.
"""

from __future__ import annotations

import pathlib
import re

from findevil_agent_mcp.sanitize import ROLE_TOKENS, _is_invisible

# services/agent_mcp/tests/ -> services/mcp/src/sanitize.rs
_RUST_SANITIZE = pathlib.Path(__file__).resolve().parents[2] / "mcp" / "src" / "sanitize.rs"

# Scan the whole Basic Multilingual Plane when deriving a mirror's stripped set
# from a predicate or a parsed range list. Every code point either mirror strips
# today (BIDI controls, zero-width chars, BOM) lives well inside this bound; a
# new arm anywhere in the BMP is still caught by the comparison.
_BMP_MAX = 0xFFFF


# --------------------------------------------------------------------------- #
# Rust source parsing
# --------------------------------------------------------------------------- #
def _rust_source() -> str:
    assert _RUST_SANITIZE.is_file(), f"Rust mirror not found at {_RUST_SANITIZE}"
    return _RUST_SANITIZE.read_text(encoding="utf-8")


def _rust_role_tokens(source: str) -> set[tuple[str, str]]:
    """Extract the ``(id, token)`` pairs from the Rust ``ROLE_TOKENS`` slice.

    Returns a set of ``(id, lowercased_token)`` pairs so it compares directly
    against the Python tuple (whose tokens are already stored lowercase).
    """
    block = re.search(
        r"const\s+ROLE_TOKENS\s*:[^=]*=\s*&\[(.*?)\];",
        source,
        re.DOTALL,
    )
    assert block is not None, "could not locate ROLE_TOKENS slice in sanitize.rs"

    pairs = re.findall(r'\(\s*"([^"]*)"\s*,\s*"([^"]*)"\s*\)', block.group(1))
    assert pairs, "no (id, token) pairs parsed from Rust ROLE_TOKENS"
    return {(token_id, token.lower()) for token_id, token in pairs}


def _rust_invisible_codepoints(source: str) -> set[int]:
    """Derive the set of code points stripped by the Rust ``is_invisible_control``.

    Parses the ``matches!`` arms -- inclusive ranges ``0xAAAA..=0xBBBB`` and bare
    ``0xNNNN`` literals -- and expands them into an explicit code-point set so it
    can be compared element-by-element against the Python predicate, independent
    of how each mirror happens to spell its ranges.
    """
    block = re.search(
        r"fn\s+is_invisible_control\s*\([^)]*\)\s*->\s*bool\s*\{(.*?)\n\}",
        source,
        re.DOTALL,
    )
    assert block is not None, "could not locate is_invisible_control in sanitize.rs"
    body = block.group(1)

    points: set[int] = set()

    # Inclusive ranges first: 0x202A..=0x202E
    for lo_hex, hi_hex in re.findall(r"0x([0-9A-Fa-f]+)\s*\.\.=\s*0x([0-9A-Fa-f]+)", body):
        lo, hi = int(lo_hex, 16), int(hi_hex, 16)
        points.update(range(lo, hi + 1))

    # Then any remaining bare literals (e.g. 0x2060, 0xFEFF). Strip the range
    # literals already consumed so their endpoints are not double-counted as
    # singletons (harmless, but keeps the parse honest).
    range_free = re.sub(r"0x[0-9A-Fa-f]+\s*\.\.=\s*0x[0-9A-Fa-f]+", "", body)
    for lit_hex in re.findall(r"0x([0-9A-Fa-f]+)", range_free):
        points.add(int(lit_hex, 16))

    assert points, "no invisible code points parsed from Rust matches! arms"
    return points


# --------------------------------------------------------------------------- #
# Python mirror introspection
# --------------------------------------------------------------------------- #
def _python_role_tokens() -> set[tuple[str, str]]:
    return {(token_id, token) for token_id, token in ROLE_TOKENS}


def _python_invisible_codepoints() -> set[int]:
    """The set of BMP code points the Python ``_is_invisible`` predicate strips."""
    return {cp for cp in range(_BMP_MAX + 1) if _is_invisible(cp)}


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_role_token_sets_are_identical_across_mirrors() -> None:
    """Both mirrors neutralize exactly the same chat/role control tokens."""
    rust = _rust_role_tokens(_rust_source())
    python = _python_role_tokens()

    only_rust = rust - python
    only_python = python - rust
    assert rust == python, (
        "ROLE_TOKENS diverged between the Rust and Python sanitizer mirrors.\n"
        f"  present only in sanitize.rs (Rust): {sorted(only_rust)}\n"
        f"  present only in sanitize.py (Python): {sorted(only_python)}\n"
        "Keep services/mcp/src/sanitize.rs and "
        "services/agent_mcp/findevil_agent_mcp/sanitize.py in lock-step."
    )


def test_invisible_codepoint_sets_are_identical_across_mirrors() -> None:
    """Both mirrors strip exactly the same invisible/BIDI Unicode code points."""
    rust = _rust_invisible_codepoints(_rust_source())
    python = _python_invisible_codepoints()

    only_rust = sorted(hex(cp) for cp in (rust - python))
    only_python = sorted(hex(cp) for cp in (python - rust))
    assert rust == python, (
        "Invisible/BIDI code-point coverage diverged between the Rust and "
        "Python sanitizer mirrors.\n"
        f"  stripped only by sanitize.rs (Rust): {only_rust}\n"
        f"  stripped only by sanitize.py (Python): {only_python}\n"
        "Keep the Trojan-Source code-point ranges identical in both mirrors."
    )


def test_parsers_actually_found_the_expected_anchors() -> None:
    """Guard the test itself: a structural rename of either mirror that defeats
    the source parse would otherwise let real divergence pass as an empty-set
    match. Assert the parsed sets are non-trivial and contain known anchors."""
    source = _rust_source()
    rust_tokens = _rust_role_tokens(source)
    rust_points = _rust_invisible_codepoints(source)

    # Anchors that must always be present in a working sanitizer.
    assert ("im_start", "<|im_start|>") in rust_tokens
    assert ("inst_close", "[/inst]") in rust_tokens
    assert len(rust_tokens) >= 8, "implausibly small parsed Rust token set"

    assert 0x202E in rust_points  # RLO (right-to-left override)
    assert 0x200B in rust_points  # ZWSP (zero-width space)
    assert 0xFEFF in rust_points  # BOM / zero-width no-break space
    assert 0x2069 in rust_points  # PDI (isolate, upper end of 0x2066..=0x2069)
