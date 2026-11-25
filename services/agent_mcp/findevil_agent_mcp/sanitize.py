"""Evidence-content sanitizer for the Python MCP output boundary.

The Python mirror of ``services/mcp/src/sanitize.rs``. The agent-mcp tools
synthesize findings whose text can embed evidence quotes; before that text is
serialized to the model it is neutralized here:

  - chat/role control tokens (``<|im_start|>``, ``[INST]``, ``<<SYS>>``, ...) are
    replaced with an inert ``[neutralized:<id>]`` marker, matched
    case-insensitively; and
  - invisible Unicode that reorders or hides text (BIDI overrides/isolates/marks
    and zero-width code points -- the Trojan Source class) is removed.

Invisible characters are stripped *before* token matching so an attacker cannot
split a control token with a zero-width character to evade it. Only string
values are touched; numbers, booleans, ``None`` and dict keys are left intact, so
tool-derived metadata (hashes, counts, enums, timestamps, ids) is never mangled.
Sanitization is deterministic.
"""

from __future__ import annotations

from typing import Any

# Chat/role control tokens used by major chat templates, stored lowercase for
# case-insensitive matching. Replaced with ``[neutralized:<id>]``.
ROLE_TOKENS: tuple[tuple[str, str], ...] = (
    ("im_start", "<|im_start|>"),
    ("im_end", "<|im_end|>"),
    ("im_sep", "<|im_sep|>"),
    ("eot_id", "<|eot_id|>"),
    ("start_header_id", "<|start_header_id|>"),
    ("end_header_id", "<|end_header_id|>"),
    ("endoftext", "<|endoftext|>"),
    ("inst_open", "[inst]"),
    ("inst_close", "[/inst]"),
    ("sys_open", "<<sys>>"),
    ("sys_close", "<</sys>>"),
)


def _is_invisible(cp: int) -> bool:
    """Invisible Unicode with no legitimate role in forensic *text*."""
    return (
        0x202A <= cp <= 0x202E  # LRE RLE PDF LRO RLO
        or 0x2066 <= cp <= 0x2069  # LRI RLI FSI PDI
        or 0x200B <= cp <= 0x200F  # ZWSP ZWNJ ZWJ LRM RLM
        or cp == 0x2060  # word joiner
        or cp == 0xFEFF  # BOM / zero-width no-break space
    )


def _bump(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def sanitize_str(text: str, counts: dict[str, int]) -> str:
    """Neutralize one string: strip invisible code points, then role tokens."""
    # 1) Remove invisible/control code points first, so a token cannot be split
    #    by a zero-width character to evade step 2.
    kept: list[str] = []
    for ch in text:
        if _is_invisible(ord(ch)):
            _bump(counts, "invisible_unicode")
        else:
            kept.append(ch)
    stripped = "".join(kept)

    # 2) Replace chat/role control tokens (case-insensitive) with an inert marker.
    lower = stripped.lower()
    out: list[str] = []
    i = 0
    n = len(stripped)
    while i < n:
        matched = False
        for token_id, token in ROLE_TOKENS:
            if lower.startswith(token, i):
                out.append(f"[neutralized:{token_id}]")
                _bump(counts, token_id)
                i += len(token)
                matched = True
                break
        if not matched:
            out.append(stripped[i])
            i += 1
    return "".join(out)


def _walk(value: Any, counts: dict[str, int]) -> Any:
    if isinstance(value, str):
        return sanitize_str(value, counts)
    if isinstance(value, list):
        return [_walk(v, counts) for v in value]
    if isinstance(value, dict):
        return {k: _walk(v, counts) for k, v in value.items()}
    return value


def sanitize_value(value: Any) -> tuple[Any, dict[str, int]]:
    """Sanitize every string in a JSON-like value.

    Returns ``(sanitized_value, counts)`` where ``counts`` maps each pattern id
    (a role-token id or ``invisible_unicode``) to how many times it was
    neutralized. The payload itself is never recorded -- only counts -- so a log
    of ``counts`` cannot re-leak the injection attempt. Non-string nodes
    (numbers, booleans, ``None``) and dict keys are returned unchanged.
    """
    counts: dict[str, int] = {}
    return _walk(value, counts), counts
