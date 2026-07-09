"""AI / agent tradecraft signature scanning — HYPOTHESIS-tier leads only.

DFIR question this answers: *was an LLM-assisted tool or an autonomous agent
framework involved in producing or staging an artifact on this host?* The
answer is never a conclusion. Every match is a **HYPOTHESIS-tier LEAD**: a
pointer worth corroborating, never proof of execution and never an attribution.

This is the domain half of the ``find_ai_signatures`` typed MCP tool (the
protocol shim lives in ``services/agent_mcp``). It is pure, deterministic, and
read-only — it scans text the caller supplies, or reads text artifacts the
caller names (open-for-read only; never writes, never mutates evidence).

Evidence-agnostic by construction: the signature list keys on **general** LLM /
agent tradecraft patterns (output boilerplate, agent-framework module names,
the ReAct scratchpad shape, LLM API-client fingerprints, prompt scaffolding,
model-family identifiers). There are no image-specific literals — no usernames,
hostnames, image names, or golden IDs. Add a new general pattern by appending
to ``_SIGNATURE_TABLE``; the curated list is the single source of truth.

Epistemic contract (mirrors SOUL.md / CLAUDE.md guardrails):

* Matches are LEADS at the ``HYPOTHESIS`` tier — they carry no ``tool_call_id``
  weight beyond a normal product-tool call, never upgrade a finding's
  confidence, and never satisfy the >=2-artifact-class corroboration gate on
  their own.
* A match is NOT execution evidence. AI-authored text on disk does not show the
  tool ran; pair it with an independent artifact class before any execution
  claim, exactly as CLAUDE.md requires.
* Detections are about *tooling/authorship fingerprints*, never actor identity,
  intent, or legal status.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Epistemic tier every match is pinned to. Exposed so the shim and the report
# layer cannot accidentally promote a lead to a higher tier.
CONFIDENCE_TIER = "HYPOTHESIS"

# Single-sentence epistemic envelope surfaced alongside the matches so a reader
# (or a pool drafting a finding) cannot mistake a lead for a conclusion.
LEAD_DISCLAIMER = (
    "AI/agent tradecraft signatures are HYPOTHESIS-tier LEADS only: they suggest "
    "LLM-assisted tooling or an agent framework was involved, never that anything "
    "executed and never an attribution. Corroborate with an independent artifact "
    "class before raising confidence; a signature alone never satisfies the "
    ">=2-artifact-class execution gate."
)

# Bounds so a noisy artifact cannot blow the MCP token budget or memory.
DEFAULT_LIMIT = 500
DEFAULT_PREVIEW_CHARS = 80
MAX_PREVIEW_CHARS = 400
MAX_FILE_BYTES = 8_000_000


@dataclass(frozen=True)
class AiSignature:
    """One curated, general AI/agent tradecraft pattern.

    ``signature_id`` is a stable ``category.slug`` handle so downstream
    consumers can reference a specific lead without depending on the regex.
    """

    signature_id: str
    category: str
    description: str
    pattern: str


# ---------------------------------------------------------------------------
# Curated GENERAL signature table.
#
# Patterns are case-insensitive (compiled with re.IGNORECASE below). Multi-word
# phrases tolerate flexible internal whitespace via ``\s+``. Framework / SDK
# tokens intentionally allow a trailing word boundary-free match so a family
# member (``langchain_core``, ``llama_index.core``) still fires. None of these
# encode an image-specific value — they are the AI/agent analogue of a curated
# YARA/Sigma rule pack.
# ---------------------------------------------------------------------------
_SIGNATURE_TABLE: tuple[AiSignature, ...] = (
    # --- LLM output boilerplate left verbatim in an artifact -----------------
    AiSignature(
        "llm_output_boilerplate.language_model_persona",
        "llm_output_boilerplate",
        "LLM identity boilerplate ('as a/an (large )?(AI )?language model').",
        r"\bas\s+an?\s+(?:large\s+)?(?:ai\s+)?language\s+model\b",
    ),
    AiSignature(
        "llm_output_boilerplate.ai_assistant_persona",
        "llm_output_boilerplate",
        "AI-assistant self-reference ('as an AI assistant' / 'I am an AI').",
        r"\bas\s+an\s+ai\s+assistant\b|\bi\s+am\s+an\s+ai\b",
    ),
    AiSignature(
        "llm_output_boilerplate.refusal",
        "llm_output_boilerplate",
        "LLM refusal phrasing ('I cannot/can't assist|help with that').",
        r"\bi\s+(?:cannot|can'?t)\s+(?:assist|help)\s+with\s+that\b"
        r"|\bi'?m\s+sorry,?\s+but\s+i\s+(?:cannot|can'?t)\b"
        r"|\bi'?m\s+unable\s+to\s+(?:provide|assist|help)\b",
    ),
    AiSignature(
        "llm_output_boilerplate.knowledge_cutoff",
        "llm_output_boilerplate",
        "Training-recency disclaimer ('knowledge cutoff' / 'my training data').",
        r"\bknowledge\s+cut[\s-]?off\b|\bmy\s+training\s+data\b",
    ),
    # --- Agent framework artifacts (module / package fingerprints) -----------
    # Framework tokens anchor only the START with \b (no trailing boundary) so a
    # suffixed family member (``langchain_core``, ``llama_index.readers``,
    # ``autogen_agentchat``) still fires on the base name.
    AiSignature(
        "agent_framework.langchain",
        "agent_framework",
        "LangChain / LangGraph agent-framework module fingerprint.",
        r"\blang(?:chain|graph)",
    ),
    AiSignature(
        "agent_framework.llama_index",
        "agent_framework",
        "LlamaIndex agent/RAG framework module fingerprint.",
        r"\bllama[_-]?index",
    ),
    AiSignature(
        "agent_framework.autogpt",
        "agent_framework",
        "Auto-GPT / BabyAGI autonomous-agent project fingerprint.",
        # (?![a-z]) so a module suffix ('autogpt_workspace') fires but the
        # common word 'auto-generated' / plural 'gpts' does not.
        r"\bauto[\s-]?gpt(?![a-z])|\bbabyagi",
    ),
    AiSignature(
        "agent_framework.crewai",
        "agent_framework",
        "CrewAI multi-agent framework fingerprint.",
        # (?![a-z]) so 'crewai_tools' fires but 'crew aircraft' does not.
        r"\bcrew[\s_-]?ai(?![a-z])",
    ),
    AiSignature(
        "agent_framework.autogen",
        "agent_framework",
        "Microsoft AutoGen multi-agent framework fingerprint.",
        # (?![a-z]) so 'autogen_agentchat' fires but 'autogenerated' does not.
        r"\bautogen(?![a-z])",
    ),
    AiSignature(
        "agent_framework.semantic_kernel",
        "agent_framework",
        "Semantic Kernel agent-orchestration framework fingerprint.",
        r"\bsemantic[_-]?kernel",
    ),
    AiSignature(
        "agent_framework.agent_executor",
        "agent_framework",
        "Agent-executor / tool-calling loop construct ('AgentExecutor').",
        r"\bagent[_]?executor",
    ),
    # --- ReAct scratchpad shape (tool-using agent reasoning trace) -----------
    AiSignature(
        "agent_scratchpad.react",
        "agent_scratchpad",
        "ReAct agent scratchpad markers ('Action Input:' / 'Final Answer:').",
        r"\baction\s+input\s*:|\bfinal\s+answer\s*:",
    ),
    # --- LLM API client / SDK fingerprints ----------------------------------
    AiSignature(
        "llm_api_client.openai_endpoint",
        "llm_api_client",
        "OpenAI API host / chat-completions endpoint fingerprint.",
        r"\bapi\.openai\.com\b|\bchat\.completions\b|\bchatcompletion\b",
    ),
    AiSignature(
        "llm_api_client.anthropic_endpoint",
        "llm_api_client",
        "Anthropic API host endpoint fingerprint.",
        r"\bapi\.anthropic\.com\b",
    ),
    AiSignature(
        "llm_api_client.sdk_import",
        "llm_api_client",
        "LLM SDK import ('import openai' / 'from anthropic import').",
        r"\b(?:import\s+(?:openai|anthropic)|from\s+(?:openai|anthropic)\s+import)\b",
    ),
    AiSignature(
        "llm_api_client.system_fingerprint",
        "llm_api_client",
        "Chat-completion response field 'system_fingerprint'.",
        r"\bsystem_fingerprint\b",
    ),
    # --- Prompt scaffolding / instruction-template tokens --------------------
    AiSignature(
        "prompt_scaffold.helpful_assistant",
        "prompt_scaffold",
        "System-prompt scaffold ('you are a helpful assistant').",
        r"\byou\s+are\s+a\s+helpful\s+assistant\b",
    ),
    AiSignature(
        "prompt_scaffold.instruction_template",
        "prompt_scaffold",
        "Instruction-tuning template header ('### Instruction' / '### Response').",
        r"#{3}\s*(?:instruction|response)\b",
    ),
    # --- General LLM model-family identifiers (NOT image-specific) -----------
    AiSignature(
        "llm_model_identifier.family",
        "llm_model_identifier",
        "General LLM model-family identifier (gpt-/claude-/llama-/mistral-/gemini-).",
        r"\b(?:gpt-(?:3\.5|4)|claude-[0-9]|llama-?[0-9]|mistral-|mixtral-|gemini-(?:pro|[0-9]))\b",
    ),
)

# Compile once at import. Keyed by signature_id for stable iteration.
_COMPILED: tuple[tuple[AiSignature, re.Pattern[str]], ...] = tuple(
    (sig, re.compile(sig.pattern, re.IGNORECASE)) for sig in _SIGNATURE_TABLE
)


@dataclass(frozen=True)
class AiSignatureHit:
    """One signature that matched within one source, aggregated.

    Aggregated per (signature, source): ``occurrences`` is how many times the
    pattern matched, ``first_offset`` / ``preview`` describe the first match.
    Aggregation keeps the output bounded on a repetitive artifact.
    """

    signature_id: str
    category: str
    description: str
    source: str
    occurrences: int
    first_offset: int
    preview: str


@dataclass(frozen=True)
class AiSignatureScan:
    """Result of a scan over one or more sources. Pure data, no I/O state."""

    hits: tuple[AiSignatureHit, ...]
    sources_scanned: int
    chars_scanned: int
    signatures_evaluated: int
    read_errors: tuple[str, ...]
    truncated: bool


def known_categories() -> tuple[str, ...]:
    """Return the distinct signature categories, sorted, for input validation."""
    return tuple(sorted({sig.category for sig in _SIGNATURE_TABLE}))


def signature_count() -> int:
    """Number of curated signatures — exposed so callers don't hardcode it."""
    return len(_SIGNATURE_TABLE)


def _make_preview(text: str, start: int, end: int, preview_chars: int) -> str:
    """Bounded, whitespace-collapsed snippet centered on a match.

    Newlines/tabs are collapsed to single spaces so a multi-line match renders
    as one inert line. The snippet is purely informational; the MCP output
    boundary still neutralizes any chat/role control tokens it contains.
    """
    width = max(0, min(preview_chars, MAX_PREVIEW_CHARS))
    pad = max(0, (width - (end - start)) // 2)
    lo = max(0, start - pad)
    hi = min(len(text), end + pad)
    snippet = text[lo:hi]
    return re.sub(r"\s+", " ", snippet).strip()


def scan_text(
    text: str,
    *,
    source: str,
    categories: frozenset[str] | None = None,
    preview_chars: int = DEFAULT_PREVIEW_CHARS,
) -> list[AiSignatureHit]:
    """Scan one text blob for AI/agent signatures. Pure; no I/O.

    ``categories``, when set, restricts evaluation to that subset (already
    validated by the caller). Returns one :class:`AiSignatureHit` per matched
    signature, with the occurrence count and first-match preview. Order follows
    the curated table so output is deterministic.
    """
    hits: list[AiSignatureHit] = []
    for sig, rx in _COMPILED:
        if categories is not None and sig.category not in categories:
            continue
        matches = list(rx.finditer(text))
        if not matches:
            continue
        first = matches[0]
        hits.append(
            AiSignatureHit(
                signature_id=sig.signature_id,
                category=sig.category,
                description=sig.description,
                source=source,
                occurrences=len(matches),
                first_offset=first.start(),
                preview=_make_preview(text, first.start(), first.end(), preview_chars),
            )
        )
    return hits


def _read_text_file(path: str) -> tuple[str | None, str | None]:
    """Read a file as text, read-only and size-bounded.

    Returns ``(text, None)`` on success or ``(None, reason)`` on a handled
    failure. Never raises for an ordinary I/O problem (missing file, permission,
    a directory) — a scan tool degrades gracefully instead of crashing the
    server, mirroring yara_scan's per-file error tolerance.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        return None, f"{path}: not found"
    except IsADirectoryError:
        return None, f"{path}: is a directory"
    except PermissionError:
        return None, f"{path}: permission denied"
    except OSError as exc:
        return None, f"{path}: unreadable ({exc.strerror or exc})"
    exceeded = len(raw) > MAX_FILE_BYTES
    text = raw[:MAX_FILE_BYTES].decode("utf-8", errors="replace")
    if exceeded:
        # Surface truncation as a soft error rather than silently dropping bytes.
        return text, f"{path}: exceeded {MAX_FILE_BYTES} bytes (truncated)"
    return text, None


def scan_sources(
    *,
    text: str | None = None,
    paths: tuple[str, ...] = (),
    categories: frozenset[str] | None = None,
    limit: int = DEFAULT_LIMIT,
    preview_chars: int = DEFAULT_PREVIEW_CHARS,
) -> AiSignatureScan:
    """Scan an inline blob and/or named text artifacts (read-only).

    The inline ``text`` is scanned under the source label ``"<inline>"``; each
    path is read (open-for-read only) and scanned under its own path label. A
    file that cannot be read is recorded in ``read_errors`` and skipped — the
    scan still completes. ``limit`` caps total hits across all sources;
    ``truncated`` is True when the cap is reached.
    """
    capped = max(1, limit)
    collected: list[AiSignatureHit] = []
    read_errors: list[str] = []
    sources_scanned = 0
    chars_scanned = 0
    truncated = False

    def _absorb(blob: str, source: str) -> None:
        nonlocal sources_scanned, chars_scanned, truncated
        sources_scanned += 1
        chars_scanned += len(blob)
        for hit in scan_text(
            blob, source=source, categories=categories, preview_chars=preview_chars
        ):
            if len(collected) >= capped:
                truncated = True
                return
            collected.append(hit)

    if text is not None:
        _absorb(text, "<inline>")

    for path in paths:
        if truncated:
            break
        blob, err = _read_text_file(path)
        if err is not None:
            read_errors.append(err)
        if blob is None:
            continue
        _absorb(blob, path)

    return AiSignatureScan(
        hits=tuple(collected),
        sources_scanned=sources_scanned,
        chars_scanned=chars_scanned,
        signatures_evaluated=(
            len(_SIGNATURE_TABLE)
            if categories is None
            else sum(1 for s in _SIGNATURE_TABLE if s.category in categories)
        ),
        read_errors=tuple(read_errors),
        truncated=truncated,
    )


__all__ = [
    "CONFIDENCE_TIER",
    "DEFAULT_LIMIT",
    "DEFAULT_PREVIEW_CHARS",
    "LEAD_DISCLAIMER",
    "AiSignature",
    "AiSignatureHit",
    "AiSignatureScan",
    "known_categories",
    "scan_sources",
    "scan_text",
    "signature_count",
]
