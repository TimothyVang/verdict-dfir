"""No-LLM injection self-attack harness over VERDICT's own sealed artifacts.

Beyond the sanitizer-fixture corpus (``tests/fixtures/sanitize/*``), this is the
end-to-end *architectural* proof: attacker-controlled evidence text containing
chat/role control tokens (``<|im_start|>``, ``[INST]``, ``<<SYS>>``) and
invisible/BIDI Trojan-Source code points is pushed through the SAME sanitizer
boundary the product uses (``findevil_agent_mcp.sanitize`` -- the mirror of
``services/mcp/src/sanitize.rs``), then a run manifest is sealed over the
*sanitized* tool output and verified offline.

The harness asserts the four custody properties the live boundary promises:

  (a) every control token is neutralized to the inert ``[neutralized:<id>]`` marker;
  (b) invisible/BIDI code points are stripped;
  (c) the transform is DETERMINISTIC -- re-running yields an identical
      ``output_sha256`` over the canonical serialized output; and
  (d) a sealed manifest over the sanitized content still verifies
      (``manifest_verify`` overall is True) -- i.e. the injection cannot alter
      what the audit chain attests.

A negative control proves the harness has teeth: if a control token slipped past
the sanitizer (simulated by a no-op sanitizer), the same assertion goes red.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from findevil_agent_mcp.injection_self_attack import (
    ATTACK_CORPUS,
    AttackResult,
    run_self_attack,
)
from findevil_agent_mcp.sanitize import sanitize_value

RLO = chr(0x202E)  # right-to-left override (BIDI / Trojan Source)
ZWSP = chr(0x200B)  # zero-width space
WJ = chr(0x2060)  # word joiner
ROLE_TOKENS = ("<|im_start|>", "<|im_", "[/INST]", "[INST]", "<<SYS>>", "<</SYS>>")
INVISIBLE = (RLO, ZWSP, WJ)


def test_corpus_is_nonempty_and_self_attacks() -> None:
    # The harness must actually carry attacker payloads, not run vacuously.
    assert len(ATTACK_CORPUS) >= 3


@pytest.mark.parametrize("attack", ATTACK_CORPUS, ids=lambda a: a.name)
def test_self_attack_holds_on_real_sanitizer(attack, tmp_path: Path) -> None:
    result: AttackResult = run_self_attack(attack, work_dir=tmp_path)

    # (a) control tokens neutralized; (b) invisible code points stripped. Check
    # the literal characters the model would see (sanitized_raw), since the JSON
    # serialization escapes invisibles and would hide a leak from a substring test.
    raw = result.sanitized_raw
    for marker in ROLE_TOKENS:
        assert marker not in raw, f"{attack.name}: {marker!r} survived sanitization"
    for marker in INVISIBLE:
        assert marker not in raw, f"{attack.name}: invisible {marker!r} survived"
    # If the payload carried a role token, the inert marker must replace it. (A
    # strip-only Trojan-Source attack neutralizes via removal, not substitution.)
    if "im_start" in result.neutralized_counts or "inst_close" in result.neutralized_counts:
        assert "[neutralized:" in raw
    assert result.neutralized_counts, "no neutralizations recorded for an attack payload"

    # (c) deterministic transform: a re-run yields the identical output hash.
    assert (
        result.output_sha256 == result.output_sha256_replay
    ), f"{attack.name}: sanitizer is non-deterministic -- output_sha256 drifted"
    assert len(result.output_sha256) == 64

    # (d) the sealed manifest over the SANITIZED content verifies offline.
    assert result.manifest_overall is True, result.manifest_audit_chain_ok
    assert result.manifest_merkle_root_ok is True, result.manifest_merkle_root_ok
    # The sealed tool-output leaf digests the sanitized serialized output, so the
    # injection cannot alter what the audit chain attests.
    assert result.output_sha256 in result.manifest_leaf_digests


@pytest.mark.parametrize("attack", ATTACK_CORPUS, ids=lambda a: a.name)
def test_metadata_survives_byte_identical(attack, tmp_path: Path) -> None:
    # The boundary promise: only attacker-controlled string VALUES are touched;
    # tool-derived metadata (counts, enums) is never mangled. Without this, an
    # over-broad sanitizer could corrupt the very evidence it protects.
    sanitized, _ = sanitize_value(attack.payload)
    for key in attack.preserved_keys:
        assert sanitized[key] == attack.payload[key], f"{attack.name}: metadata {key} mangled"


@pytest.mark.parametrize("attack", ATTACK_CORPUS, ids=lambda a: a.name)
def test_negative_control_a_passthrough_sanitizer_fails(attack, tmp_path: Path) -> None:
    # NEGATIVE CONTROL: if the sanitizer were a no-op (a token slipped through),
    # the neutralization assertion the harness relies on must go RED. This proves
    # the green result above is load-bearing, not vacuous.
    result = run_self_attack(attack, work_dir=tmp_path, sanitizer=lambda v: (v, {}))

    raw = result.sanitized_raw
    leaked = any(marker in raw for marker in ROLE_TOKENS) or any(
        marker in raw for marker in INVISIBLE
    )
    assert leaked, (
        f"{attack.name}: negative control did not leak -- the harness would pass "
        "even with a broken sanitizer, so the real-sanitizer assertion proves nothing"
    )
    # And the harness exposes that nothing was neutralized.
    assert not result.neutralized_counts
