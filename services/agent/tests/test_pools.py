"""Sanity tests for the ACH pool prompt fragments."""

from __future__ import annotations

from findevil_agent.pools import (
    EXFIL_SYSTEM_PROMPT,
    PERSISTENCE_SYSTEM_PROMPT,
    ExfilPool,
    PersistencePool,
)


class TestPersistencePool:
    def test_pool_origin(self) -> None:
        assert PersistencePool().pool_origin == "A"

    def test_prompt_mentions_canonical_techniques(self) -> None:
        # Spec #2 §8.1 enumerates these MITRE TIDs as the persistence
        # priors the pool agent should focus on.
        for tid in ("T1053.005", "T1543.003", "T1546.003", "T1547.001", "T1546.012"):
            assert tid in PERSISTENCE_SYSTEM_PROMPT, f"missing technique {tid}"

    def test_prompt_mentions_lolbins(self) -> None:
        # MEMORY.md Tier-1 LOLBin priors.
        for bin_name in ("rundll32", "regsvr32", "mshta", "wmic", "certutil", "bitsadmin"):
            assert bin_name in PERSISTENCE_SYSTEM_PROMPT.lower()

    def test_prompt_mentions_amcache_caveat(self) -> None:
        assert "Amcache" in PERSISTENCE_SYSTEM_PROMPT
        assert (
            "catalog-registration time" in PERSISTENCE_SYSTEM_PROMPT
            or "not execution" in PERSISTENCE_SYSTEM_PROMPT
        )

    def test_prompt_enforces_tool_call_id_invariant(self) -> None:
        assert "tool_call_id" in PERSISTENCE_SYSTEM_PROMPT


class TestExfilPool:
    def test_pool_origin(self) -> None:
        assert ExfilPool().pool_origin == "B"

    def test_prompt_mentions_exfil_techniques(self) -> None:
        # Spec #2 §8.1 exfil priors.
        for tid in ("T1071", "T1074", "T1105", "T1567", "T1052"):
            assert tid in EXFIL_SYSTEM_PROMPT, f"missing technique {tid}"

    def test_prompt_mentions_lolbins_for_exfil(self) -> None:
        for tok in ("certutil", "bitsadmin", "curl", "Invoke-WebRequest"):
            assert tok.lower() in EXFIL_SYSTEM_PROMPT.lower(), f"missing tok {tok}"

    def test_prompt_mentions_evtx_caveats(self) -> None:
        assert "Type 3" in EXFIL_SYSTEM_PROMPT  # network logon
        assert "Type 10" in EXFIL_SYSTEM_PROMPT  # RDP

    def test_prompt_distinguishes_processguid_from_pid(self) -> None:
        assert "ProcessGuid" in EXFIL_SYSTEM_PROMPT
        assert "PID" in EXFIL_SYSTEM_PROMPT

    def test_prompts_share_no_attribution_rule(self) -> None:
        for prompt in (PERSISTENCE_SYSTEM_PROMPT, EXFIL_SYSTEM_PROMPT):
            assert "attribution" in prompt.lower()


class TestPoolsAreDistinct:
    def test_pools_have_different_origins(self) -> None:
        assert PersistencePool().pool_origin != ExfilPool().pool_origin

    def test_pools_have_different_prompts(self) -> None:
        # Otherwise the dual-pool ACH dance is a no-op.
        assert PERSISTENCE_SYSTEM_PROMPT != EXFIL_SYSTEM_PROMPT
        # Sanity: pool A talks about persistence; pool B about exfil.
        assert "persistence" in PERSISTENCE_SYSTEM_PROMPT.lower()
        assert "exfiltrat" in EXFIL_SYSTEM_PROMPT.lower()
