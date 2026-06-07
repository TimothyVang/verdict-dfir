# Amendment A5 — Remove OpenTimestamps / Bitcoin Tier

**Status: SHIPPED**
**Date:** 2026-04-30
**Supersedes:** nothing; extends A3 by removing one of its five cryptographic primitives.
**Affects:** `services/agent/`, `services/agent_mcp/`, `docs/cryptographic-attestation.md`, CLAUDE.md §3.

---

## What changed

The fourth tier of the cryptographic chain — Bitcoin blockchain anchoring via
OpenTimestamps — was removed. Five code touchpoints were cut:

| Removed | Replaced by |
|---|---|
| `services/agent/findevil_agent/crypto/ots.py` | (deleted) |
| `ots_stamp` MCP tool module | (deleted) |
| `ots_verify` MCP tool module | (deleted) |
| `opentimestamps-client` dep in `services/agent/pyproject.toml` | (deleted) |
| Orchestrator + report-renderer + smoke references to OTS | Updated to 3-tier |

Commits: `743404d`, `a75ea44`, `e265600`, `6da4d95`, `2b59572`.

The Python `findevil-agent-mcp` registry went from 13 tools to 11 (Track 4 later adds
`expert_miss_capture` as the 12th, for a final count of 12).
`services/agent_mcp/tests/test_stdio_smoke.py` enforces the current count.

---

## Why it was removed

The Bitcoin tier offered the strongest no-single-party timestamp guarantee: a hash
anchored to a Bitcoin block is attested by every mining node in the network, with no
trust placed in any single operator. However, it had two operational problems
incompatible with a hackathon-demo timeline:

1. **Network dependency.** Anchoring requires a round-trip to an OpenTimestamps calendar
   server (`a.pool.opentimestamps.org` or `b.pool.opentimestamps.org`). Judges scoring
   offline, or inside a SIFT VM with no outbound calendar reach, cannot exercise the tier.

2. **Maturation delay.** A Bitcoin timestamp does not exist until a block is mined
   (~10 minutes best-case). The upgrade file must then be fetched and verified after the
   fact. An investigation completed and submitted before that window closes produces an
   unverifiable OTS receipt at judge time.

The Rekor / sigstore tier (link 4) already provides an independent-party lower-bound
timestamp via the Linux Foundation's append-only transparency log, without the above
constraints. Removing Bitcoin reduces complexity without reducing the chain-of-custody
claim that matters to rubric criterion #5.

---

## Post-A5 chain shape

```
evidence SHA-256
    ↓  (sha2 = 0.10, Rust in-process)
audit prev_hash chain
    ↓  (JSONL append-only, each record has prev_hash)
rs_merkle root over canonical-JSON record bytes
    ↓  (rs_merkle = 1.4, Rust in-process)
sigstore / Rekor signature
    (Fulcio cert + Rekor inclusion proof — attested by Linux Foundation)
```

Three tiers; four primitives composed. Full treatment: `docs/cryptographic-attestation.md`.

---

## FRE 902(14) impact

None. The Bitcoin tier was supplementary to the core self-authentication claim, which
rests on SHA-256 hash-value identification (the 2017 Advisory Committee Note's
"ordinary" method). Removing Bitcoin does not weaken the 902(14) basis.
See `docs/cryptographic-attestation.md` "What FRE 902(14) requires."

---

## Note on spec lineage

A1/A2/A3 each have a dedicated spec file because they changed the product's primary
interface or delivery model. A5 was a targeted removal with no architectural
consequence — two MCP tools deleted, one Python module deleted, one dep dropped.
This document exists to complete the amendment numbering sequence and provide a
canonical reference for the "why Bitcoin was cut" question that arises in judge Q&A.
