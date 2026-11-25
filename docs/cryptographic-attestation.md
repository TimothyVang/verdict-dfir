# Cryptographic Chain of Custody

This document is the canonical answer to "how does VERDICT's
cryptographic attestation work, and how do I verify a manifest
someone else produced?" The story is scattered across CLAUDE.md,
README.md, the DC investigation report, and the demo script — this
file collects the load-bearing claims in one place.

> **Why this matters:** audit-trail quality turns on whether the
> agent's findings are independently verifiable by a third party
> with no trust in the agent itself. VERDICT's answer is "yes, by
> `manifest_verify` alone — no network, no trusted third-party
> servers." This supports a FRE 902(14) self-authenticating-evidence
> claim, with the honest caveat documented below.

> **Amendment A5 (2026-05-01):** the OpenTimestamps + Bitcoin
> anchoring tier was removed. The chain dropped from five links
> to four primitives composed across three tiers (audit chain →
> Merkle root → manifest signature). The Bitcoin tier required
> network reach to a calendar server plus a multi-hour wait for
> the attestation to mature, neither of which an offline verifier
> can exercise. The honest implication for the FRE 902(14)
> claim is in the "What FRE 902(14) requires" section.

---

## The three-link chain

![Chain of custody — manifest_finalize output: the hash-chained audit.jsonl, one Merkle leaf per tool_call_output, and audit_log_final_hash + merkle_root_hex bound into an ed25519-signed run.manifest.json](showcase/results-custody-chain.png)

Every VERDICT investigation produces a `run.manifest.json`
backed by composed cryptographic primitives across three tiers:

```
   evidence file (.e01 / .img / .evtx)
       │
       ▼  sha2 = 0.10 (Rust, in-process)
   image_hash (32-byte SHA-256, committed at case_open)
       │
       ▼  audit_append (append-only JSONL with prev_hash)
   audit chain  (each record: { kind, payload, prev_hash, seq, ts })
       │
       ▼  rs_merkle = 1.4 (Rust, in-process)
   Merkle tree over canonical-JSON record bytes
       │
       ▼  signer tier (Ed25519 default; Sigstore for identity; stub for tests)
   signature  (signed over the manifest body bytes)
```

Each link's role:

| # | Primitive | What it proves | Library |
|---|---|---|---|
| 1 | SHA-256 of the evidence | The image we read is the image we received | `sha2 = 0.10` (Rust) |
| 2 | Audit hash chain | No record was deleted, reordered, or back-dated after the fact | `services/agent/findevil_agent/crypto/audit_log.py` |
| 3 | rs_merkle tree | The set of records named in the manifest is the set the agent actually wrote | `rs_merkle = 1.4.0` (Rust) |
| 4 | manifest signature | See signer tiers below — every run is signed; the tier determines what the signature proves | `cryptography` (ed25519) / `sigstore = 3.x` |

**Signer tiers** (choose with `--signer` / `FINDEVIL_SIGNER`; the manifest
records the tier that *actually* sealed the run in `signature.kind`):

| Tier | Default? | What it proves | Verified offline? |
|---|---|---|---|
| `ed25519` | **yes** | A real Ed25519 signature over the manifest body, signed with a local keypair (`~/.findevil/signing.key`, auto-generated; override `FINDEVIL_SIGNING_KEY`). Proves **integrity + local key continuity** — the manifest body has not changed since sealing | **yes** — `manifest_verify` rebuilds the canonical body and checks it against the embedded public key: `signature_verified=true` is a genuine cryptographic pass |
| `sigstore` | opt-in | Everything ed25519 proves, **plus identity**: the sealing key's Fulcio cert is logged in Rekor — non-repudiable provenance via a public transparency log. The customer-release tier | bundle recorded; full verification needs the expected signer identity (deployment policy) |
| `stub` | explicit opt-in | Nothing cryptographic — a deterministic dev/offline placeholder | never (`signature_verified` honestly says so) |

A failed signer degrades honestly (`sigstore → ed25519 → stub`) with the
reason recorded in `signature.fallback_reason` — a run never crashes, and
never silently overstates its tier.

**No single primitive is load-bearing alone.** A SHA-256 by itself
proves byte equality but not freshness; a Merkle root proves set
membership but not who built the set; the signer tier states who, if
anyone, sealed the manifest. Ed25519 proves local key continuity
offline, while Sigstore adds public identity and a Rekor time lower
bound. The composition is the attestation.

---

## Where each link lives in the code

```
services/mcp/                                    ← (Rust DFIR tool MCP)
├── src/tools/case_open.rs                       — link 1: sha2 hash of evidence
└── (every tool emits _meta.output_sha256 over its canonical JSON output)

services/agent/findevil_agent/crypto/            ← (M2 crypto stack)
├── audit.py                                     — link 2: prev_hash chain
├── merkle.py                                    — link 3: rs_merkle tree
├── signer.py                                    — link 4: Ed25519/Sigstore/stub signer tiers
└── manifest.py                                  — composes 2/3/4 into run.manifest.json

services/agent_mcp/findevil_agent_mcp/tools/     ← (Python MCP wrapping the above)
├── audit_append.py                              ↘  one MCP tool per link
├── audit_verify.py                              ↘  11 Python tools total — see TOOLS.md
├── manifest_finalize.py                         ↘  (the OTS pair was removed under A5)
└── manifest_verify.py                           ↘
```

The Rust side does the in-process content addressing (links 1 and
the per-tool output_sha256 that feeds the Merkle leaves). The
Python side composes the chain and signs.

---

## How a third party verifies offline

An auditor, regulator, or counter-party who has zero trust in the
agent can verify a VERDICT manifest with one tool, offline:

```bash
# The manifest signature, audit chain, and Merkle root.
# No network required (the manifest is self-contained).
# Direct library call — no MCP server, no JSON-RPC plumbing.
uv run --directory services/agent python -c "
from pathlib import Path
from findevil_agent.crypto.manifest import verify_manifest
case = Path('<absolute-path-to-case-dir>')
r = verify_manifest(case / 'run.manifest.json',
                    audit_log_path=case / 'audit.jsonl')
print(r)
"
# Returns: ManifestVerification(audit_chain_ok=True, merkle_root_ok=True,
#                               leaf_count_ok=True, signature_present=True,
#                               overall=True)
# Any field becomes a string instead of True on failure, naming the
# precise reason (e.g. 'audit chain seq=4 prev_hash mismatch').
```

For a fuller workout that also exercises `audit_verify`,
`detect_contradictions`, `judge_findings`, and `correlate_findings`
through the actual MCP server (matching the live agent's flow),
run the smoke harness against the same case dir:

```bash
uv run --directory services/agent_mcp \
    python ../../scripts/agent-mcp-smoke.py \
    --real-evidence <absolute-path-to-case-dir>
```

The smoke spawns the server as a subprocess (matching `.mcp.json`),
drives it over piped stdio, and reports pass/fail per stage. This is
heavier than the direct library call but proves the MCP wire format
also passes — useful when verifying that what the live agent emits
is what the verifier consumes.

`manifest_verify` rebuilds:

1. The audit chain by walking `prev_hash` SHA-256 links from `seq=0`
   forward — first mismatch reports the seq + field that diverged.
   It then re-derives the record count, the final line hash, and the
   full Merkle-eligible leaf set from the replayed log and compares
   them to what the manifest declares — so a tail-truncated log, a
   post-seal append, or an internally-consistent forged leaf set all
   fail with a precise diagnostic, even though each is self-consistent
   on its own.
2. The Merkle tree from the manifest's `leaves[]` array — declared
   `merkle_root_hex` must match the rebuilt root byte-for-byte.
3. The signature bundle: `signature_present` confirms a bundle with a
   payload digest is attached, and `signature_verified` reports the
   honest cryptographic status — never `true` for a stub bundle (a
   deterministic placeholder is not proof), and a sigstore bundle is
   recorded for offline verification by a party that supplies the
   expected signer identity. `overall` requires a bundle to be present
   and treats a `stub` or recorded `sigstore` bundle as advisory (so
   dev/offline stub runs verify end-to-end), but a present `ed25519`
   bundle that does **not** cryptographically verify fails `overall` —
   a forged or corrupted signature cannot pass.

If all checks pass, `overall=true`. Any one fails → `overall=false`
with a precise diagnostic naming the field and the expected vs actual
value. Tampering with the audit log, or with the manifest's account of
it, is loud. The honest limits per tier: an **ed25519**-signed run (the
default) verifies cryptographically offline — `signature_verified=true`
proves the manifest body is exactly what the local key sealed — but a
local key carries no third-party identity; a **stub**-signed run proves
chain and Merkle integrity but nothing about who sealed it. Only a real
sigstore signature adds non-repudiable identity via the transparency
log, which is why customer release requires `signer=sigstore`.

---

## What FRE 902(14) requires and why this meets it

[Federal Rule of Evidence 902(14)](https://www.law.cornell.edu/rules/fre/rule_902)
("Certified Records Generated by an Electronic Process or System")
admits a digital record as **self-authenticating** — meaning the
proponent doesn't need to call a live witness to authenticate it —
when the record is supported by **a certification of a qualified
person** that complies with the certification requirements of Rule
902(11) or (12). Per the 2017 Advisory Committee Note, the
contemplated "process of digital identification" is **ordinarily
hash-value comparison**: data copied from electronic devices, storage
media, and files are "ordinarily authenticated by 'hash value'...
identical hash values for the original and copy reliably attest...
that they are exact duplicates." The proponent must also give the
adverse party **reasonable written notice** plus access to the record
and certification (the Rule 902(11) notice requirement).

> **Correction (2026-06, validated against Cornell LII rule text, the
> 2017 Advisory Committee Note, and G. Joseph, *Self-Authentication
> of Electronic Evidence*):** earlier versions of this document
> asserted a "two-prong" requirement whose prong (b) was *a trusted
> timestamp from an independent third party*. **That prong does not
> exist.** Neither 902(13) nor 902(14) requires a third-party
> timestamp. The rule requires only the qualified-person
> certification via a process of digital identification (ordinarily
> hashing) plus 902(11) notice. VERDICT therefore satisfies
> 902(14) on hash-value identification alone — the sigstore/Rekor
> signature is **defense-in-depth, not a legal prerequisite.**

**How VERDICT meets the actual requirement:**

- **Accurate process of digital identification (the rule's core):**
  every evidence image is SHA-256 hashed at `case_open` and every
  tool output is content-addressed by SHA-256. The `verify_finding`
  MCP tool re-executes any cited `tool_call_id` and confirms the
  original output's hash matches. The qualified-person certification
  is the human expert sign-off attached to the readiness packet.
  This is exactly the hash-value identification the Advisory
  Committee Note contemplates.
- **Signature + transparency log (supplementary, not required):**
  sigstore's Rekor transparency log records every signature with an
  append-only inclusion proof, establishing that the signed body
  existed at or before the entry's logged time, attested by an
  independent party (the Linux Foundation) with no relationship to
  VERDICT's authors. This *strengthens* provenance and gives a
  lower-bound time, but the 902(14) admissibility claim does not
  depend on it.
  - **Historical (pre-A5):** the shipped chain is Rekor-only for this
    independent-time property. An OpenTimestamps/Bitcoin tier that
    *also* anchored it was **removed under Amendment A5 and is not part
    of the current chain.** Bitcoin offered a stronger no-single-party
    timestamp; Rekor trusts the LF to operate the log honestly. Either
    way, this is supplementary to — not part of — the 902(14) requirement.

A court looking at a `run.manifest.json` three years from now
establishes the record's integrity from the hash chain and signature
offline, without trusting VERDICT or the analyst. Trusting Rekor
not to have been silently rewritten is relevant only to the
*supplementary* time claim, not to the core 902(14) self-
authentication, which rests on hash-value identification.

---

## The negative test (live demonstration)

The DC investigation report (§7) demonstrates tamper detection
end-to-end. Flip any byte of any field; verification fails with a
diagnostic that names exactly what diverged:

```bash
# Tamper with the Merkle root field of an existing manifest:
python -c "
import json, pathlib
p = pathlib.Path('run.manifest.json')
d = json.loads(p.read_text())
d['merkle_root_hex'] = 'ff' * 32   # 64 hex chars = 32 bytes
p.write_text(json.dumps(d, indent=2, sort_keys=True))
"

# Verify — expect failure with diagnostic:
# manifest_verify { manifest_path: "run.manifest.json" }
# →
# {
#   "overall": false,
#   "audit_chain_ok": true,
#   "merkle_root_ok": false,
#   "merkle_root_detail": "declared root ff..ff != rebuilt fbc25852755b...",
#   "signature_present": true
# }
```

The audit chain still verifies (we didn't tamper with the chain),
but the Merkle root fails — the rebuilt root from `leaves[]` is
the original `fbc25852755b...`, not the `ff..ff` we wrote in.
Same shape if you tamper with any audit record (chain breaks at
the seq you altered) or any signed body field (signature
verification fails).

This is exercised on every `agent-mcp-smoke.py` run as a deliberate
negative test — see `scripts/agent-mcp-smoke.py` "10. tampered
manifest is rejected" step.

---

## What this attestation does NOT prove

Honest disclosure (per `docs/false-positives.md` and SOUL.md):

- **Not the truth of the findings.** The chain proves the agent ran
  the named tool calls and recorded the named outputs — it does
  not prove those outputs *correctly identify* malicious activity.
  An agent emitting wrong analysis with cryptographic precision
  is still emitting wrong analysis. The `verify_finding` veto +
  the SOUL.md ≥2-artifact correlator + the Pool A vs B
  contradiction surface are the *epistemic* guardrails; the chain
  is the *integrity* guardrail. Both are needed.
- **Not the trustworthiness of the SIFT VM or Volatility's symbol
  cache.** If the SIFT VM's vol3 is compromised before the
  agent runs, the SHA-256 of the tool output is the SHA-256 of
  the *compromised* output. Defense-in-depth (read-only mounts,
  unprivileged user, no `execute_shell`) is the architectural
  layer; the cryptographic layer assumes those guardrails hold.
- **Not the absence of evidence.** A valid manifest covers the
  evidence the agent looked at. Evidence not collected (e.g. a
  full disk image from a host where only memory was acquired)
  is not part of the chain. The DC investigation report §8
  enumerates this caveat explicitly.

---

## References

- CLAUDE.md "Non-negotiable invariants" (audit-log append-only,
  every Finding cites a `tool_call_id`)
- `agent-config/SOUL.md` (epistemic hierarchy: CONFIRMED >
  INFERRED > HYPOTHESIS)
- `agent-config/JUDGING.md` (after-the-fact self-assessment rubric;
  scored out-of-band by `scripts/self-score.py`, not part of the chain)
- `scripts/trace-finding` (offline replay helper for completed case directories)
- `scripts/agent-mcp-smoke.py` (the negative test runs in CI on
  every L1 build per `docker/l1-compose.yml`)
- [Federal Rule of Evidence 902(14)](https://www.law.cornell.edu/rules/fre/rule_902)
- [sigstore-python documentation](https://github.com/sigstore/sigstore-python)
- [Rekor transparency log](https://docs.sigstore.dev/logging/overview/)
