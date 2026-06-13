# `docs/release-evidence/` — release-validation evidence

This directory holds small, reviewable evidence summaries that explain what the release workflows validated. The current file records the historical `v-submit` release boundary; it is not proof that later post-tag commits have passed a refreshed release gate.

## Files

| File | Purpose |
|---|---|
| `l3-local-sift.json` | Local VMware/SIFT L3 fallback evidence for `v-submit`. It records the NIST Hacking Case image hash, run/readiness state, artifact hashes, and verification commands used when the GitHub KVM runner label had no capacity. |

## Why this exists

The preferred L3 path is a full SIFT run on a KVM-capable GitHub runner. During final release, the `ubuntu-latest-4-core-kvm` label had no available jobs, so CI validated this explicit local SIFT evidence instead of treating a skipped L3 run as success.

This is intentionally narrow:

- It does not contain raw evidence, disk images, reports, or case artifacts.
- It records hashes and gate outcomes only.
- It preserves the truth boundary: the packet is `READY_FOR_EXPERT_REVIEW`, not customer-releasable.
- It does not mutate or refresh the GitHub `v-submit` release asset set.

Validator:

```bash
python scripts/validate-l3-evidence.py docs/release-evidence/l3-local-sift.json --emit logs/l3/nist-hacking-case-verdict.json
```
