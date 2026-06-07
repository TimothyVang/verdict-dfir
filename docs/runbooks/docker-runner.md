# Docker runner — reproducible VERDICT runs

The `verdict-runner` image is a *runnable clone* of VERDICT: a pinned DFIR
toolchain + the prebuilt `findevil-mcp` + the synced Python MCP env + the repo +
the Claude Code CLI, all in one image. Its job is to make the **environment**
identical on every host so the tool behaves the same way each time you run it.

> This is distinct from the repo-root `Dockerfile`, which ships *build artifacts
> only* (Amendment A2 "Option B") and runs nothing.

## What "the same every time" does — and does not — mean

There are two different guarantees hiding in that phrase:

- **(a) Environment reproducibility** — same tool versions, same MCP surface,
  same read-only evidence handling, on any host. **This image delivers (a).**
- **(b) Output determinism** — identical Findings/verdict/report prose every
  run. **No container can deliver (b)**, because the orchestrator is an LLM.

What keeps (b) *constrained and trustworthy* is the architecture, not the
container: every Finding cites a `tool_call_id` (a SHA-256 over the tool's raw
output) or it is vetoed, `verify_finding` re-runs each cited tool, the audit log
is hash-chained and append-only, and `goldens/*/expected-findings.json` +
`scripts/l3-run-goldens.sh` catch drift. The honest framing: *the evidence chain
is pinned and tamper-evident; the analysis is falsifiable and regression-gated —
not a frozen LLM transcript.*

The single highest-value knob toward (b) is pinning the model id — set
`ANTHROPIC_MODEL` (passed through by the wrapper and compose file). Even a pinned
id is eventually retired by Anthropic.

## Quick start

```bash
# 1. Provide ONE credential mode (see CLAUDE.md sec 8):
export CLAUDE_CODE_OAUTH_TOKEN=...        # or ANTHROPIC_API_KEY=..., or have ~/.claude
# 2. (optional) pin the model for run-to-run consistency:
export ANTHROPIC_MODEL=claude-opus-4-8

# 3. Run an investigation (builds the image on first run):
bash scripts/verdict-docker tmp/evidence/base-dc-memory.img
```

Inside the container Claude Code starts automatically; then type:

```
investigate /evidence/case
```

Evidence is mounted **read-only** at `/evidence/case`. The signed run and
`audit.jsonl` persist to `./out/` on your host (find_evil_auto.py writes
`tmp/auto-runs/<case>/`, mounted from `./out`).

## Build / run by hand

```bash
docker build -f docker/verdict-runner.Dockerfile -t verdict-runner:local .

mkdir -p out
docker run --rm -it \
  -v "$PWD/tmp/evidence/base-dc-memory.img:/evidence/case:ro" \
  -v "$PWD/out:/workspace/tmp:rw" \
  -e CLAUDE_CODE_OAUTH_TOKEN \
  -e ANTHROPIC_MODEL \
  verdict-runner:local
```

Or via compose:

```bash
mkdir -p out
EVIDENCE=tmp/evidence/base-dc-memory.img \
  docker compose -f docker/verdict-compose.yml run --rm verdict
```

## Pinning further (optional, for a fully reproducible image)

The image builds out of the box, but two reproducibility knobs are opt-in:

- **DFIR download checksums** — pass the real hashes to enforce verification:
  ```bash
  docker build -f docker/verdict-runner.Dockerfile \
    --build-arg HAYABUSA_SHA256=<sha> \
    --build-arg CHAINSAW_SHA256=<sha> \
    -t verdict-runner:local .
  ```
- **Claude CLI version** — `--build-arg CLAUDE_CODE_VERSION=<x.y.z>` instead of
  the `latest` default.

For maximum reproducibility, also digest-pin the base images
(`rust:1.88-bookworm`, `ubuntu:22.04`) to `@sha256:...`.

## Known limits (even with everything pinned)

- **FUSE-backed `.E01` mounting** (`disk_mount`, `disk_extract_artifacts`) needs
  loopback/FUSE, which plain Docker blocks. Prefer the libewf direct-read that
  `case_open` already uses; for the extraction paths that truly need it, add
  `--device /dev/fuse --cap-add SYS_ADMIN`. The full SIFT VM
  (`packer/sift-microvm.pkr.hcl`, QEMU/KVM) cannot live in an image.
- **sigstore signing** needs network egress to Fulcio/Rekor + an OIDC token. A
  fully air-gapped run produces only a `StubSigner` manifest, which verifiers
  reject. Use `--signer sigstore` only when egress is available.

## License note

Hayabusa (AGPL-3.0), Chainsaw (GPL-2.0), and Volatility3 are invoked as
**subprocesses only** — never linked — so they do not contaminate the
Apache-2.0 submission license. The image keeps that boundary.
