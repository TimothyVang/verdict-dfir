# syntax=docker/dockerfile:1
# docker/verdict-runner.Dockerfile — the reproducible VERDICT runner image.
#
# The repo-root Dockerfile ships *build artifacts only* (Amendment A2 "Option B":
# no in-image orchestrator). This image is deliberately different: it is a
# *runnable* clone of the tool — pinned DFIR toolchain + prebuilt findevil-mcp +
# synced Python MCP env + the repo + Claude Code CLI — so the ENVIRONMENT is
# identical on every host. It cannot make the LLM's wording identical; see
# docs/runbooks/docker-runner.md for what "the same every time" does and does
# not mean.
#
#   Build:  docker build -f docker/verdict-runner.Dockerfile -t verdict-runner:local .
#   Run:    bash scripts/verdict-docker <evidence-path>      (see the runbook)

# ============================================================
# Stage 1 — Rust build. Base pinned to rust-toolchain.toml (channel 1.88.0).
# ============================================================
FROM rust:1.88-bookworm AS rust-build
WORKDIR /build

# C deps the MCP server links against (libewf for .E01, yara for yara_scan).
RUN apt-get update && apt-get install -y --no-install-recommends \
      libewf-dev libyara-dev libclang-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Manifest + lock first (layer caching), then the crate source.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY services/mcp ./services/mcp

# Strict: --locked enforces Cargo.lock; a failure must fail the image (unlike
# the repo-root Dockerfile's best-effort `|| true`). Assert the binary exists.
RUN cargo build --release --locked --workspace \
 && test -x target/release/findevil-mcp

# ============================================================
# Stage 2 — Runtime: Ubuntu 22.04 (parity with the SIFT base).
# ============================================================
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PIP_NO_CACHE_DIR=1

# --- System + DFIR runtime deps. Runtime lib set mirrors the proven repo-root
#     Dockerfile stage 3 (libewf2 / libafflib-dev / libyara-dev / sleuthkit);
#     git/unzip/xz/zstd are added for the Hayabusa/Chainsaw downloads. FUSE is
#     intentionally omitted — loopback mounting needs caps plain Docker blocks
#     (see the runbook); libewf direct-read in case_open covers the common path.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl jq git unzip xz-utils zstd \
      python3.11 python3.11-venv python3-pip \
      libewf2 libafflib-dev libyara-dev sleuthkit \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# --- uv (Python MCP env manager) — pinned to the L1/devbase version ---
RUN pip install 'uv==0.11.19'

# --- Node 20 + Claude Code CLI (the orchestrator runs INSIDE the image) ---
ARG NODE_MAJOR=20
RUN curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*
# `latest` is the out-of-box default; pass --build-arg CLAUDE_CODE_VERSION=x.y.z
# to pin a specific CLI for a fully reproducible image.
ARG CLAUDE_CODE_VERSION=latest
RUN npm install -g "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}"

# --- Volatility3 — pinned (matches docker/l2-siftlite.Dockerfile) ---
RUN pip install 'volatility3==2.11.0'

# --- Hayabusa (AGPL-3.0, subprocess only) — version-pinned; checksum-verified
#     when HAYABUSA_SHA256 is supplied (build out-of-the-box without it). ---
ARG HAYABUSA_VERSION=2.19.0
ARG HAYABUSA_SHA256=
RUN curl -fsSL "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" -o /tmp/hayabusa.zip \
 && { [ -z "${HAYABUSA_SHA256}" ] || echo "${HAYABUSA_SHA256}  /tmp/hayabusa.zip" | sha256sum -c -; } \
 && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
 && hb="$(find /opt/hayabusa -maxdepth 2 -name 'hayabusa-*-lin-x64-gnu' -type f | head -1)" \
 && chmod +x "${hb}" \
 && ln -sf "${hb}" /usr/local/bin/hayabusa \
 && rm -f /tmp/hayabusa.zip

# --- Chainsaw (GPL-2.0, subprocess only) — same pin + optional-verify pattern ---
ARG CHAINSAW_VERSION=2.13.0
ARG CHAINSAW_SHA256=
RUN curl -fsSL "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip" -o /tmp/chainsaw.zip \
 && { [ -z "${CHAINSAW_SHA256}" ] || echo "${CHAINSAW_SHA256}  /tmp/chainsaw.zip" | sha256sum -c -; } \
 && unzip -q /tmp/chainsaw.zip -d /opt/chainsaw \
 && chmod +x /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu \
 && ln -sf /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu /usr/local/bin/chainsaw \
 && rm -f /tmp/chainsaw.zip

# --- Non-root runtime user ---
ARG RUN_UID=1000
ARG RUN_GID=1000
RUN groupadd --gid "${RUN_GID}" verdict \
 && useradd --uid "${RUN_UID}" --gid "${RUN_GID}" --create-home --shell /bin/bash verdict

# --- The repo + the prebuilt Rust binary ---
WORKDIR /workspace
COPY . /workspace
COPY --from=rust-build /build/target/release/findevil-mcp /usr/local/bin/findevil-mcp
# scripts/run-mcp-rust.sh prefers $FINDEVIL_MCP_BIN → no `cargo run` recompile
# on a cold MCP spawn.
ENV FINDEVIL_MCP_BIN=/usr/local/bin/findevil-mcp

# Pre-sync the Python MCP env so `uv run` is instant at spawn (not resolved
# cold on first tool call), then hand the tree to the runtime user.
RUN cd services/agent_mcp && uv sync --extra dev --frozen \
 && chown -R verdict:verdict /workspace

USER verdict
ENV HOME=/home/verdict

# Tools + orchestrator must all be on PATH. Volatility's `vol` console script
# carries its own interpreter shebang, so we check the command, not an import.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD command -v findevil-mcp >/dev/null \
   && command -v hayabusa >/dev/null \
   && command -v chainsaw >/dev/null \
   && command -v vol >/dev/null \
   && command -v claude >/dev/null \
   && command -v uv >/dev/null || exit 1

LABEL org.opencontainers.image.title="verdict-runner" \
      org.opencontainers.image.description="Reproducible VERDICT / Find Evil! DFIR runner: pinned DFIR tools + MCP servers + Claude Code. Delivers environment parity, not LLM-output determinism." \
      org.opencontainers.image.licenses="Apache-2.0"

# Default to an interactive shell in the repo. scripts/verdict-docker launches
# `claude` directly with evidence mounted.
CMD ["bash"]
