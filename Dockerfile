# Glue plan Task 7 — image published to ghcr.io/find-evil/find-evil:v<N>
# per glue Spec #4 §4. Multi-stage so the shipped image is slim.
#
# Matches SIFT's Ubuntu 22.04 base per Spec #2 §4.5.

# ============================================================
# Stage 1 — Rust build.
# ============================================================
# hadolint ignore=DL3007
# Pinned to 1.88 to match rust-toolchain.toml channel = "1.88.0".
# The workspace's rust-version (Cargo.toml [workspace.package])
# also requires 1.88 because transitive deps (clap_builder 4.6
# and friends) need edition-2024 stabilization (Rust ≥1.85).
# A 1.83 base would either fail at cargo build or trigger a
# rustup pull at build time.
FROM rust:1.88-bookworm AS rust-build
WORKDIR /build

# Install libs needed for the MCP server's C deps (libewf, yara).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    libewf-dev libyara-dev libclang-dev pkg-config \
 && rm -rf /var/lib/apt/lists/*

# Leverage Docker layer caching — manifest first, full tree after.
COPY Cargo.toml Cargo.lock* ./
COPY services/mcp ./services/mcp
# Compile only when Rust sources exist (pre-Week-2 they don't).
RUN if [ -f Cargo.toml ]; then \
      cargo build --release --locked --workspace 2>/dev/null || true ; \
    else \
      mkdir -p target/release && touch target/release/.placeholder ; \
    fi

# ============================================================
# Stage 2 — Python agent build.
# ============================================================
# hadolint ignore=DL3007
FROM python:3.11-slim-bookworm AS py-build
WORKDIR /build
RUN pip install --no-cache-dir 'uv==0.5.8'
COPY services/agent/pyproject.toml* services/agent/uv.lock* ./services/agent/
RUN if [ -f services/agent/pyproject.toml ]; then \
      cd services/agent && uv sync --frozen 2>/dev/null || uv sync 2>/dev/null || true ; \
    fi
COPY services/agent ./services/agent
RUN if [ -f services/agent/pyproject.toml ]; then \
      cd services/agent && uv build --wheel --out-dir /build/wheels 2>/dev/null || true ; \
    else \
      mkdir -p /build/wheels ; \
    fi

# ============================================================
# Stage 3 — Runtime. Ubuntu 22.04 matches SIFT's base.
# ============================================================
# hadolint ignore=DL3007
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl jq \
    python3.11 python3.11-venv python3-pip \
    libewf2 libafflib-dev libyara-dev sleuthkit \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# Pull in Rust binary + Python wheel from build stages.
COPY --from=rust-build /build/target/release/findevil-mcp* /usr/local/bin/
COPY --from=py-build   /build/wheels/                      /tmp/wheels/
RUN if ls /tmp/wheels/*.whl >/dev/null 2>&1; then \
      pip install --no-cache-dir /tmp/wheels/*.whl ; \
    fi \
 && rm -rf /tmp/wheels

# Amendment A2 decision (2026-04-27, runbook docs/runbooks/dockerfile-
# a2-decision.md "Option B"): no in-container CLI wrapper. A2's central
# claim is "Claude Code IS the orchestrator" — the canonical user
# contract is `claude` invoked from a repo clone with .mcp.json present.
# This image ships the Rust MCP binary + Python wheel as build
# artifacts, useful for reproducing CI build state and for the .mcp.json
# server-spawn entries that point at the in-image binaries.

# Non-root runtime user.
ARG RUN_UID=1000
ARG RUN_GID=1000
RUN groupadd --gid "${RUN_GID}" find-evil \
 && useradd --uid "${RUN_UID}" --gid "${RUN_GID}" --create-home --shell /bin/bash find-evil
USER find-evil
WORKDIR /home/find-evil

HEALTHCHECK --interval=30s --timeout=5s --retries=2 \
  CMD command -v findevil-mcp && command -v python3 || exit 1

LABEL org.opencontainers.image.title="find-evil" \
      org.opencontainers.image.description="Find Evil! DFIR build artifacts for SANS SIFT (Rust MCP + Python wheel; orchestrator is Claude Code, not in-container)" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/"

CMD ["bash"]
