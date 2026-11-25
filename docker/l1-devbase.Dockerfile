# Spec #3 §4.2 — L1 dev-base image.
# Matches SIFT's Ubuntu 22.04 base so CI + L3 golden-run Product
# environments are byte-compatible where it matters.
#
# Budget: 2-5min build; <5min L1 test cycle.
# Blocks PR merge via .github/workflows/l1-unit.yml.

# hadolint ignore=DL3007
FROM ubuntu:22.04

# Ensure deterministic apt behavior.
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:/usr/local/fnm:/usr/local/bin:${PATH}

# System deps matching BUILD_PLAN_v2.md §10 week-1 skeleton + Spec #2 §4.1
# (rmcp + evtx + duckdb) + Spec #2 §4.2 (Python agent with sigstore custody).
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    pkg-config \
    libssl-dev \
    libclang-dev \
    lld \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3-pip \
    libyara-dev \
    libewf-dev \
    libafflib-dev \
    libfuse-dev \
    sleuthkit \
    postgresql-client \
    xz-utils \
    zstd \
    unzip \
    jq \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# Rust 1.88 (bumped from 1.83 — transitive deps increasingly need
# edition 2024 stabilization, which landed in 1.85). See
# rust-toolchain.toml for the authoritative pin.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y \
        --default-toolchain 1.88.0 \
        --profile minimal \
        --component clippy,rustfmt \
 && /usr/local/cargo/bin/rustup --version \
 && /usr/local/cargo/bin/cargo --version

# Node 20 via fnm + pnpm 9.12.0 via npm. Some fnm-provided Node
# builds do not expose corepack until the shell environment is reloaded,
# so use the explicit npm path instead of assuming PATH/corepack state.
RUN curl -fsSL https://fnm.vercel.app/install | bash -s -- --install-dir /usr/local/fnm --skip-shell \
 && FNM_DIR=/usr/local/fnm bash -lc 'export FNM_DIR=/usr/local/fnm \
    && eval "$(/usr/local/fnm/fnm env --shell bash)" \
    && fnm install 20 \
    && fnm default 20 \
    && npm install -g pnpm@9.12.0 \
    && NODE_BIN_DIR="$(dirname "$(find "${FNM_DIR}/node-versions" -path "*/installation/bin/node" -type f -print -quit)")" \
    && test -x "${NODE_BIN_DIR}/node" \
    && ln -sf "${NODE_BIN_DIR}/node" /usr/local/bin/node \
    && ln -sf "${NODE_BIN_DIR}/npm" /usr/local/bin/npm \
    && ln -sf "${NODE_BIN_DIR}/npx" /usr/local/bin/npx \
    && ln -sf "${NODE_BIN_DIR}/pnpm" /usr/local/bin/pnpm \
    && ln -sf "${NODE_BIN_DIR}/pnpx" /usr/local/bin/pnpx \
    && node --version \
    && pnpm --version'

# Python packaging: uv for env+lockfile (matches CLAUDE.md conventions).
# Pinned per https://astral.sh/uv release notes around the plan date.
# cryptography: report-policy-smoke.py verifies a real ed25519 manifest signature
# and runs under bare `python3` (not the uv venv), so the base image must carry it.
RUN pip install --no-cache-dir 'uv==0.11.19' 'matplotlib>=3.8,<4.0' 'cryptography>=42,<47' \
 && uv --version

# Non-root build user. Anything that runs evidence-adjacent must be non-root.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN groupadd --gid "${DEV_GID}" dev \
 && useradd --uid "${DEV_UID}" --gid "${DEV_GID}" --create-home --shell /bin/bash dev \
 && mkdir -p \
    /workspace \
    /home/dev/l1-node-workspace/apps/web \
    /home/dev/.cargo/git \
    /home/dev/.cargo/registry \
    /home/dev/.cargo-target \
    /home/dev/.cache/uv \
    /home/dev/.local/share/pnpm/store \
 && chown -R dev:dev \
    /workspace \
    /home/dev/.cargo \
    /home/dev/.cargo-target \
    /home/dev/.cache \
    /home/dev/.local \
    /usr/local/cargo \
    /usr/local/rustup \
    /usr/local/fnm || true

# Seed the pnpm store into the same directory that L1 mounts as a named volume.
# Docker initializes fresh volumes from image contents, so first-run Node tests
# avoid redownloading hundreds of packages after Rust/Python have already run.
COPY --chown=dev:dev pnpm-lock.yaml pnpm-workspace.yaml /home/dev/l1-node-workspace/
COPY --chown=dev:dev apps/web/package.json /home/dev/l1-node-workspace/apps/web/package.json
RUN cd /home/dev/l1-node-workspace \
 && pnpm fetch --frozen-lockfile --store-dir /home/dev/l1-node-workspace/.pnpm-store \
 && chown -R dev:dev /home/dev/l1-node-workspace

WORKDIR /workspace

# Healthcheck proves every toolchain is invocable.
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD rustc --version >/dev/null \
   && cargo --version >/dev/null \
   && python3.11 --version >/dev/null \
   && uv --version >/dev/null \
   && node --version >/dev/null \
   && pnpm --version >/dev/null \
   || exit 1

# Default: print toolchain versions, then drop to a shell if overridden.
CMD ["bash", "-lc", "echo 'L1 devbase — toolchains:' && rustc --version && python3.11 --version && uv --version && node --version && pnpm --version"]
