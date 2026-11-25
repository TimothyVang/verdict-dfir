# Spec #3 §4.3 — L2 "SIFT-lite" image.
#
# Runs on Sysbox runtime (nestybox/sysbox-runc) so systemd, FUSE, and
# loopback devices work inside the container WITHOUT --privileged.
# This is the intermediate tier between L1 (no DFIR tools) and L3
# (full QEMU microvm from the real OVA).
#
# Usage (LOCAL, requires Sysbox installed):
#   docker build -f docker/l2-siftlite.Dockerfile -t findevil/l2-siftlite:local .
#   docker run --runtime=sysbox-runc --rm \
#       -v $(pwd)/fixtures:/fixtures:ro \
#       -v $(pwd)/goldens:/goldens:ro \
#       findevil/l2-siftlite:local \
#       /usr/local/bin/run-dfir-smoke.sh
#
# Budget: 5-10 min per smoke run. ADVISORY ONLY in CI per Spec #3 §4.3 —
# DFIR tool flakiness must not stall the PR pipeline.

# Sysbox's systemd-aware Ubuntu base. Without Sysbox, this image will
# still build, but `systemctl` operations will fail at runtime —
# enforce the Sysbox runtime at `docker run`.
# hadolint ignore=DL3007
FROM nestybox/ubuntu-22.04-systemd:latest

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# Core system deps — superset of L1 for DFIR tool invocation.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    unzip \
    xz-utils \
    zstd \
    python3.11 \
    python3.11-venv \
    python3-pip \
    libewf-utils \
    libafflib-utils \
    sleuthkit \
    ewf-tools \
    afflib-tools \
    fuse \
    libfuse-dev \
    yara \
    libyara-dev \
    build-essential \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# Volatility3 — pinned to 2.x per Spec #2 §16.
# hadolint ignore=DL3013
RUN pip install --no-cache-dir 'volatility3==2.11.0'

# Hayabusa 2.x (AGPL-3.0, subprocess only) from the official release tarball.
# Pinned by version. unzip drops the exec bit, so the old `-type f -executable`
# find matched nothing and left no symlink (hayabusa was silently absent); match
# by exact name then chmod +x.
ARG HAYABUSA_VERSION=2.19.0
RUN curl -fsSL \
      "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
      -o /tmp/hayabusa.zip \
 && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
 && hb="$(find /opt/hayabusa -maxdepth 2 -name 'hayabusa-*-lin-x64-gnu' -type f | head -1)" \
 && chmod +x "${hb}" \
 && ln -sf "${hb}" /usr/local/bin/hayabusa \
 && rm -f /tmp/hayabusa.zip

# Chainsaw v2.x (GPL-2.0, subprocess only). Same pattern — pinned release.
ARG CHAINSAW_VERSION=2.13.0
RUN curl -fsSL \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip" \
      -o /tmp/chainsaw.zip \
 && unzip -q /tmp/chainsaw.zip -d /opt/chainsaw \
 && chmod +x /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu \
 && ln -sf /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu \
           /usr/local/bin/chainsaw \
 && rm -f /tmp/chainsaw.zip

# Smoke script placement.
COPY scripts/l2-dfir-smoke.sh /usr/local/bin/run-dfir-smoke.sh
RUN chmod +x /usr/local/bin/run-dfir-smoke.sh

# Non-root dev user for non-systemd runs; Sysbox invocations use the
# container's systemd init as PID 1.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN groupadd --gid "${DEV_GID}" dev \
 && useradd --uid "${DEV_UID}" --gid "${DEV_GID}" --create-home --shell /bin/bash dev \
 && mkdir -p /fixtures /goldens /workspace \
 && chown -R dev:dev /workspace

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD command -v hayabusa >/dev/null \
   && command -v chainsaw >/dev/null \
   && vol --version >/dev/null 2>&1 || python3 -c "import volatility3" \
   || exit 1

CMD ["bash", "-lc", "echo 'L2 SIFT-lite ready.' && hayabusa --version && chainsaw --version && vol --version 2>&1 | head -1"]
