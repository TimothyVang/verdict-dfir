# VERDICT DFIR toolchain image — the reproducible replacement for the SIFT VM.
#
# Why this exists: the SIFT VM was a bottleneck — un-reproducible, hard to
# update, network-isolated (so a missing tool like `tshark` could not be
# installed in-place), and slow over its hgfs shared folder. This image bakes
# the entire DFIR toolchain VERDICT invokes into one pinned, rebuildable layer
# so nothing is ever silently "missing," and evidence bind-mounts at native
# disk speed instead of over a FUSE share.
#
# Runs on a stock Docker daemon (no Sysbox). Disk-image mounting (ewfmount /
# FUSE) needs `--cap-add SYS_ADMIN --device /dev/fuse` at `docker run` time;
# everything else (memory, pcap, evtx, registry, artifact parsing) runs with no
# extra privileges. See docs/using/docker-backend.md.
#
# Build:
#   docker build -f docker/dfir.Dockerfile -t findevil/dfir:local .
# Bring up as VERDICT's tool backend (repo + evidence bind-mounted read-only):
#   scripts/run-dfir-container.sh <evidence-path>
#
# The VERDICT MCP server is NOT baked in — it is built inside the running
# container from the bind-mounted repo on first bring-up (mirrors how
# sift-vm-bootstrap builds it in the VM), so the image stays decoupled from any
# single repo snapshot. This file provisions the toolchain + the Rust/uv build
# environment it is compiled with.

# Ubuntu 22.04 to match the SIFT Workstation base (tool ABI parity).
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# System deps + DFIR binaries available from apt.
# Mirrors docker/l2-siftlite.Dockerfile's proven set, plus the gaps the SIFT VM
# was missing: tshark (pcap_triage — THE tool that was absent), suricata,
# nfdump, auditd(ausearch); plus the Rust C-build deps (libclang/pkg-config/
# libssl) so findevil-mcp compiles inside the container. libicu70 is the ICU
# globalization runtime the .NET-based Eric Zimmerman tools (ez_parse) need.
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
    build-essential \
    pkg-config \
    libclang-dev \
    libssl-dev \
    sleuthkit \
    ewf-tools \
    afflib-tools \
    fuse \
    libfuse-dev \
    yara \
    libyara-dev \
    tshark \
    suricata \
    nfdump \
    auditd \
    libicu70 \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# Volatility 3 — pinned to SIFT Workstation parity (requirements.txt).
# Make the symbols dirs writable: vol downloads Windows PDB symbols on first use
# and must cache them, but the non-root user cannot write the root-owned package
# dir otherwise (windows.info et al. fail with an unsatisfied-symbol error).
# hadolint ignore=DL3013
RUN pip install --no-cache-dir 'volatility3==2.27.0' \
 && vol_dir="$(python3 -c 'import volatility3,os;print(os.path.dirname(volatility3.__file__))')" \
 && mkdir -p "${vol_dir}/symbols" "${vol_dir}/framework/symbols" \
 && chmod -R a+rwX "${vol_dir}/symbols" "${vol_dir}/framework/symbols"

# INDXParse ($I30/INDX slack — the indx_parse lane). Not on PyPI, so install
# from source, best-effort: it is an optional lane (BinaryNotFound-graceful), so
# a fetch/packaging hiccup must never fail the image build.
# hadolint ignore=DL3013
RUN pip install --no-cache-dir 'git+https://github.com/williballenthin/INDXParse.git' || true

# Hayabusa (subprocess only) + its Sigma rules. unzip drops the exec bit, so
# match the binary by exact name then chmod. The rules are NOT bundled with the
# release — `update-rules` fetches them, and without them every EVTX/Sigma scan
# returns 0 alerts. Bake them at a fixed path and point HAYABUSA_RULES_BASE at it.
ARG HAYABUSA_VERSION=2.19.0
RUN curl -fsSL \
      "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
      -o /tmp/hayabusa.zip \
 && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
 && hb="$(find /opt/hayabusa -maxdepth 2 -name 'hayabusa-*-lin-x64-gnu' -type f | head -1)" \
 && chmod +x "${hb}" \
 && ln -sf "${hb}" /usr/local/bin/hayabusa \
 && rm -f /tmp/hayabusa.zip \
 && mkdir -p /opt/hayabusa-mcp \
 && hayabusa update-rules -r /opt/hayabusa-mcp/rules || true

# Chainsaw (subprocess only) — pinned release, shipped for EVTX/Sigma parity.
ARG CHAINSAW_VERSION=2.13.0
RUN curl -fsSL \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip" \
      -o /tmp/chainsaw.zip \
 && unzip -q /tmp/chainsaw.zip -d /opt/chainsaw \
 && chmod +x /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu \
 && ln -sf /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu /usr/local/bin/chainsaw \
 && rm -f /tmp/chainsaw.zip

# Velociraptor (single static binary) — live-collection lane (vel_collect).
ARG VELOCIRAPTOR_VERSION=0.74.6
ARG VELOCIRAPTOR_RELEASE=0.74
RUN curl -fsSL \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_RELEASE}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64-musl" \
      -o /usr/local/bin/velociraptor \
 && chmod +x /usr/local/bin/velociraptor

# Pandoc (report rendering, host-side lane) — pinned static tarball.
ARG PANDOC_VERSION=3.1.11.1
RUN curl -fsSL \
      "https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz" \
      -o /tmp/pandoc.tar.gz \
 && tar -xzf /tmp/pandoc.tar.gz -C /opt \
 && ln -sf "/opt/pandoc-${PANDOC_VERSION}/bin/pandoc" /usr/local/bin/pandoc \
 && rm -f /tmp/pandoc.tar.gz

# .NET runtime (Eric Zimmerman tools = ez_parse). Eric publishes the tools as
# cross-platform, framework-dependent .NET 9 builds: a managed `<Tool>.dll` plus
# a Windows apphost — no Linux apphost — so on Linux each runs as
# `dotnet <Tool>.dll`. We install the .NET 10 LTS runtime (currently the active
# LTS; .NET 9 is the shorter-support STS the tools target) and let the net9
# builds roll forward onto it via DOTNET_ROLL_FORWARD=Major. dotnet-install.sh
# pins the exact runtime patch; the `dotnet` symlink lands on PATH via
# /usr/local/bin. This is a hint tool — ez_parse degrades to a typed
# BinaryNotFound when EZTOOLS_DIR is empty — so it is NOT added to HEALTHCHECK.
ARG DOTNET_VERSION=10.0.9
RUN curl -fsSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh \
 && chmod +x /tmp/dotnet-install.sh \
 && /tmp/dotnet-install.sh --runtime dotnet --version "${DOTNET_VERSION}" \
      --install-dir /opt/dotnet --no-path \
 && ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet \
 && rm -f /tmp/dotnet-install.sh \
 && dotnet --list-runtimes

ENV DOTNET_ROOT=/opt/dotnet \
    DOTNET_ROLL_FORWARD=Major \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# Eric Zimmerman tools (ez_parse): the .NET decoders for the Windows execution /
# persistence / anti-forensic artifacts (LNK, jump-lists, Amcache, ShimCache,
# Recycle Bin, shellbags, Win10 Timeline). We fetch only the seven binaries the
# ez_parse allow-list uses, then write a thin exec-wrapper per tool named
# EXACTLY as the tool resolves it ($EZTOOLS_DIR/<Tool>) — ez_parse invokes the
# bare name, not `dotnet <dll>`, so the wrapper bridges the two. The published
# URLs serve the current build (Eric does not version the download path), so the
# EZ tool build itself is not pinnable here; the .NET runtime is.
RUN mkdir -p /opt/eztools /opt/eztools-net9 \
 && for tool in LECmd JLECmd AmcacheParser AppCompatCacheParser RBCmd SBECmd WxTCmd; do \
      curl -fsSL "https://download.ericzimmermanstools.com/net9/${tool}.zip" \
        -o "/tmp/${tool}.zip" ; \
      unzip -q -o "/tmp/${tool}.zip" -d "/opt/eztools-net9/${tool}" ; \
      test -f "/opt/eztools-net9/${tool}/${tool}.dll" ; \
      printf '#!/bin/sh\nexec /opt/dotnet/dotnet "/opt/eztools-net9/%s/%s.dll" "$@"\n' \
        "${tool}" "${tool}" > "/opt/eztools/${tool}" ; \
      chmod +x "/opt/eztools/${tool}" ; \
      rm -f "/tmp/${tool}.zip" ; \
    done \
 && /opt/eztools/LECmd --help >/dev/null \
 && /opt/eztools/AmcacheParser --help >/dev/null

# plaso / log2timeline (plaso_parse): the super-timeline builder + long-tail log
# normalizer (syslog, utmp, dpkg, selinux, legacy winevt/msiecf/winjob, recycle
# bin, macOS asl). The GIFT stable PPA ships prebuilt plaso-tools with the heavy
# libyal native deps already compiled, so it is the clean container path (vs pip
# building libyal from source). Added the lean way — armored key into a keyring
# + a signed-by source, no software-properties-common. log2timeline.py/psort.py
# land in /usr/bin; plaso_parse finds them on PATH ($PLASO_DIR then PATH).
# Optional lane — NOT added to HEALTHCHECK; degrades to BinaryNotFound.
#
# Interpreter pin: plaso's C-extensions (pytsk3, libbde, ...) are compiled for
# jammy's distro python3.10, but the base layer repoints /usr/bin/python3 at
# 3.11 (VERDICT's runtime). plaso's `#!/usr/bin/python3` shebang would then load
# under 3.11 and fail (`ModuleNotFoundError: pytsk3`). So we shadow the two CLIs
# with PATH-preceding wrappers in /usr/local/bin that force python3.10 (present
# as a plaso dependency) — leaving python3 -> 3.11 intact for everything else.
ARG GIFT_PPA_FPR=3ED1EAECE81894B171D7DA5B5E80511B10C598B8
# hadolint ignore=DL3008
RUN install -d -m 0755 /etc/apt/keyrings \
 && curl -fsSL "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x${GIFT_PPA_FPR}" \
      -o /etc/apt/keyrings/gift.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/gift.asc] https://ppa.launchpadcontent.net/gift/stable/ubuntu jammy main" \
      > /etc/apt/sources.list.d/gift-stable.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends plaso-tools \
 && rm -rf /var/lib/apt/lists/* \
 && for s in log2timeline.py psort.py; do \
      printf '#!/bin/sh\nexec /usr/bin/python3.10 "/usr/bin/%s" "$@"\n' "${s}" \
        > "/usr/local/bin/${s}" ; \
      chmod +x "/usr/local/bin/${s}" ; \
    done \
 && log2timeline.py --version \
 && psort.py --version

# Rust toolchain (pinned to rust-toolchain.toml) + uv — the build environment
# findevil-mcp (Rust) and findevil-agent-mcp (Python) are compiled with at
# container bring-up. Installed system-wide so the non-root user can build.
ARG RUST_VERSION=1.88.0
ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:/root/.local/bin:/usr/local/bin:${PATH}
RUN curl -fsSL https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain "${RUST_VERSION}" --component clippy,rustfmt \
 && curl -fsSL https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh \
 && chmod -R a+rX /opt/rust \
 && chmod -R a+rwX /opt/rust/cargo

# Point VERDICT's MCP tools at the toolchain. Every subprocess tool degrades to
# a typed BinaryNotFound when absent, so these are hints, not hard requirements.
ENV HAYABUSA_BIN=/usr/local/bin/hayabusa \
    HAYABUSA_RULES_BASE=/opt/hayabusa-mcp \
    CHAINSAW_BIN=/usr/local/bin/chainsaw \
    VELOCIRAPTOR_BIN=/usr/local/bin/velociraptor \
    TSHARK_BIN=/usr/bin/tshark \
    SURICATA_BIN=/usr/bin/suricata \
    NFDUMP_BIN=/usr/bin/nfdump \
    AUSEARCH_BIN=/sbin/ausearch \
    VOLATILITY_BIN=/usr/local/bin/vol \
    EZTOOLS_DIR=/opt/eztools \
    FINDEVIL_FLS_BIN=/usr/bin/fls \
    FINDEVIL_ICAT_BIN=/usr/bin/icat \
    EWF_MOUNT_BIN=/usr/bin/ewfmount \
    FINDEVIL_MOUNT_BIN=/bin/mount \
    FINDEVIL_UMOUNT_BIN=/bin/umount

# Non-root user; evidence mounts read-only at /evidence, repo at /workspace.
# disk_mount loop-mounts the image read-only, which needs root: the DFIR tools
# invoke ewfmount / mount / umount / mmls via `sudo -n` (services/mcp/src/tools/
# disk.rs::run_sudo_fixed), exactly as the SIFT VM does. Grant the non-root
# analyst passwordless sudo so disk_mount -> disk_extract_artifacts works in the
# container; without it every raw disk stays custody-only. This is scoped to a
# single-purpose, ephemeral forensic container that already runs with SYS_ADMIN
# + unconfined apparmor for disk mounting and read-only evidence, mirroring the
# SIFT sansforensics passwordless-sudo setup.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN groupadd --gid "${DEV_GID}" analyst \
 && useradd --uid "${DEV_UID}" --gid "${DEV_GID}" --create-home --shell /bin/bash analyst \
 && mkdir -p /evidence /workspace \
 && chown -R analyst:analyst /workspace \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'analyst ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/analyst-dfir \
 && chmod 0440 /etc/sudoers.d/analyst-dfir \
 && visudo -cf /etc/sudoers.d/analyst-dfir

# Prove the toolchain is invocable — the failure mode this image exists to kill.
HEALTHCHECK --interval=30s --timeout=15s --retries=3 \
  CMD tshark --version >/dev/null 2>&1 \
   && fls -V >/dev/null 2>&1 \
   && ewfexport -V >/dev/null 2>&1 \
   && command -v hayabusa >/dev/null \
   && (vol --version >/dev/null 2>&1 || python3 -c "import volatility3") \
   || exit 1

USER analyst
WORKDIR /workspace

# Long-lived by default so `docker exec -i` can drive the MCP servers (the
# container analog of `ssh -T` into the SIFT VM). run-dfir-container.sh starts
# it detached; a bare `docker run` just prints a readiness banner.
CMD ["bash", "-lc", "echo 'VERDICT DFIR container ready.'; tshark --version | head -1; fls -V; hayabusa --version | head -1; vol --version 2>&1 | head -1; dotnet --list-runtimes 2>/dev/null | head -1; /opt/eztools/LECmd --help 2>/dev/null | grep -m1 -i 'LECmd version' || true; log2timeline.py --version 2>&1 | head -1 || true"]
