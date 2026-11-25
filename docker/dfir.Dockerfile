# VERDICT DFIR toolchain image — the reproducible replacement for the SIFT VM.
#
# Why this exists: the SIFT VM was a bottleneck — un-reproducible, hard to
# update, network-isolated (so a missing tool like `tshark` could not be
# installed in-place), and slow over its hgfs shared folder. This image bakes
# the entire DFIR toolchain VERDICT invokes into one pinned, rebuildable layer
# so nothing is ever silently "missing," and evidence bind-mounts at native
# disk speed instead of over a FUSE share.
#
# Runs on a stock Docker daemon (no Sysbox). The evidence runtime is always
# unprivileged and capability-free. Raw images use direct Sleuth Kit reads;
# compressed EWF mounting must run locally/SIFT or be extracted first. See
# docs/using/docker-backend.md.
#
# Build:
#   docker build -f docker/dfir.Dockerfile -t findevil/dfir:local .
# Bring up as VERDICT's tool backend (exact parser files + evidence read-only):
#   scripts/verdict --docker <evidence-path>
#
# The VERDICT MCP server is NOT baked in. Bring-up builds it in a disposable,
# resource-bounded builder from exact read-only source/lockfile binds, exports
# only the bounded binary, and removes the builder before evidence is attached.
# The capability-free evidence runtime receives that binary as an exact
# read-only bind and never sees the repository or build toolchain. This file
# provisions the pinned DFIR toolchain and isolated Rust/uv build environment.

# Ubuntu 22.04 to match the SIFT Workstation base (tool ABI parity).
FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d

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
    gnupg \
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
    libesedb-utils \
    libvshadow-utils \
 && rm -rf /var/lib/apt/lists/* \
 && command -v esedbexport \
 && command -v vshadowinfo \
 && ln -sf /usr/bin/python3.11 /usr/bin/python3 \
 && ln -sf /usr/bin/python3.11 /usr/bin/python

# bulk_extractor — not in Ubuntu jammy apt. Build from the pinned upstream
# release tarball when possible; optional lane so a fetch/build failure must
# never fail the image (bulk_extract degrades to bulk_extractor_available=false).
# hadolint ignore=DL3003,DL3008
ARG BULK_EXTRACTOR_VERSION=2.1.1
ARG BULK_EXTRACTOR_SHA256=0cd57c743581a66ea94d49edac2e89210c80a2a7cc90dd254d56940b3d41b7f7
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      autoconf automake libtool flex bison libewf-dev libxml2-dev \
      zlib1g-dev libsqlite3-dev libexpat1-dev libre2-dev \
    || true; \
    curl -fsSL \
      "https://github.com/simsong/bulk_extractor/releases/download/v${BULK_EXTRACTOR_VERSION}/bulk_extractor-${BULK_EXTRACTOR_VERSION}.tar.gz" \
      -o /tmp/bulk_extractor.tgz \
    || true; \
    if [ -s /tmp/bulk_extractor.tgz ]; then \
      echo "${BULK_EXTRACTOR_SHA256}  /tmp/bulk_extractor.tgz" | /usr/bin/sha256sum -c -; \
      mkdir -p /tmp/bulk_src \
      && tar -xzf /tmp/bulk_extractor.tgz -C /tmp/bulk_src --strip-components=1 \
      && cd /tmp/bulk_src \
      && (test -x ./configure || (./bootstrap.sh || autoreconf -fi || true)) \
      && if [ -x ./configure ]; then \
           ./configure --prefix=/usr/local --disable-BEViewer \
           && make -j"$(nproc)" \
           && make install \
           && command -v bulk_extractor \
           && bulk_extractor -V || true; \
         else \
           echo "WARN: bulk_extractor configure missing; lane will degrade"; \
         fi; \
    else \
      echo "WARN: bulk_extractor tarball unavailable; lane will degrade"; \
    fi; \
    rm -rf /tmp/bulk_src /tmp/bulk_extractor.tgz /var/lib/apt/lists/* || true

# Volatility 3 — pinned to SIFT Workstation parity (requirements.txt).
# Make the symbols dirs writable: vol downloads Windows PDB symbols on first use
# and must cache them, but the non-root user cannot write the root-owned package
# dir otherwise (windows.info et al. fail with an unsatisfied-symbol error).
# hadolint ignore=DL3013
ARG VOLATILITY3_VERSION=2.27.0
ARG VOLATILITY3_SHA256=9d3693bd3ecf833a966d512247af77ce53c7a6dae0b692c95da1455cd75430d7
ARG PEFILE_VERSION=2024.8.26
ARG PEFILE_SHA256=76f8b485dcd3b1bb8166f1128d395fa3d87af26360c2358fb75b80019b957c6f
RUN printf '%s\n' \
      "volatility3==${VOLATILITY3_VERSION} --hash=sha256:${VOLATILITY3_SHA256}" \
      "pefile==${PEFILE_VERSION} --hash=sha256:${PEFILE_SHA256}" \
      > /tmp/volatility-requirements.txt \
 && pip install --no-cache-dir --require-hashes -r /tmp/volatility-requirements.txt \
 && rm -f /tmp/volatility-requirements.txt \
 && vol_dir="$(python3 -c 'import volatility3,os;print(os.path.dirname(volatility3.__file__))')" \
 && mkdir -p "${vol_dir}/symbols" "${vol_dir}/framework/symbols" \
 && chmod -R a+rwX "${vol_dir}/symbols" "${vol_dir}/framework/symbols"

# INDXParse ($I30/INDX slack — the indx_parse lane). Not on PyPI, so install
# from an exact source commit with a reviewed archive digest. Dependencies are
# separately hash-locked; the source package itself installs with --no-deps.
# hadolint ignore=DL3013
ARG INDXPARSE_COMMIT=038e8ec836cf23600124db74b40757b7184c08c5
ARG INDXPARSE_SHA256=c95bffe9595e94eecef080629d2083c52d7c0321450f5cd21e615e2c44060b6a
ARG JINJA2_VERSION=3.1.6
ARG JINJA2_SHA256=85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67
ARG MARKUPSAFE_VERSION=3.0.3
ARG MARKUPSAFE_SHA256=0bf2a864d67e76e5c9a34dc26ec616a66b9888e25e7b9460e1c76d3293bd9dbf
RUN curl -fsSL \
      "https://github.com/williballenthin/INDXParse/archive/${INDXPARSE_COMMIT}.tar.gz" \
      -o /tmp/indxparse.tgz \
 && echo "${INDXPARSE_SHA256}  /tmp/indxparse.tgz" | /usr/bin/sha256sum -c - \
 && printf '%s\n' \
      "Jinja2==${JINJA2_VERSION} --hash=sha256:${JINJA2_SHA256}" \
      "MarkupSafe==${MARKUPSAFE_VERSION} --hash=sha256:${MARKUPSAFE_SHA256}" \
      > /tmp/indxparse-requirements.txt \
 && pip install --no-cache-dir --require-hashes -r /tmp/indxparse-requirements.txt \
 && pip install --no-cache-dir --no-deps /tmp/indxparse.tgz \
 && rm -f /tmp/indxparse.tgz /tmp/indxparse-requirements.txt

# Hayabusa (subprocess only) + its Sigma rules. unzip drops the exec bit, so
# match the binary by exact name then chmod. The rules are NOT bundled with the
# release — `update-rules` fetches them, and without them every EVTX/Sigma scan
# returns 0 alerts. Bake them at a fixed path and point HAYABUSA_RULES_BASE at it.
ARG HAYABUSA_VERSION=2.19.0
ARG HAYABUSA_SHA256=c0c66036dff78ebf6c6b96bc0232b58f19c286e8b80ba176811070b493bcbd95
ARG HAYABUSA_RULES_COMMIT=acd8a5fc84bed17f9ed61b1aa553ba1c5db65f93
ARG HAYABUSA_RULES_SHA256=bff78417648e1ea0c2d8161dcebd332edfb7d8b824b414c9604b50147762c8ca
RUN curl -fsSL \
      "https://github.com/Yamato-Security/hayabusa/releases/download/v${HAYABUSA_VERSION}/hayabusa-${HAYABUSA_VERSION}-lin-x64-gnu.zip" \
      -o /tmp/hayabusa.zip \
 && echo "${HAYABUSA_SHA256}  /tmp/hayabusa.zip" | /usr/bin/sha256sum -c - \
 && unzip -q /tmp/hayabusa.zip -d /opt/hayabusa \
 && hb="$(find /opt/hayabusa -maxdepth 2 -name 'hayabusa-*-lin-x64-gnu' -type f | head -1)" \
 && chmod +x "${hb}" \
 && ln -sf "${hb}" /usr/local/bin/hayabusa \
 && rm -f /tmp/hayabusa.zip \
 && mkdir -p /opt/hayabusa-mcp \
 && curl -fsSL \
      "https://github.com/Yamato-Security/hayabusa-rules/archive/${HAYABUSA_RULES_COMMIT}.tar.gz" \
      -o /tmp/hayabusa-rules.tgz \
 && echo "${HAYABUSA_RULES_SHA256}  /tmp/hayabusa-rules.tgz" | /usr/bin/sha256sum -c - \
 && tar -xzf /tmp/hayabusa-rules.tgz -C /opt/hayabusa-mcp \
 && mv "/opt/hayabusa-mcp/hayabusa-rules-${HAYABUSA_RULES_COMMIT}" \
      /opt/hayabusa-mcp/rules \
 && rm -f /tmp/hayabusa-rules.tgz

# Chainsaw (subprocess only) — pinned release, shipped for EVTX/Sigma parity.
ARG CHAINSAW_VERSION=2.13.0
ARG CHAINSAW_SHA256=2308426f5d6eb42cfa13f1a95812d4f49071aec773cdac0f3e414c0042282638
RUN curl -fsSL \
      "https://github.com/WithSecureLabs/chainsaw/releases/download/v${CHAINSAW_VERSION}/chainsaw_all_platforms+rules.zip" \
      -o /tmp/chainsaw.zip \
 && echo "${CHAINSAW_SHA256}  /tmp/chainsaw.zip" | /usr/bin/sha256sum -c - \
 && unzip -q /tmp/chainsaw.zip -d /opt/chainsaw \
 && chmod +x /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu \
 && ln -sf /opt/chainsaw/chainsaw/chainsaw_x86_64-unknown-linux-gnu /usr/local/bin/chainsaw \
 && rm -f /tmp/chainsaw.zip

# Velociraptor (single static binary) — typed live-collection support. Download
# to a private staging path, verify the reviewed release digest, then install;
# the evidence runtime never performs an updater/network fetch.
ARG VELOCIRAPTOR_VERSION=0.74.6
ARG VELOCIRAPTOR_RELEASE=0.74
ARG VELOCIRAPTOR_SHA256=fd359cd1a3634847e10bd13d3ec969b78d42f50caca74914bb0f85b092da96fd
RUN curl -fsSL \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_RELEASE}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64-musl" \
      -o /tmp/velociraptor \
 && echo "${VELOCIRAPTOR_SHA256}  /tmp/velociraptor" | /usr/bin/sha256sum -c - \
 && install -m 0755 /tmp/velociraptor /usr/local/bin/velociraptor \
 && rm -f /tmp/velociraptor \
 && velociraptor version

# Pandoc (report rendering, host-side lane) — pinned static tarball.
ARG PANDOC_VERSION=3.1.11.1
ARG PANDOC_SHA256=07635f6953201ee261bf90e821b8fe36c045e5a6fbae2ae6b1c2127715432942
RUN curl -fsSL \
      "https://github.com/jgm/pandoc/releases/download/${PANDOC_VERSION}/pandoc-${PANDOC_VERSION}-linux-amd64.tar.gz" \
      -o /tmp/pandoc.tar.gz \
 && echo "${PANDOC_SHA256}  /tmp/pandoc.tar.gz" | /usr/bin/sha256sum -c - \
 && tar -xzf /tmp/pandoc.tar.gz -C /opt \
 && ln -sf "/opt/pandoc-${PANDOC_VERSION}/bin/pandoc" /usr/local/bin/pandoc \
 && rm -f /tmp/pandoc.tar.gz

# .NET runtime (Eric Zimmerman tools = ez_parse). Eric publishes the tools as
# cross-platform, framework-dependent .NET 9 builds: a managed `<Tool>.dll` plus
# a Windows apphost — no Linux apphost — so on Linux each runs as
# `dotnet <Tool>.dll`. We install the .NET 10 LTS runtime (currently the active
# LTS; .NET 9 is the shorter-support STS the tools target) and let the net9
# builds roll forward onto it via DOTNET_ROLL_FORWARD=Major. The exact runtime
# archive is SHA-512 verified; the `dotnet` symlink lands on PATH via
# /usr/local/bin. All seven allow-listed wrappers are executed during the
# isolated launcher preflight, before evidence or the workspace is mounted;
# a deliberately partial image must use the documented bring-up escape hatch
# rather than silently degrading the recommended backend.
ARG DOTNET_VERSION=10.0.9
ARG DOTNET_SHA512=e413f4914e7911e1cd994aa01c433cb30c3f505b369ff55c6c61d130dcd4305e0e078dbe9dc05b27d10514cf3afce08fc7797bc64f7fa0d9945381a805f85cb9
RUN curl -fsSL \
      "https://builds.dotnet.microsoft.com/dotnet/Runtime/${DOTNET_VERSION}/dotnet-runtime-${DOTNET_VERSION}-linux-x64.tar.gz" \
      -o /tmp/dotnet-runtime.tar.gz \
 && echo "${DOTNET_SHA512}  /tmp/dotnet-runtime.tar.gz" | /usr/bin/sha512sum -c - \
 && mkdir -p /opt/dotnet \
 && tar -xzf /tmp/dotnet-runtime.tar.gz -C /opt/dotnet \
 && ln -sf /opt/dotnet/dotnet /usr/local/bin/dotnet \
 && rm -f /tmp/dotnet-runtime.tar.gz \
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
# URLs serve the current build (Eric does not version the download path), so we
# content-pin each archive. Updating an EZ tool is an explicit digest review,
# not an invisible change on the next image rebuild.
ARG EZ_LECMD_SHA256=f3e9c799ec7d3fa4cd5f553ec3f9d544c80c8e48afd04ef43456da3d48ad0760
ARG EZ_JLECMD_SHA256=155ee54e6ac6b70bce1aa636ec52d0b0165263933764d9a45c85af97df546892
ARG EZ_AMCACHEPARSER_SHA256=d40d1e7863159dbd9aa3ae826d919edc490ca33df84bde57e86da848a583af03
ARG EZ_APPCOMPATCACHEPARSER_SHA256=67756841dbcd8ca3f47083be2b016a22f61bde0ea3450f0a776cf878bf66d42d
ARG EZ_RBCMD_SHA256=e2b5c6ba8929a8731d861577c796763730e303ec2d4dd8d294ee0de8d5ceb541
ARG EZ_SBECMD_SHA256=88edb98a32baaf68114aa106f25f999e46d387d9d0003d3222a1168cc1b7eb9b
ARG EZ_WXTCMD_SHA256=aa08a020cc9daa22551edbf07bca336cb8249ce29830d67cf09bc3703dffec6d
RUN set -eu; \
    mkdir -p /opt/eztools /opt/eztools-net9 \
 && for spec in \
      "LECmd:${EZ_LECMD_SHA256}" \
      "JLECmd:${EZ_JLECMD_SHA256}" \
      "AmcacheParser:${EZ_AMCACHEPARSER_SHA256}" \
      "AppCompatCacheParser:${EZ_APPCOMPATCACHEPARSER_SHA256}" \
      "RBCmd:${EZ_RBCMD_SHA256}" \
      "SBECmd:${EZ_SBECMD_SHA256}" \
      "WxTCmd:${EZ_WXTCMD_SHA256}" ; do \
      tool="${spec%%:*}" ; \
      expected_sha256="${spec#*:}" ; \
      curl -fsSL "https://download.ericzimmermanstools.com/net9/${tool}.zip" \
        -o "/tmp/${tool}.zip" || exit 1 ; \
      printf '%s  %s\n' "${expected_sha256}" "/tmp/${tool}.zip" \
        | /usr/bin/sha256sum -c - || exit 1 ; \
      unzip -q -o "/tmp/${tool}.zip" -d "/opt/eztools-net9/${tool}" || exit 1 ; \
      test -f "/opt/eztools-net9/${tool}/${tool}.dll" || exit 1 ; \
      printf '#!/bin/sh\nexec /opt/dotnet/dotnet "/opt/eztools-net9/%s/%s.dll" "$@"\n' \
        "${tool}" "${tool}" > "/opt/eztools/${tool}" || exit 1 ; \
      chmod +x "/opt/eztools/${tool}" || exit 1 ; \
      rm -f "/tmp/${tool}.zip" || exit 1 ; \
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
# The two CLI stages are build-probed here and executed again by the isolated
# launcher preflight. A broken distro-Python / libyal binding must fail image
# readiness before a Case can rely on this lane.
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
 && gift_primary_fprs="$(gpg --batch --show-keys --with-colons /etc/apt/keyrings/gift.asc \
      | awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }')" \
 && gift_primary_count="$(printf '%s\n' "${gift_primary_fprs}" | grep -c .)" \
 && test "${gift_primary_count}" = "1" \
 && gift_actual_fpr="${gift_primary_fprs}" \
 && test "${gift_actual_fpr}" = "${GIFT_PPA_FPR}" \
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

# libewf CLI tools, rebuilt from upstream source AFTER the GIFT layer.
#
# The apt line above installs jammy's `ewf-tools`, but plaso-tools drags in the
# GIFT PPA's `libewf`, which Conflicts: jammy's `libewf2` — so apt silently
# REMOVES ewf-tools while resolving plaso. That is the eviction predicted in
# services/mcp/src/tools/disk.rs. The result shipped: v0.5.0-beta.3 had zero
# /usr/bin/ewf* binaries and failed its own HEALTHCHECK on `ewfexport -V`.
# Re-adding `ewf-tools` here cannot work — apt hits pkgProblemResolver breaks.
#
# So build upstream libewf into a private prefix and link the tools against it
# with an RPATH. /opt/libewf/lib is NEVER added to ld.so.conf, so plaso's
# python3-libewf bindings keep loading the GIFT shared library they were built
# against, while our CLI tools get a modern libewf.
#
# Scope: this restores the missing binaries. It is NOT known to fix the
# multi-segment .E01 truncation docs/using/docker-backend.md warns about — on a
# segmented .E01+.E02 test image `ewfverify` SUCCEEDS under both the 2014 tools
# and 20240506, so that caveat is unreproduced, not disproven.
ARG LIBEWF_VERSION=20240506
ARG LIBEWF_SHA256=247d8ee9572392a2404be514d1137f099970f41f240c1134ddc3f04322281c67
# hadolint ignore=DL3003,DL3008
RUN apt-get update \
 && apt-get install -y --no-install-recommends zlib1g-dev libbz2-dev \
 && curl -fsSL "https://github.com/libyal/libewf/releases/download/${LIBEWF_VERSION}/libewf-experimental-${LIBEWF_VERSION}.tar.gz" \
      -o /tmp/libewf.tar.gz \
 && echo "${LIBEWF_SHA256}  /tmp/libewf.tar.gz" | /usr/bin/sha256sum -c - \
 && tar -xzf /tmp/libewf.tar.gz -C /tmp \
 && cd "/tmp/libewf-${LIBEWF_VERSION}" \
 && ./configure --prefix=/opt/libewf --enable-static-executables=no \
      LDFLAGS="-Wl,-rpath,/opt/libewf/lib" \
 && make -j"$(nproc)" \
 && make install \
 && cd / && rm -rf "/tmp/libewf-${LIBEWF_VERSION}" /tmp/libewf.tar.gz \
 && rm -rf /var/lib/apt/lists/* \
 && for t in ewfinfo ewfexport ewfmount ewfverify ewfacquire; do \
      ln -sf "/opt/libewf/bin/${t}" "/usr/local/bin/${t}" ; \
    done \
 && ewfinfo -V \
 && ewfexport -V \
 && ewfmount -V

# esedbexport + vshadowinfo — same GIFT-PPA eviction pattern as ewf-tools.
# jammy's libesedb-utils / libvshadow-utils install early, then plaso-tools
# pulls GIFT's library-only packages and drops the CLI utils. Rebuild from
# libyal into /opt prefixes with RPATH (do not touch GIFT shared libs).
# hadolint ignore=DL3003,DL3008
ARG LIBESEDB_VERSION=20240420
ARG LIBESEDB_SHA256=07250741dff8a1ea1f5e38c02f1b9a1ae5e9fa52d013401067338842883a5b9f
ARG LIBVSHADOW_VERSION=20240504
ARG LIBVSHADOW_SHA256=b0463c64cbf44b4168ad0032c5dad6da7d45ddc3839a0322a5b86656ab7e03bf
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential pkg-config \
      autoconf automake libtool gettext \
 && curl -fsSL "https://github.com/libyal/libesedb/releases/download/${LIBESEDB_VERSION}/libesedb-experimental-${LIBESEDB_VERSION}.tar.gz" \
      -o /tmp/libesedb.tar.gz \
 && echo "${LIBESEDB_SHA256}  /tmp/libesedb.tar.gz" | /usr/bin/sha256sum -c - \
 && tar -xzf /tmp/libesedb.tar.gz -C /tmp \
 && cd "/tmp/libesedb-${LIBESEDB_VERSION}" \
 && ./configure --prefix=/opt/libesedb --enable-static-executables=no \
      LDFLAGS="-Wl,-rpath,/opt/libesedb/lib" \
 && make -j"$(nproc)" \
 && make install \
 && curl -fsSL "https://github.com/libyal/libvshadow/releases/download/${LIBVSHADOW_VERSION}/libvshadow-alpha-${LIBVSHADOW_VERSION}.tar.gz" \
      -o /tmp/libvshadow.tar.gz \
 && echo "${LIBVSHADOW_SHA256}  /tmp/libvshadow.tar.gz" | /usr/bin/sha256sum -c - \
 && tar -xzf /tmp/libvshadow.tar.gz -C /tmp \
 && cd "/tmp/libvshadow-${LIBVSHADOW_VERSION}" \
 && ./configure --prefix=/opt/libvshadow --enable-static-executables=no \
      LDFLAGS="-Wl,-rpath,/opt/libvshadow/lib" \
 && make -j"$(nproc)" \
 && make install \
 && cd / && rm -rf /tmp/libesedb-* /tmp/libvshadow-* /tmp/libesedb.tar.gz /tmp/libvshadow.tar.gz \
 && rm -rf /var/lib/apt/lists/* \
 && ln -sf /opt/libesedb/bin/esedbexport /usr/local/bin/esedbexport \
 && ln -sf /opt/libvshadow/bin/vshadowinfo /usr/local/bin/vshadowinfo \
 && ln -sf /opt/libvshadow/bin/vshadowmount /usr/local/bin/vshadowmount \
 && esedbexport -h >/dev/null \
 && vshadowinfo -h >/dev/null

# Rust toolchain pinned to rust-toolchain.toml. Install Rust from the
# official combined compiler archive with an independently verified digest;
# rustup's small bootstrap binary is insufficient because it downloads mutable
# channel metadata/components after its own digest check. Installed system-wide
# so the non-root parser builder can compile findevil-mcp.
ARG RUST_VERSION=1.91.0
ARG RUST_TOOLCHAIN_SHA256=5bea12c1911dda5c0a91cee4e9b617a65bcf23a21e2852a17b544936de1f83e3
ENV CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/toolchain/bin:/root/.local/bin:/usr/local/bin:${PATH}
RUN curl -fsSL \
      "https://static.rust-lang.org/dist/rust-${RUST_VERSION}-x86_64-unknown-linux-gnu.tar.xz" \
      -o /tmp/rust-toolchain.tar.xz \
 && echo "${RUST_TOOLCHAIN_SHA256}  /tmp/rust-toolchain.tar.xz" | /usr/bin/sha256sum -c - \
 && mkdir -p /tmp/rust-toolchain /opt/rust/toolchain /opt/rust/cargo \
 && tar -xJf /tmp/rust-toolchain.tar.xz -C /tmp/rust-toolchain --strip-components=1 \
 && /tmp/rust-toolchain/install.sh --prefix=/opt/rust/toolchain --disable-ldconfig \
 && /opt/rust/toolchain/bin/rustc --version \
 && /opt/rust/toolchain/bin/cargo --version \
 && rm -rf /tmp/rust-toolchain /tmp/rust-toolchain.tar.xz \
 && chmod -R a+rX /opt/rust \
 && chmod 1777 /opt/rust/cargo \
 && chmod -R go-w /opt/rust/toolchain/bin

# Point VERDICT's MCP tools at the toolchain. Every subprocess tool degrades to
# a typed BinaryNotFound when absent, so these are hints, not hard requirements.
ENV HAYABUSA_BIN=/usr/local/bin/hayabusa \
    HAYABUSA_RULES_BASE=/opt/hayabusa-mcp \
    CHAINSAW_BIN=/usr/local/bin/chainsaw \
    TSHARK_BIN=/usr/bin/tshark \
    SURICATA_BIN=/usr/bin/suricata \
    NFDUMP_BIN=/usr/bin/nfdump \
    AUSEARCH_BIN=/sbin/ausearch \
    VOLATILITY_BIN=/usr/local/bin/vol \
    EZTOOLS_DIR=/opt/eztools \
    FINDEVIL_FLS_BIN=/usr/bin/fls \
    FINDEVIL_ICAT_BIN=/usr/bin/icat \
    EWF_MOUNT_BIN=/usr/local/bin/ewfmount \
    FINDEVIL_ESEDBEXPORT_BIN=/usr/local/bin/esedbexport \
    FINDEVIL_VSHADOWINFO_BIN=/usr/local/bin/vshadowinfo \
    FINDEVIL_MOUNT_BIN=/bin/mount \
    FINDEVIL_UMOUNT_BIN=/bin/umount

# Non-root parser user. The image deliberately contains no sudo policy: hostile
# evidence and native parsers never gain a root command path. Raw disk tools can
# still use direct, read-only Sleuth Kit access without a kernel mount.
ARG DEV_UID=1000
ARG DEV_GID=1000
RUN groupadd --gid "${DEV_GID}" analyst \
 && useradd --uid "${DEV_UID}" --gid "${DEV_GID}" --create-home --shell /bin/bash analyst \
 && mkdir -p /evidence /workspace \
 && chown -R analyst:analyst /workspace

# Seal the exact executables and managed parser payloads exercised by the
# isolated preflight. Plaso is a Python application, so its Python 3.10
# interpreter, standard library, distro package tree, formatter/signature data,
# and forensic-artifact definitions are part of the payload—not merely its two
# shell entrypoints. The mounted runtime HEALTHCHECK validates this manifest
# with trusted coreutils; it never repeatedly executes third-party parser code
# in the mounted evidence runtime.
RUN set -eu; \
    rule_count="$(/usr/bin/find \
      /opt/hayabusa-mcp/rules/config \
      /opt/hayabusa-mcp/rules/hayabusa \
      /opt/hayabusa-mcp/rules/sigma \
      -type f | /usr/bin/wc -l)" ; \
    test "${rule_count}" -ge 1000 ; \
    mkdir -p /opt/verdict \
 && /usr/bin/sha256sum \
      /usr/bin/tshark \
      /usr/bin/fls \
      /usr/bin/icat \
      /usr/local/bin/ewfexport \
      /usr/local/bin/ewfmount \
      /usr/bin/mmls \
      /usr/local/bin/vol \
      /usr/local/bin/hayabusa \
      /usr/local/bin/bulk_extractor \
      /usr/local/bin/chainsaw \
      /usr/local/bin/velociraptor \
      /usr/local/bin/pandoc \
      /usr/local/bin/INDXParse.py \
      /usr/local/bin/esedbexport \
      /usr/local/bin/vshadowinfo \
      /usr/bin/suricata \
      /usr/bin/nfdump \
      /usr/sbin/ausearch \
      /usr/bin/yara \
      /usr/local/bin/log2timeline.py \
      /usr/local/bin/psort.py \
      /usr/bin/python3.10 \
      /usr/bin/log2timeline.py \
      /usr/bin/psort.py \
      /opt/eztools/LECmd \
      /opt/eztools/JLECmd \
      /opt/eztools/AmcacheParser \
      /opt/eztools/AppCompatCacheParser \
      /opt/eztools/RBCmd \
      /opt/eztools/SBECmd \
      /opt/eztools/WxTCmd \
      > /opt/verdict/dfir-toolchain.sha256 \
 && /usr/bin/find \
      /opt/dotnet \
      /usr/lib/python3.10 \
      /usr/lib/python3/dist-packages \
      /usr/local/lib/python3.11/dist-packages \
      /usr/share/plaso \
      /usr/share/artifacts \
      /opt/eztools-net9/LECmd \
      /opt/eztools-net9/JLECmd \
      /opt/eztools-net9/AmcacheParser \
      /opt/eztools-net9/AppCompatCacheParser \
      /opt/eztools-net9/RBCmd \
      /opt/eztools-net9/SBECmd \
      /opt/eztools-net9/WxTCmd \
      /opt/hayabusa-mcp/rules/config \
      /opt/hayabusa-mcp/rules/hayabusa \
      /opt/hayabusa-mcp/rules/sigma \
      -type f -print0 > /tmp/dfir-toolchain-files \
 && /usr/bin/sort -z -o /tmp/dfir-toolchain-files /tmp/dfir-toolchain-files \
 && /usr/bin/xargs -0 -r /usr/bin/sha256sum \
      < /tmp/dfir-toolchain-files >> /opt/verdict/dfir-toolchain.sha256 \
 && rm -f /tmp/dfir-toolchain-files \
 && chmod 0444 /opt/verdict/dfir-toolchain.sha256

HEALTHCHECK --interval=30s --timeout=15s --retries=3 \
  CMD /usr/bin/sha256sum --check --status /opt/verdict/dfir-toolchain.sha256

USER analyst
WORKDIR /workspace

# Long-lived by default so `docker exec -i` can drive the MCP servers (the
# container analog of `ssh -T` into the SIFT VM). run-dfir-container.sh starts
# it detached; a bare `docker run` just prints a readiness banner.
CMD ["bash", "-lc", "/usr/bin/sha256sum --check --status /opt/verdict/dfir-toolchain.sha256 && echo 'VERDICT DFIR container ready; toolchain integrity verified.' && exec sleep infinity"]
