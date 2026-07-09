# DFIR container backend — the SIFT-VM replacement

The DFIR container is a reproducible, rebuildable Docker image that carries the
full forensic toolchain VERDICT invokes. It is the recommended replacement for
the SIFT VM as the disk/memory/network tool backend.

## Why it replaces the SIFT VM

The SIFT VM worked, but it was a bottleneck for structural reasons:

- **It drifted.** Tools could be missing with no clean way to notice — a live
  run found `tshark` simply absent, so the whole PCAP lane read 0 packets.
- **It was network-isolated**, so a missing tool could not be installed in place.
- **Its shared folder (hgfs) was slow and flaky** for large evidence; tools
  reading an 11 GiB image or a 198 MB pcap over FUSE under-produced.
- **It was heavy** — a full VM, SSH routing, per-tool round-trips.

The container fixes each of these by construction:

| SIFT-VM problem | Container |
|---|---|
| Silent missing tools | Toolchain is declared in `docker/dfir.Dockerfile`; the image `HEALTHCHECK` fails if `tshark`/`fls`/`ewfexport`/`vol`/`hayabusa` are not invocable. |
| Can't update in place | Add a line, `docker build` — network is available at build time. |
| Slow hgfs reads | Evidence is a bind mount — native disk speed. |
| Heavy VM + SSH | A container driven over `docker exec -i` (the same stdio pipe `ssh -T` gives the VM). |

The image pins Volatility 3, Hayabusa (**with its Sigma rules baked in**, so
scans are never silently empty), Chainsaw, Velociraptor, Sleuth Kit, libewf,
`tshark`, Suricata, `nfdump`, the Eric Zimmerman tools (`ez_parse`, via a pinned
.NET 10 LTS runtime the .NET 9 builds roll forward onto) and plaso /
`log2timeline` (`plaso_parse`, from the GIFT stable PPA), plus the Rust 1.88 +
`uv` build environment.

## Download (recommended) or build

The image is published to GHCR, so most users can just pull it (~2.3 GB) instead
of building the toolchain locally:

```bash
docker pull ghcr.io/<owner>/verdict-dfir-toolkit:latest
```

`scripts/run-dfir-container.sh` does this automatically — it uses a local image if
present, else **pulls the published one**, else builds from the Dockerfile. So the
common path is simply:

```bash
scripts/run-dfir-container.sh <path-to-evidence>
```

To build locally instead (offline, or to modify the toolchain):

```bash
docker build -f docker/dfir.Dockerfile -t findevil/dfir:local .
```

**Maintainers** publish a new image with `scripts/publish-dfir-image.sh <tag>`
(needs a `write:packages` token in `GHCR_TOKEN`); CI also builds + pushes it on
release. The pull target is overridable with `FINDEVIL_DFIR_GHCR`.

## Bring up

`run-dfir-container.sh` gets the image (per above), starts a long-lived
`findevil-dfir` container with the repo bind-mounted read-write at `/workspace`
and evidence read-only at `/evidence`, builds the MCP server inside it (mirroring
how `sift-vm-bootstrap` builds it in the VM), and prints a toolchain check.

Disk-image mounting needs FUSE, so the container runs with
`--cap-add SYS_ADMIN --device /dev/fuse`; every other lane (memory, pcap, evtx,
registry, artifact parsing) runs unprivileged.

## One command: `scripts/verdict --docker`

`scripts/verdict --docker <evidence>` folds the bring-up and the transport swap
into one step — the container analog of `--sift`:

```bash
scripts/verdict --docker <path-to-evidence>
```

It:

- brings the container up via `scripts/run-dfir-container.sh` (build/pull the
  image, mount the evidence read-only at `/evidence`, build the MCP in-container);
- skips the host `cargo build` — the MCP is built in the container;
- swaps in the docker MCP transport (`.mcp.json.docker` over `.mcp.json`, backed
  up and restored on exit, exactly as `--sift` swaps `.mcp.json.sift`);
- hands the run the in-container evidence path (`/evidence`, where the evidence
  is bind-mounted read-only), since the tools run in the container and see it
  there;
- leaves the container running for reuse.

`--sift` and `--docker` are mutually exclusive (each picks where the DFIR tools
run), and `--docker` is single-host — a multi-host case folder is refused. Tear
the container down when finished:

```bash
scripts/run-dfir-container.sh --down
```

## Point VERDICT at the container (manual equivalent)

`scripts/verdict --docker` performs the two steps below for you; run them by hand
when driving the container from an interactive Claude Code session. Activate the
Docker MCP transport (the container analog of `.mcp.json.sift`):

```bash
scripts/run-dfir-container.sh <path-to-evidence>   # bring the container up
cp .mcp.json.docker .mcp.json                       # route the MCP over `docker exec -i`
```

Both product MCP servers now run **inside** the container. The evidence is
bind-mounted read-only at `/evidence`, so that is the in-container evidence path
(`case_open /evidence`). Revert with `git checkout .mcp.json` (or `cp .mcp.json`
from your local backend variant) to return to local/`--sift`.

Tear down when finished:

```bash
scripts/run-dfir-container.sh --down
```

## Evidence safety

The read-only contract is unchanged. Evidence is mounted `:ro`, so the container
cannot modify source evidence even if a tool tried. Only the two product MCP
servers run in the container; the operator-convenience servers are not part of
this image.

## Known limitations (honest scope)

- **Long-tail DFIR tools degrade, never crash.** Every subprocess tool the image
  omits returns a typed `BinaryNotFound` the engine pivots on, rather than
  crashing. The Eric Zimmerman tools (`ez_parse`: `AmcacheParser`, `JLECmd`,
  `RBCmd`, `LECmd`, `AppCompatCacheParser`, `SBECmd`, `WxTCmd`) and plaso
  (`plaso_parse`: `log2timeline.py` / `psort.py`) are now **baked into the
  image** — the EZ .NET 9 builds run on a pinned .NET 10 LTS runtime via
  `DOTNET_ROLL_FORWARD=Major`, and plaso comes from the GIFT stable PPA — so a
  disk case runs `case_open` → `disk_mount` → `disk_extract_artifacts` →
  `evtx_query` / `registry_query` / `mft_timeline` / `usnjrnl_query` /
  `hayabusa_scan` **and** `ez_parse` (Amcache/ShimCache/LNK/JumpList/RecycleBin/
  shellbags) and `plaso_parse` (super timeline). `ez_parse` still depends on
  `disk_extract_artifacts` having carved the target artifact. Remaining SIFT-only
  long-tail lanes (e.g. `mac_triage` / mac_apt) are not in the image and still
  degrade to `BinaryNotFound`. Prefer `--sift` when you need one of those lanes.
- **Multi-segment E01.** The image ships Ubuntu 22.04's `libewf` (`ewfmount
  20140807`), the same era as the SIFT VM. A truncated multi-segment E01 read
  seen on the VM may persist. Workaround until a newer `libewf` is pinned:
  `ewfexport` the segmented `.E01`/`.E02` to a single raw `.dd` first, then point
  VERDICT at the `.dd`.
- **The MCP server is built at bring-up, not baked into the image**, so the image
  stays decoupled from any single repo snapshot. First bring-up compiles
  `findevil-mcp` inside the container; subsequent starts reuse it.

## See also

- `docker/dfir.Dockerfile` — the pinned toolchain.
- `scripts/run-dfir-container.sh` — bring-up / teardown.
- `.mcp.json.docker` — the Docker MCP transport variant.
- [running-verdict.md](running-verdict.md) — the local and `--sift` run modes.
