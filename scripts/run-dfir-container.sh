#!/usr/bin/env bash
# Bring up the VERDICT DFIR container as the tool backend — the container analog
# of sift-vm-bootstrap.sh. Builds docker/dfir.Dockerfile if needed, starts a
# long-lived 'findevil-dfir' container with the repo bind-mounted read-write at
# /workspace and (optional) evidence read-only at /evidence, then builds the MCP
# servers inside it. After this, `scripts/verdict --docker` (or copying
# .mcp.json.docker over .mcp.json) routes the MCP over `docker exec -i`.
#
# Usage:
#   scripts/run-dfir-container.sh [evidence-path]
#   scripts/run-dfir-container.sh --down        # stop + remove the container
#
# Disk-image mounting needs FUSE + SYS_ADMIN; everything else runs unprivileged.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${FINDEVIL_DFIR_IMAGE:-findevil/dfir:local}"
CTR="${FINDEVIL_DFIR_CONTAINER:-findevil-dfir}"
DOCKERFILE="${REPO_ROOT}/docker/dfir.Dockerfile"
# Published image to pull before building locally (set FINDEVIL_DFIR_GHCR="" to
# always build). Owner is derived from the origin remote.
default_ghcr_owner() {
  local url slug; url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  slug="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^/]+/##; s#^[^:]+:##; s#\.git$##')"
  printf '%s' "${slug%%/*}" | tr '[:upper:]' '[:lower:]'
}
GHCR_IMAGE="${FINDEVIL_DFIR_GHCR-ghcr.io/$(default_ghcr_owner)/verdict-dfir-toolkit:latest}"

log() { printf '[dfir-container] %s\n' "$*"; }

if [[ "${1:-}" == "--down" ]]; then
  docker rm -f "${CTR}" >/dev/null 2>&1 && log "removed ${CTR}" || log "${CTR} not running"
  exit 0
fi

EVIDENCE="${1:-}"

command -v docker >/dev/null || { log "docker not found on PATH"; exit 1; }

# 1. Get the image: use local if present, else try pulling the published one
#    (fast), else build it (slow, first run installs the whole toolchain).
if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
  log "image ${IMAGE} present"
elif [[ -n "${GHCR_IMAGE}" ]] && docker pull "${GHCR_IMAGE}" 2>/dev/null; then
  log "pulled published image ${GHCR_IMAGE}"
  docker tag "${GHCR_IMAGE}" "${IMAGE}"
else
  log "no local or published image — building ${IMAGE} (installs the DFIR toolchain)..."
  docker build -f "${DOCKERFILE}" -t "${IMAGE}" "${REPO_ROOT}"
fi

# 2. (Re)start the container. Evidence is mounted read-only when supplied.
mounts=(-v "${REPO_ROOT}:/workspace")
if [[ -n "${EVIDENCE}" ]]; then
  EVIDENCE_ABS="$(cd "$(dirname "${EVIDENCE}")" && pwd)/$(basename "${EVIDENCE}")"
  [[ -e "${EVIDENCE_ABS}" ]] || { log "evidence path not found: ${EVIDENCE}"; exit 1; }
  mounts+=(-v "${EVIDENCE_ABS}:/evidence:ro")
  log "evidence mounted read-only: ${EVIDENCE_ABS} -> /evidence"
fi

if docker ps -a --format '{{.Names}}' | grep -qx "${CTR}"; then
  log "recreating existing container ${CTR}"
  docker rm -f "${CTR}" >/dev/null
fi
log "starting ${CTR} (FUSE + SYS_ADMIN for disk mounts)"
docker run -d --name "${CTR}" \
  --cap-add SYS_ADMIN --device /dev/fuse --security-opt apparmor=unconfined \
  "${mounts[@]}" \
  "${IMAGE}" sleep infinity >/dev/null

# 3. Build the MCP servers inside the container if the binary is not runnable
#    there (mirrors sift-vm-setup: build in the target environment).
if docker exec "${CTR}" test -x /workspace/target/release/findevil-mcp \
   && docker exec "${CTR}" /workspace/target/release/findevil-mcp --help >/dev/null 2>&1; then
  log "findevil-mcp already runnable in-container (reusing target/)"
else
  log "building findevil-mcp inside the container..."
  docker exec "${CTR}" bash -lc "cd /workspace && cargo build --release -p findevil-mcp --locked"
fi
log "syncing the Python agent MCP env..."
docker exec "${CTR}" bash -lc "cd /workspace/services/agent_mcp && uv sync" || \
  log "uv sync reported an issue (agent MCP tools may be degraded)"

# 4. Prove the toolchain resolves — the failure the SIFT VM used to hide.
log "toolchain check:"
docker exec "${CTR}" bash -lc '
  for t in tshark fls icat ewfexport mmls vol hayabusa; do
    if command -v "$t" >/dev/null 2>&1; then printf "  ok   %s\n" "$t"; else printf "  MISS %s\n" "$t"; fi
  done'
log "ready. Activate the backend: cp .mcp.json.docker .mcp.json  (or run: scripts/verdict --docker <evidence>)"
