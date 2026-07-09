#!/usr/bin/env bash
# Publish the VERDICT DFIR toolchain image to GHCR so users can `docker pull` it
# instead of building locally. Free + operator-run (git-ship philosophy) — reads
# the token from the environment, never a billed CI runner required.
#
# Needs a token with the `write:packages` scope (a classic PAT, or a fine-grained
# token with package write). The default `gh auth token` usually lacks it.
#
# Usage:
#   GHCR_TOKEN=ghp_xxx scripts/publish-dfir-image.sh                 # push :latest
#   GHCR_TOKEN=ghp_xxx scripts/publish-dfir-image.sh v0.5.0-beta.2   # push a tag + :latest
#   scripts/publish-dfir-image.sh --dry-run v0.5.0                   # print, push nothing
#
# Env overrides:
#   GHCR_OWNER   registry owner (default: derived from the git remote, lowercased)
#   GHCR_IMAGE   full image path (default: ghcr.io/<owner>/verdict-dfir-toolkit)
#   GHCR_USER    login user (default: $GHCR_OWNER)
#   GHCR_TOKEN / GITHUB_TOKEN   the write:packages token
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCAL_IMAGE="${FINDEVIL_DFIR_IMAGE:-findevil/dfir:local}"

DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && { DRY_RUN=1; shift; }
TAG="${1:-latest}"

# Derive owner from the origin remote unless overridden.
default_owner() {
  local url; url="$(git -C "$REPO_ROOT" remote get-url origin 2>/dev/null || true)"
  local slug; slug="$(printf '%s' "$url" | sed -E 's#^[a-z]+://[^/]+/##; s#^[^:]+:##; s#\.git$##')"
  printf '%s' "${slug%%/*}" | tr '[:upper:]' '[:lower:]'
}
GHCR_OWNER="${GHCR_OWNER:-$(default_owner)}"
GHCR_IMAGE="${GHCR_IMAGE:-ghcr.io/${GHCR_OWNER}/verdict-dfir-toolkit}"
GHCR_USER="${GHCR_USER:-$GHCR_OWNER}"
TOKEN="${GHCR_TOKEN:-${GITHUB_TOKEN:-}}"

log() { printf '[publish-dfir] %s\n' "$*"; }

command -v docker >/dev/null || { log "docker not found"; exit 1; }

# Ensure the local image exists (build it if not).
if ! docker image inspect "$LOCAL_IMAGE" >/dev/null 2>&1; then
  log "local image $LOCAL_IMAGE absent — building it first"
  [[ "$DRY_RUN" == 1 ]] || docker build -f "$REPO_ROOT/docker/dfir.Dockerfile" -t "$LOCAL_IMAGE" "$REPO_ROOT"
fi

TAGS=("${GHCR_IMAGE}:${TAG}")
[[ "$TAG" != "latest" ]] && TAGS+=("${GHCR_IMAGE}:latest")

log "target tags: ${TAGS[*]}"
if [[ "$DRY_RUN" == 1 ]]; then
  log "DRY-RUN — would: docker login ghcr.io; tag ${LOCAL_IMAGE} -> each; docker push"
  exit 0
fi

[[ -n "$TOKEN" ]] || { log "no GHCR_TOKEN/GITHUB_TOKEN (needs write:packages scope)"; exit 1; }
log "logging in to ghcr.io as ${GHCR_USER}"
printf '%s' "$TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin
for t in "${TAGS[@]}"; do
  docker tag "$LOCAL_IMAGE" "$t"
  log "pushing $t"
  docker push "$t"
done
log "done — users can now: docker pull ${GHCR_IMAGE}:${TAG}"
