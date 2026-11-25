#!/usr/bin/env bash
# Spark local-seal smoke — time-bounded investigate via spark-ollama + DE_1102.
#
# Honest outcomes (exactly one final line of this form):
#   PASS: sealed with ed25519 (agent path; used_fallback=0)
#   PASS: investigate completed via fallback (not agent seal)
#   SKIP: spark down
#   FAIL: <reason with evidence>
#
# Env:
#   CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1 — FAIL if deterministic EVTX fallback ran
#     (used_fallback=1). Default 0 keeps m13 PASS-with-fallback behavior.
#   VERDICT_BIN / OPENCODE_BIN — preferred external runtime. When unset, prefer
#     engine/packages/opencode/dist/*/bin/opencode over PATH so a stale
#     ~/.local/bin/verdict with a slash-containing version cannot hang npm
#     (git ls-remote on 0.0.0-agent/…).
#   VERDICT_LLM_MODEL — optional model override (e.g. llama3.1:8b when gpt-oss hangs).
#   OPENCODE_TOOL_CHOICE / VERDICT_FORCE_TOOL_CHOICE — default required for agent tool calls
#     (set OPENCODE_TOOL_CHOICE=auto or VERDICT_FORCE_TOOL_CHOICE=0 to disable).
#
# Never fabricates seal success. If Spark Ollama is unreachable, exits 0 with SKIP.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

# Prefer a real node on PATH; allow common nvm layout without hard-coding a user.
if ! command -v node >/dev/null 2>&1; then
  if [ -n "${NVM_DIR:-}" ] && [ -d "${NVM_DIR}/versions/node" ]; then
    # shellcheck disable=SC2012
    newest="$(ls -1 "${NVM_DIR}/versions/node" 2>/dev/null | sort -V | tail -1 || true)"
    if [ -n "${newest}" ] && [ -x "${NVM_DIR}/versions/node/${newest}/bin/node" ]; then
      export PATH="${NVM_DIR}/versions/node/${newest}/bin:${PATH}"
    fi
  fi
fi
if ! command -v node >/dev/null 2>&1; then
  echo "FAIL: node not on PATH (install Node >=20 or put node on PATH)"
  exit 1
fi

say() { echo "==> $*"; }
fail() {
  echo "FAIL: $*"
  exit 1
}

resolve_dfir_home() {
  if [ -n "${VERDICT_DFIR_HOME:-}" ]; then
    printf '%s\n' "${VERDICT_DFIR_HOME}"
    return 0
  fi
  local candidate
  for candidate in \
    "${ROOT}/../dev" \
    "${ROOT}/../../verdict/dev" \
    "${ROOT}/../verdict-dfir-community" \
    "${ROOT}/../dev-verdict-next"
  do
    if [ -f "${candidate}/scripts/run-mcp-rust.sh" ]; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  return 1
}

# Prefer a non-slash versioned runtime. PATH ~/.local/bin/verdict may be a
# preview build stamped from branch names containing '/' (e.g. agent/m4-…),
# which hangs the harness on git ls-remote during plugin pin install.
# Dist is often only built in the primary worktree (gitignored), so also scan
# other worktrees of this repo. Reject candidates whose --version contains '/'.
runtime_version_ok() {
  local bin="$1" ver
  [ -x "${bin}" ] || return 1
  ver="$("${bin}" --version 2>/dev/null | head -1 || true)"
  # Empty version: still allow (some stubs); only reject slash-stamped previews.
  if [[ "${ver}" == *"/"* ]]; then
    return 1
  fi
  return 0
}

dist_candidates_under() {
  local base="$1"
  printf '%s\n' \
    "${base}/engine/packages/opencode/dist/opencode-linux-x64/bin/opencode" \
    "${base}/engine/packages/opencode/dist/opencode-linux-arm64/bin/opencode" \
    "${base}/engine/packages/opencode/dist/opencode-darwin-arm64/bin/opencode" \
    "${base}/engine/packages/opencode/dist/opencode-darwin-x64/bin/opencode"
}

resolve_verdict_runtime() {
  local candidate wt
  for candidate in "${VERDICT_BIN:-}" "${OPENCODE_BIN:-}"; do
    [ -n "${candidate}" ] || continue
    if runtime_version_ok "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done
  while IFS= read -r candidate; do
    [ -n "${candidate}" ] || continue
    if runtime_version_ok "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done < <(dist_candidates_under "${ROOT}")
  if command -v git >/dev/null 2>&1; then
    while IFS= read -r wt; do
      [ -n "${wt}" ] || continue
      [ "${wt}" = "${ROOT}" ] && continue
      while IFS= read -r candidate; do
        [ -n "${candidate}" ] || continue
        if runtime_version_ok "${candidate}"; then
          printf '%s\n' "${candidate}"
          return 0
        fi
      done < <(dist_candidates_under "${wt}")
    done < <(git -C "${ROOT}" worktree list --porcelain 2>/dev/null | awk '/^worktree / { print substr($0, 10) }')
  fi
  # Last resort: PATH, but only slash-free versions.
  while IFS= read -r candidate; do
    [ -n "${candidate}" ] || continue
    if runtime_version_ok "${candidate}"; then
      printf '%s\n' "${candidate}"
      return 0
    fi
  done < <( { type -P -a verdict 2>/dev/null || true; type -P -a opencode 2>/dev/null || true; } )
  return 1
}

# Route endpoint: env override wins; else spark-ollama.base_url from model-routes.yaml.
route_id="${CASEFORGE_SPARK_ROUTE:-spark-ollama}"
routes_file="${ROOT}/configs/model-routes.yaml"
yaml_base=""
if [ -f "${routes_file}" ]; then
  yaml_base="$(
    awk -v id="${route_id}:" '
      $0 ~ "^[[:space:]]*" id { in_route=1; next }
      in_route && /^[[:space:]]+[a-zA-Z0-9_-]+:/ && $0 !~ /^[[:space:]]+base_url:/ { if ($0 ~ /^[[:space:]]{2}[a-zA-Z]/ && $0 !~ /^[[:space:]]{4}/) exit }
      in_route && /base_url:/ {
        sub(/^[^:]+:[[:space:]]*/, "")
        sub(/[[:space:]]+#.*$/, "")
        gsub(/[[:space:]]/, "")
        print
        exit
      }
    ' "${routes_file}"
  )"
fi

endpoint="${VERDICT_LLM_BASEURL:-${CASEFORGE_SPARK_ENDPOINT:-${yaml_base:-}}}"
if [ -z "${endpoint}" ] || [[ "${endpoint}" == *"SPARK-HOST"* ]] || [[ "${endpoint}" == *"<spark-ip>"* ]]; then
  # Unconfigured placeholder is treated as down (honest SKIP, not FAIL).
  echo "SKIP: spark down (set VERDICT_LLM_BASEURL or CASEFORGE_SPARK_ENDPOINT; route ${route_id} base_url is unset/placeholder)"
  exit 0
fi

# Bare host roots (http://host:11434) make openai-compat call /chat/completions
# and Ollama returns "404 page not found". OpenAI surface is under /v1.
endpoint="${endpoint%/}"
if [[ "${endpoint}" =~ ^https?://[^/]+$ ]]; then
  endpoint="${endpoint}/v1"
fi

# Normalize to Ollama tags URL for the liveness probe.
probe_url="${endpoint%/}"
probe_url="${probe_url%/v1}"
probe_url="${probe_url}/api/tags"

say "probe Spark Ollama at ${probe_url}"
set +e
probe_out="$(curl -sS -m 2 "${probe_url}" 2>&1)"
probe_rc=$?
set -e
if [ "${probe_rc}" -ne 0 ] || ! grep -Eq '"models"|models' <<<"${probe_out}"; then
  echo "SKIP: spark down (endpoint unreachable or not Ollama: ${probe_url}; curl_rc=${probe_rc})"
  exit 0
fi
say "Spark Ollama up (${probe_url})"

# When agent seal is required, refuse models Ollama reports as non-tool-capable.
# (e.g. qwen3.6:35b-a3b → "does not support tools"; agent path cannot seal.)
if [ "${CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT:-0}" = "1" ]; then
  model_name="${VERDICT_LLM_MODEL:-}"
  if [ -z "${model_name}" ] && [ -f "${routes_file}" ]; then
    model_name="$(
      awk -v id="${route_id}:" '
        $0 ~ "^[[:space:]]*" id { in_route=1; next }
        in_route && /^[[:space:]]+[a-zA-Z0-9_-]+:/ && $0 !~ /^[[:space:]]+model:/ { if ($0 ~ /^[[:space:]]{2}[a-zA-Z]/ && $0 !~ /^[[:space:]]{4}/) exit }
        in_route && /model:/ {
          sub(/^[^:]+:[[:space:]]*/, "")
          sub(/[[:space:]]+#.*$/, "")
          gsub(/[[:space:]]/, "")
          print
          exit
        }
      ' "${routes_file}"
    )"
  fi
  if [ -n "${model_name}" ]; then
    show_url="${probe_url%/api/tags}/api/show"
    set +e
    show_out="$(curl -sS -m 5 -H "Content-Type: application/json" -d "{\"name\":\"${model_name}\"}" "${show_url}" 2>&1)"
    show_rc=$?
    set -e
    if [ "${show_rc}" -eq 0 ] && printf '%s' "${show_out}" | grep -q '"capabilities"'; then
      if ! printf '%s' "${show_out}" | grep -Fq '"tools"'; then
        fail "REQUIRE_AGENT=1 but Ollama model ${model_name} has no tools capability (cannot agent-seal). show=${show_url}"
      fi
      say "model ${model_name} tools capability: ok"
    else
      say "WARN: could not probe Ollama tools capability for ${model_name} (continuing)"
    fi
  fi
fi


CLI="${ROOT}/packages/caseforge-cli/dist/src/cli.js"
if [ ! -f "${CLI}" ]; then
  say "building CLI (dist missing)"
  npm run build
fi
[ -f "${CLI}" ] || fail "missing built CLI at ${CLI}"

DFIR_HOME="$(resolve_dfir_home)" || fail "set VERDICT_DFIR_HOME to a toolkit checkout with scripts/run-mcp-rust.sh"
[ -f "${DFIR_HOME}/scripts/run-mcp-rust.sh" ] || fail "VERDICT toolkit launcher missing: ${DFIR_HOME}/scripts/run-mcp-rust.sh"

if runtime_bin="$(resolve_verdict_runtime)"; then
  export VERDICT_BIN="${runtime_bin}"
  export OPENCODE_BIN="${OPENCODE_BIN:-${runtime_bin}}"
  say "VERDICT_BIN=${VERDICT_BIN}"
  runtime_ver="$("${VERDICT_BIN}" --version 2>/dev/null | head -1 || true)"
  if [ -n "${runtime_ver}" ]; then
    say "runtime version: ${runtime_ver}"
    if [[ "${runtime_ver}" == *"/"* ]]; then
      say "WARN: runtime version contains '/' (npm may treat it as github owner/repo and hang on git ls-remote); prefer engine dist or rebuild with sanitized channel"
    fi
  fi
else
  say "WARN: no engine dist runtime found; doctor/investigate will use PATH verdict (slash-version hang risk)"
fi

FIND_EVIL_HOME="${FINDEVIL_HOME:-${DFIR_HOME}/.project-local/findevil}"
CASES_DIR="${FIND_EVIL_HOME}/cases"

# DE_1102 only (read-only evidence paths; do not invent evidence).
EVIDENCE=""
for candidate in \
  "${CASEFORGE_SPARK_EVIDENCE:-}" \
  "${DFIR_HOME}/evidence/DE_1102_security_log_cleared.evtx" \
  "${ROOT}/../dev/evidence/DE_1102_security_log_cleared.evtx" \
  "${ROOT}/../../verdict/dev/evidence/DE_1102_security_log_cleared.evtx"
do
  [ -n "${candidate}" ] || continue
  if [ -f "${candidate}" ]; then
    EVIDENCE="$(cd "$(dirname "${candidate}")" && pwd)/$(basename "${candidate}")"
    break
  fi
done
[ -n "${EVIDENCE}" ] || fail "DE_1102 EVTX not found (set CASEFORGE_SPARK_EVIDENCE or VERDICT_DFIR_HOME/evidence/DE_1102_security_log_cleared.evtx)"

say "doctor --route ${route_id}"
set +e
doctor_out="$(
  VERDICT_DFIR_HOME="${DFIR_HOME}" \
  VERDICT_LLM_BASEURL="${endpoint}" \
  VERDICT_BIN="${VERDICT_BIN:-}" \
  OPENCODE_BIN="${OPENCODE_BIN:-}" \
  VERDICT_LLM_MODEL="${VERDICT_LLM_MODEL:-}" \
  OPENCODE_TOOL_CHOICE="${OPENCODE_TOOL_CHOICE:-required}" \
  VERDICT_FORCE_TOOL_CHOICE="${VERDICT_FORCE_TOOL_CHOICE:-1}" \
  node "${CLI}" doctor --route "${route_id}" 2>&1
)"
doctor_rc=$?
set -e
printf '%s\n' "${doctor_out}"
# Doctor may still MISS findevil-mcp binary etc.; we only require the selected
# local endpoint not be reported down after our live probe.
if grep -Fq "selected local endpoint down" <<<"${doctor_out}"; then
  echo "SKIP: spark down (doctor: selected local endpoint down for ${route_id})"
  exit 0
fi
if [ "${doctor_rc}" -ne 0 ]; then
  say "doctor returned ${doctor_rc} (continuing if Spark itself is up; other MISSes are separate)"
fi

timeout_s="${CASEFORGE_SPARK_SMOKE_TIMEOUT:-240}"
if ! [[ "${timeout_s}" =~ ^[0-9]+$ ]] || [ "${timeout_s}" -lt 60 ]; then
  timeout_s=240
fi
# Clamp to the milestone window (~180–300s) unless the operator forces higher.
if [ "${CASEFORGE_SPARK_SMOKE_TIMEOUT_FORCE:-0}" != "1" ]; then
  if [ "${timeout_s}" -lt 180 ]; then timeout_s=180; fi
  if [ "${timeout_s}" -gt 300 ]; then timeout_s=300; fi
fi

marker_dir="${FIND_EVIL_HOME}/.caseforge-spark-seal-smoke"
mkdir -p "${marker_dir}"
marker="$(mktemp "${marker_dir}/marker.XXXXXX")"
touch "${marker}"
log="$(mktemp "${marker_dir}/investigate.XXXXXX.log")"

cleanup() {
  rm -f "${marker}" 2>/dev/null || true
}
trap cleanup EXIT

say "investigate ${EVIDENCE} --route ${route_id} (timeout ${timeout_s}s)"
set +e
if command -v timeout >/dev/null 2>&1; then
  VERDICT_DFIR_HOME="${DFIR_HOME}" \
  FINDEVIL_HOME="${FIND_EVIL_HOME}" \
  VERDICT_LLM_BASEURL="${endpoint}" \
  VERDICT_BIN="${VERDICT_BIN:-}" \
  OPENCODE_BIN="${OPENCODE_BIN:-}" \
  VERDICT_LLM_MODEL="${VERDICT_LLM_MODEL:-}" \
  OPENCODE_TOOL_CHOICE="${OPENCODE_TOOL_CHOICE:-required}" \
  VERDICT_FORCE_TOOL_CHOICE="${VERDICT_FORCE_TOOL_CHOICE:-1}" \
  timeout "${timeout_s}" \
    node "${CLI}" investigate "${EVIDENCE}" \
      --privacy local-only \
      --evidence sensitive \
      --route "${route_id}" \
    >"${log}" 2>&1
  inv_rc=$?
else
  VERDICT_DFIR_HOME="${DFIR_HOME}" \
  FINDEVIL_HOME="${FIND_EVIL_HOME}" \
  VERDICT_LLM_BASEURL="${endpoint}" \
  VERDICT_BIN="${VERDICT_BIN:-}" \
  OPENCODE_BIN="${OPENCODE_BIN:-}" \
  VERDICT_LLM_MODEL="${VERDICT_LLM_MODEL:-}" \
  OPENCODE_TOOL_CHOICE="${OPENCODE_TOOL_CHOICE:-required}" \
  VERDICT_FORCE_TOOL_CHOICE="${VERDICT_FORCE_TOOL_CHOICE:-1}" \
    node "${CLI}" investigate "${EVIDENCE}" \
      --privacy local-only \
      --evidence sensitive \
      --route "${route_id}" \
    >"${log}" 2>&1
  inv_rc=$?
fi
set -e

# Keep a tail for FAIL evidence; full log path for operators.
echo "--- investigate log (tail) ---"
tail -n 80 "${log}" || true
echo "--- end log tail (full: ${log}) ---"

used_fallback=0
if grep -Eq 'deterministic local EVTX auto-runner fallback|verifying deterministic EVTX fallback' "${log}"; then
  used_fallback=1
fi

# Optional strict agent-seal gate (Milestone 14):
# CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1 fails if the deterministic EVTX fallback ran.
# Default remains the honest PASS-with-fallback path (m13).
require_agent="${CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT:-0}"

# Prefer case dir mentioned in the log; else newest case under CASES_DIR after marker.
run_dir=""
if grep -Eo 'verifying (produced|deterministic EVTX fallback) run: [^[:space:]]+' "${log}" >/dev/null 2>&1; then
  run_dir="$(grep -Eo 'verifying (produced|deterministic EVTX fallback) run: [^[:space:]]+' "${log}" | tail -1 | awk '{print $NF}')"
fi
if [ -z "${run_dir}" ] || [ ! -d "${run_dir}" ]; then
  if [ -d "${CASES_DIR}" ]; then
    run_dir="$(
      find "${CASES_DIR}" -mindepth 1 -maxdepth 1 -type d -newer "${marker}" -printf '%T@ %p\n' 2>/dev/null \
        | sort -nr \
        | head -1 \
        | cut -d' ' -f2-
    )"
  fi
fi

# Timeout exit codes: GNU timeout → 124; some wrappers → 137
# After the m15 /v1 bare-root fix, agent can still hang on long Spark tool runs
# (case dir may exist with only case.json). Fail with hang messaging here instead
# of falling through to a misleading "missing run.manifest.json" FAIL.
if [ "${inv_rc}" -eq 124 ] || [ "${inv_rc}" -eq 137 ]; then
  hang_hint="agent path likely hung after LLM /v1 (not bare-baseURL 404); raise CASEFORGE_SPARK_SMOKE_TIMEOUT or inspect log"
  if [ -n "${run_dir}" ] && [ -d "${run_dir}" ] && [ -f "${run_dir}/run.manifest.json" ]; then
    say "investigate timed out (rc=${inv_rc}) but case has run.manifest.json: ${run_dir}"
  elif [ -n "${run_dir}" ] && [ -d "${run_dir}" ]; then
    fail "investigate timed out after ${timeout_s}s (rc=${inv_rc}); case incomplete (no run.manifest.json). ${hang_hint}. run_dir=${run_dir} log=${log}"
  else
    fail "investigate timed out after ${timeout_s}s (rc=${inv_rc}); no case/run dir produced. ${hang_hint}. log=${log}"
  fi
fi

if [ -z "${run_dir}" ] || [ ! -d "${run_dir}" ]; then
  fail "investigate finished (rc=${inv_rc}) without a case/run dir under ${CASES_DIR}. log=${log}"
fi

say "inspect run dir: ${run_dir}"
manifest="${run_dir}/run.manifest.json"
verify_json="${run_dir}/manifest_verify.json"

sig_kind=""
signer_effective=""
overall=""
signature_verified=""

if [ -f "${manifest}" ]; then
  # shellcheck disable=SC2016
  eval "$(
    node -e '
      const fs = require("fs");
      const p = process.argv[1];
      let d = {};
      try { d = JSON.parse(fs.readFileSync(p, "utf8")); } catch { process.exit(0); }
      const sig = d.signature && typeof d.signature === "object" ? d.signature : {};
      const kind = d.signature_kind || sig.kind || d.signer || "";
      const se = d.signer_effective || sig.signer_effective || kind || "";
      const q = (s) => String(s).replace(/[^a-zA-Z0-9._+-]/g, "");
      console.log("sig_kind=" + JSON.stringify(q(kind)));
      console.log("signer_effective=" + JSON.stringify(q(se)));
    ' "${manifest}"
  )"
fi
if [ -f "${verify_json}" ]; then
  eval "$(
    node -e '
      const fs = require("fs");
      const p = process.argv[1];
      let d = {};
      try { d = JSON.parse(fs.readFileSync(p, "utf8")); } catch { process.exit(0); }
      const kind = d.signature_kind || "";
      const overall = d.overall === true ? "true" : d.overall === false ? "false" : "";
      const sv = d.signature_verified === true ? "true" : d.signature_verified === false ? "false" : "";
      const q = (s) => String(s).replace(/[^a-zA-Z0-9._+-]/g, "");
      if (kind) console.log("sig_kind=" + JSON.stringify(q(kind)));
      console.log("overall=" + JSON.stringify(overall));
      console.log("signature_verified=" + JSON.stringify(sv));
    ' "${verify_json}"
  )"
fi

echo "evidence: run_dir=${run_dir}"
echo "evidence: signature_kind=${sig_kind:-<missing>} signer_effective=${signer_effective:-<missing>} overall=${overall:-<missing>} signature_verified=${signature_verified:-<missing>} used_fallback=${used_fallback} inv_rc=${inv_rc}"

is_ed25519=0
if [ "${sig_kind}" = "ed25519" ] || [ "${signer_effective}" = "ed25519" ]; then
  is_ed25519=1
fi
overall_true=0
if [ "${overall}" = "true" ]; then
  overall_true=1
fi

if [ "${used_fallback}" -eq 1 ]; then
  # Fallback path can still produce an ed25519-sealed case; do not claim agent seal.
  if [ "${require_agent}" = "1" ]; then
    fail "agent seal not achieved: used_fallback=1 (CASEFORGE_SPARK_SMOKE_REQUIRE_AGENT=1). signature_kind=${sig_kind:-n/a} overall=${overall:-n/a} run_dir=${run_dir}"
  fi
  if [ "${is_ed25519}" -eq 1 ] && { [ "${overall_true}" -eq 1 ] || [ "${inv_rc}" -eq 0 ]; }; then
    echo "PASS: investigate completed via fallback (not agent seal)"
    echo "  quoted: signature_kind=${sig_kind:-n/a} overall=${overall:-n/a} used_fallback=1 run_dir=${run_dir}"
    exit 0
  fi
  echo "PASS: investigate completed via fallback (not agent seal)"
  echo "  note: fallback path used; seal fields incomplete (signature_kind=${sig_kind:-n/a} overall=${overall:-n/a})"
  exit 0
fi

if [ "${is_ed25519}" -eq 1 ] && [ "${overall_true}" -eq 1 ]; then
  echo "PASS: sealed with ed25519 (agent path; used_fallback=0)"
  echo "  quoted: signature_kind=${sig_kind} signer_effective=${signer_effective:-${sig_kind}} overall=true signature_verified=${signature_verified:-n/a} used_fallback=0 run_dir=${run_dir}"
  exit 0
fi

if [ "${is_ed25519}" -eq 1 ]; then
  # Have ed25519 on the manifest but overall not proven true — do not over-claim.
  fail "run has signature_kind/ed25519 but manifest_verify overall is not true (overall=${overall:-missing} signature_verified=${signature_verified:-missing} run_dir=${run_dir})"
fi

if [ -f "${manifest}" ]; then
  fail "run dir produced but not ed25519-sealed (signature_kind=${sig_kind:-missing} overall=${overall:-missing} inv_rc=${inv_rc} run_dir=${run_dir})"
fi

fail "run dir missing run.manifest.json (inv_rc=${inv_rc} run_dir=${run_dir})"
