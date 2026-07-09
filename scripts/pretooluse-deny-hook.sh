#!/usr/bin/env bash
# pretooluse-deny-hook.sh — OPTIONAL OS-level Bash PreToolUse deny-hook.
#
# DEFENSE IN DEPTH, NOT A REPLACEMENT. This sits BELOW VERDICT's in-process
# typed-MCP boundary (the Rust/Python servers that have no execute_shell verb and
# only invoke fixed-argv forensic binaries). It defaults OFF: it does nothing
# until an operator deliberately wires it as a Claude Code `Bash` PreToolUse hook
# (see docs/sandbox/optional-os-hardening.md). It NEVER widens the tool surface —
# it can only DENY, never grant.
#
# Contract (Claude Code PreToolUse): the tool-call JSON arrives on stdin. To
# block a tool call, exit with a NONZERO status and print the reason to stderr;
# exit 0 lets the call proceed. This hook:
#   * ignores any non-Bash tool (exit 0 — not its concern);
#   * for a Bash command, resolves the FIRST invoked binary's basename and HARD-
#     EXITS nonzero unless that basename is on scripts/forensic-allowlist.txt
#     (the single source of truth — the binaries the typed wrappers shell out to);
#   * FAILS CLOSED: malformed JSON, an empty command, an unparseable argv, or a
#     shell-chaining metacharacter ( ; | & ` $( ) all DENY.
#
# It is read-only: it changes no evidence and writes nothing to the audit chain.

set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOWLIST="${VERDICT_DENY_HOOK_ALLOWLIST:-${REPO_ROOT}/scripts/forensic-allowlist.txt}"

deny() {
  # Exit code 2 is the Claude Code convention for a hard PreToolUse block
  # (stderr is surfaced back to the agent). Any nonzero blocks; we use 2.
  echo "[deny-hook] BLOCKED: $*" >&2
  echo "[deny-hook] Only forensic binaries on ${ALLOWLIST} may run under this hook." >&2
  exit 2
}

STDIN="$(cat)"

# Resolve tool name + Bash command from the PreToolUse JSON with stdlib Python
# (already a VERDICT dependency; avoids a hard jq requirement). Emits two lines:
#   <tool_name>
#   <command>          (empty for non-Bash tools)
# A JSON parse failure prints PARSE_ERROR and the hook fails closed below.
parsed="$(
  VERDICT_DENY_HOOK_STDIN="${STDIN}" python3 - <<'PY' 2>/dev/null || echo "PARSE_ERROR"
import json, os, sys
try:
    data = json.loads(os.environ.get("VERDICT_DENY_HOOK_STDIN", ""))
except Exception:
    print("PARSE_ERROR"); sys.exit(0)
tool = str(data.get("tool_name", ""))
cmd = ""
if tool == "Bash":
    cmd = str(data.get("tool_input", {}).get("command", ""))
print(tool)
print(cmd)
PY
)"

[[ "${parsed}" == "PARSE_ERROR" ]] && deny "could not parse PreToolUse JSON (failing closed)"

tool_name="$(printf '%s' "${parsed}" | sed -n '1p')"
command="$(printf '%s' "${parsed}" | sed -n '2p')"

# Not a Bash tool call — outside this hook's scope. Let it proceed.
[[ "${tool_name}" != "Bash" ]] && exit 0

# Reject shell chaining/substitution outright: a single allow-listed argv[0]
# must not be a cover for `vol; curl ...` or `$(rm -rf /)`.
# shellcheck disable=SC2016  # the '$(' is a literal substring match, not an expansion
if [[ "${command}" =~ [\;\|\&\`] || "${command}" == *'$('* ]]; then
  deny "command uses shell chaining/substitution (; | & \` \$()) — not allowed under the deny-hook"
fi

# First token = argv[0]. Skip a leading `env`/`VAR=val` prefix so the real
# binary is what gets checked; a leading `sudo` is itself allow-listed (the disk
# verbs use `sudo -n mount/ewfmount/mmls`), so it passes on its own merits.
read -r -a tokens <<< "${command}"
first=""
for tok in "${tokens[@]}"; do
  case "${tok}" in
    env) continue ;;        # `env vol ...` -> check vol
    *=*) continue ;;        # `VAR=val vol ...` -> skip the assignment
    *) first="${tok}"; break ;;
  esac
done

[[ -z "${first}" ]] && deny "empty or unparseable command (failing closed)"

# Compare on the basename so `/usr/bin/vol` and `vol` resolve to the same entry.
binary="${first##*/}"

if [[ ! -f "${ALLOWLIST}" ]]; then
  deny "allow-list not found at ${ALLOWLIST} (failing closed)"
fi

# Allow-list match: exact basename against a non-comment, non-blank line.
while IFS= read -r line; do
  line="${line%%#*}"                       # strip inline/full comments
  line="${line#"${line%%[![:space:]]*}"}"  # ltrim
  line="${line%"${line##*[![:space:]]}"}"  # rtrim
  [[ -z "${line}" ]] && continue
  if [[ "${binary}" == "${line}" ]]; then
    exit 0
  fi
done < "${ALLOWLIST}"

deny "binary '${binary}' is not an allow-listed forensic tool"
