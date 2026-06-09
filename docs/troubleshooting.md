# Troubleshooting

Every failure mode below is detected by code, not convention — the symptom column quotes the
actual error text the detector prints, and the fix column is the command that clears it.
Run `bash scripts/doctor.sh` first: it executes most of these checks in one pass and prints
per-check fixes.

Related docs: `QUICKSTART.md` (3-step setup), `docs/onboarding.md` (pre-flight checklist),
`docs/using/running-verdict.md` (every flag), `docs/reference/environment-variables.md`
(all `FIND_EVIL_*` / `FINDEVIL_*` vars).

---

## 1. Install & preflight

| Symptom | Detector | Fix |
|---|---|---|
| `none of the 3 modes detected` (credential) | `scripts/doctor.sh` credential check | Any one of: `claude setup-token` (then export `CLAUDE_CODE_OAUTH_TOKEN`), `claude auth login`, or `export ANTHROPIC_API_KEY=...` |
| `python3` / `git` / `unzip` / `claude` / `cargo` / `uv` "not on PATH" | `scripts/doctor.sh` toolchain checks | Install the named tool; `scripts/install.sh` prints the per-tool install command |
| `findevil-mcp not built — run: bash scripts/install.sh` | `scripts/doctor.sh` MCP check | `cargo build --release -p findevil-mcp` (or just `bash scripts/install.sh`) |
| `agent_mcp venv not synced` | `scripts/doctor.sh` MCP check | `uv sync --directory services/agent_mcp` |
| volatility3 / hayabusa / velociraptor / tshark / sleuthkit "absent" | `scripts/doctor.sh` DFIR checks (warn-only) | Optional — tools that need a missing binary return a clean `BinaryNotFound` and the run continues with reduced coverage. Install via `bash scripts/install-dfir-tools.sh` or set `$VOLATILITY_BIN` etc. |
| Report renders without figures, no error | matplotlib absent (warn-only) | `pip3 install matplotlib` |

## 2. Evidence path

| Symptom | Detector | Fix |
|---|---|---|
| `no evidence path given and the default evidence/ directory is empty` | `scripts/find_evil_auto.py` (`resolve_evidence_path`) | Pass an explicit path: `scripts/verdict /path/to/evidence.E01`, or drop the file into `evidence/` |
| `no evidence path given and <path> does not exist` | same | Create the directory or pass an explicit path; `FINDEVIL_EVIDENCE_ROOT` overrides the default root |

When `evidence/` holds multiple unrelated cases, always pass the explicit file — never run
pathless (the resolver would pick the newest file, which may be the wrong case).

## 3. Runs that produce 0 findings (memory tools all errored)

If the verdict is honest-but-empty (`INDETERMINATE`, every Volatility tool listed under
`analysis_limitations`), the memory image and the Volatility install are the usual suspects:

1. `vol -f <image> windows.info` by hand — if this fails, the image is the problem
   (truncated download, nested archive not fully extracted — e.g. a `.zip` containing a `.7z`).
2. `scripts/doctor.sh` — confirms `volatility3` resolves; set `$VOLATILITY_BIN` if it lives
   outside PATH.
3. The run is still valid: every failure is recorded as a `course_correction` in
   `audit.jsonl`, two consecutive failures emit a `heartbeat_failure` escalation record, and
   the Verdict stays honest about coverage rather than guessing.

## 4. Verifier rejects every finding

Three known causes, all detected and fixed in current code — listed here because a stale
checkout or an unsynced SIFT VM reintroduces them:

| Cause | Detector / fix location | Fix |
|---|---|---|
| Relative evidence path: the verifier replays from `services/agent_mcp/` cwd, so a relative path 404s (`-32602 image not found`) | `Investigation.__init__` pins evidence to an absolute path in local mode | `git pull` — fixed in current code |
| Extra fields on findings rejected by the Pydantic `extra=forbid` model | `finding_for_verifier()` projects to canonical fields | `git pull` — fixed in current code |
| SIFT VM running an older `services/agent_mcp` copy than the host | none (environment drift) | Re-sync the VM: `scp -i ~/.ssh/sift_key -r services/agent_mcp sansforensics@$FIND_EVIL_GUEST_IP:$FIND_EVIL_GUEST_REPO/` |

## 5. SIFT mode (`--sift`)

| Symptom | Detector | Fix |
|---|---|---|
| `ERROR: SSH key not found at <path>` | `find_evil_auto.py` SIFT preflight | First time: `bash scripts/sift-vm-bootstrap.sh`; or `export FIND_EVIL_SSH_KEY=/path/to/key` |
| `ERROR: cannot reach SIFT VM at <user>@<ip> or MCP server prerequisite missing` (lists the 3 prerequisites) | same preflight (10 s SSH probe) | Boot the VM (`bash scripts/find-evil-sift` auto-boots), check `ping $FIND_EVIL_GUEST_IP`, and verify all three listed paths exist on the guest |
| SSH probe times out with the default IP | default `FIND_EVIL_GUEST_IP` may not match your VM's network | `export FIND_EVIL_GUEST_IP=<your VM's IP>` (NAT setups commonly land on `192.168.137.x`); also `FIND_EVIL_GUEST_USER` / `FIND_EVIL_GUEST_REPO` if non-default |

**You do not need SIFT mode for full results.** Local mode parses disk artifacts
(Prefetch + registry/UserAssist) via Sleuth Kit direct-read and produces the same 2-class
CONFIRMED escalation — see `docs/sample-run/README.md` (the `nist-hacking-case/` local run and
its `--sift` twin reach the identical verdict). The 9.3 GB gated SIFT OVA download is only
needed to reproduce the VM-isolated judging environment.

## 6. Dashboard

| Symptom | Detector | Fix |
|---|---|---|
| Port 3000 occupied / wrong app opens | `scripts/verdict` opens `http://localhost:3000` | Free the port (`lsof -i :3000`), or start the dashboard on another port: `pnpm --filter @findevil/web exec next dev -p 3100` and open `http://localhost:3100/?case=<case_dir>` with `scripts/verdict --no-dashboard` |
| `dashboard slow to start — open ... manually` | `scripts/verdict` 40 s readiness wait | Cold webpack build can exceed the wait; pre-start with `pnpm --filter @findevil/web dev`, then run verdict |
| `?case=` deep link returns API 400 | dashboard needs the repo root | `export FINDEVIL_REPO_ROOT=$PWD` and `FINDEVIL_DASHBOARD_EXTRA_ROOTS=$PWD/tmp/auto-runs` before starting the dashboard (scripts/verdict sets these for you) |

## 7. MCP server spawn / tool-call failures

| Symptom | Meaning | Fix |
|---|---|---|
| `<server>: server closed stdout` / `server stdin closed` | the MCP server process died (Rust panic, Python import error, SSH drop in SIFT mode) | `bash scripts/install.sh` to rebuild; in SIFT mode verify the VM connection (§5) |
| `... timed out after Ns` | a tool subprocess hung | Re-run; if reproducible on one artifact, file it — every other lane completed and was sealed |
| `case_open failed: ...` | evidence unreadable or unsupported type | Verify the file is readable and complete (compare SHA-256 / re-download); try a known-good file to isolate |

## 8. Offline verification

| Symptom | Meaning | Fix |
|---|---|---|
| `manifest_verify` returns `overall: false` on a **copied** case dir | the manifest embeds the original run's `audit_log_path` | Pass the local log explicitly: `manifest_verify(manifest_path=..., audit_log_path=<copied audit.jsonl>)` — see `docs/sample-run/README.md` |
| `scripts/trace-finding <run-dir>` exits non-zero | a hash-chain link or Merkle leaf failed to resolve | That is the tool working: a single flipped bit anywhere in `audit.jsonl` breaks the chain. Diff against the original run dir |
