# Environment Variables — reference

> **Status: ACTIVE.** The full env-var surface for running VERDICT, grouped by purpose. Each
> row names the default and which script/component reads it. Defaults are what the code ships;
> when in doubt, grep the script.

## Credentials (Amendment A1 — one of three, priority order)

| Var | Default | Read by | Notes |
|---|---|---|---|
| `CLAUDE_CODE_OAUTH_TOKEN` | unset | `install.sh`, `doctor.sh` | Preferred non-interactive mode (`claude setup-token`) |
| *(interactive `~/.claude/`)* | — | `install.sh` | Dev default if a Claude Code login exists |
| `ANTHROPIC_API_KEY` | unset | `install.sh` | Fallback mode 3 — direct metered API |

## Run mode / dashboard

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FIND_EVIL_LOCAL` | unset | `scripts/verdict` (set internally) | Enables live dashboard streaming to :3000 + pins `case_id` so the dashboard can open before the run finishes |
| `FINDEVIL_REPO_ROOT` | repo root | dashboard (`apps/web`) | Lets the dashboard serve audit JSONL from any case dir |
| `FINDEVIL_DASHBOARD_EXTRA_ROOTS` | unset | dashboard | Additional allowed roots for case paths (e.g. `tmp/auto-runs`) |
| `PYTHONPATH` | prepended `services/agent` | `scripts/verdict` (local mode) | Resolves the agent package in `FIND_EVIL_LOCAL=1` |
| `FINDEVIL_L1_DOCKER` | unset | dashboard build | Disables some Next.js optimizations for CI Docker |
| `FIND_EVIL_FAULT_INJECT` | unset | `find_evil_auto.py` (verify stage) | Demo/showcase fault hook: `verifier_reject_once:<finding-id-fragment>` corrupts ONE verify replay's tool name on the first attempt so the verifier rejects and the re-dispatch loop recovers — live, on camera. Inert by default; never silent (audited `fault_injection` record + stderr banner) |

## SIFT VM (`--sift` mode)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FIND_EVIL_GUEST_IP` / `SIFT_VM_IP` | `192.168.x.x` | `find-evil-sift`, `.mcp.json.sift` | SIFT VM IP (rewritten into `.mcp.json.sift`) |
| `FIND_EVIL_GUEST_USER` / `GUEST_USER` | `sansforensics` | `find-evil-sift` | SSH user on the VM |
| `FIND_EVIL_SSH_KEY` / `SIFT_SSH_KEY` | `~/.ssh/sift_key` | `find-evil-sift` | SSH private key |
| `FIND_EVIL_GUEST_REPO` / `GUEST_REPO_PATH` | `/home/sansforensics/find-evil` | `find-evil-sift` | Repo path inside the VM |
| `FIND_EVIL_GUEST_MOUNT_BIN` | unset | `find-evil-sift` | Passwordless-sudo mount wrapper on the VM (`disk_mount`, SIFT only) |
| `OVA_PATH` | repo-root `*.ova` | `sift-vm-bootstrap.sh` | Override SIFT OVA location |
| `FINDEVIL_SETUP_SIFT` | unset | `install.sh` | Non-interactive: build the SIFT VM without prompting |
| `FINDEVIL_SKIP_SIFT` | unset | `install.sh` | Skip SIFT VM setup |

## External DFIR tool binary overrides (Rust server resolves env-var first, then PATH)

| Var | Backs | Default resolution |
|---|---|---|
| `VOLATILITY_BIN` | `vol_pslist/psscan/psxview/malfind` | then `vol`/`vol.py`/`volatility3` on PATH |
| `HAYABUSA_BIN` | `hayabusa_scan` | then `hayabusa` on PATH |
| `VELOCIRAPTOR_BIN` | `vel_collect` | then `velociraptor` on PATH |
| `TSHARK_BIN` / `ZEEK_BIN` | `pcap_triage` / `zeek_summary` | then `tshark` / `zeek` on PATH |
| `FINDEVIL_FLS_BIN` / `FINDEVIL_ICAT_BIN` | `disk_extract_artifacts` (Sleuth Kit enumerate/extract) | then `fls` / `icat` on PATH |
| `FIND_EVIL_MEMORY_YARA_RULES` | `yara_scan` (memory) | optional rule-file override |
| `FIND_EVIL_DISK_YARA_RULES` | `yara_scan` (disk) | optional rule-file override |

## Setup / install toggles

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FINDEVIL_SKIP_BROWSER` | unset | `install.sh` | Skip Playwright/Puppeteer install |
| `FINDEVIL_SKIP_N8N` | unset | `install.sh` | Skip optional n8n automation setup |
| `FINDEVIL_DOWNLOAD_DIR` | `~/Downloads` | `setup` / browser MCP | Gated-asset download dir (set to `tmp/gated-downloads` to keep the OVA in-project) |
| `HAYABUSA_VERSION` / `CHAINSAW_VERSION` / `VOLATILITY_VERSION` / `VELOCIRAPTOR_VERSION` / `PANDOC_VERSION` | see [`dependencies.md`](dependencies.md) | `install-dfir-tools.sh` | Override external-tool pins |
| `FINDEVIL_LAUNCHER_SMOKE_BASH_TIMEOUT_SECONDS` | platform | launcher smoke | Windows Git Bash slow-start workaround |

## n8n automation (operator-runtime, optional)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `N8N_API_URL` | `http://localhost:5678` | `n8n-mcp`, `setup-n8n.py` | n8n base URL; if unreachable, n8n setup auto-skips |
| `N8N_API_KEY` | unset | `n8n-mcp` | REST key (provisioned by `setup-n8n.py` if omitted) |
| `MCP_MODE` | `stdio` | `n8n-mcp` | Required transport mode (set by `install.sh`) |
| `DISABLE_CONSOLE_OUTPUT` | `true` | `n8n-mcp` | Quiets pre-fetch output |

## obsidian-mind memory layer (dev/operator, optional)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `CLAUDE_PROJECT_DIR` | repo root | vault hook scripts | Resolves the vault hook script paths |
| `INDEX_PATH` | `~/.cache/qmd/<index>.sqlite` | `qmd-mcp.mjs` | Forces the QMD SQLite store (works around a qmd 2.1.0 `--index` bug) |

See [`../runbooks/obsidian-mind-memory.md`](../runbooks/obsidian-mind-memory.md) for the memory
layer; the QMD index name lives in `obsidian-mind/vault-manifest.json` (`qmd_index`).
