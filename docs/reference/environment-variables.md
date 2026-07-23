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
| `FIND_EVIL_REQUIRE_ASSERTED_VALUES` | unset (`1` to enable) | `events.Finding` validator | Fact-fidelity (R3) gate: when `1`, a CONFIRMED finding MUST declare `asserted_values` and an INFERRED finding MUST declare `asserted_values` or `derived_from`, so the verifier's entailment check can re-extract each value. Default-off until the finding emitters populate the field. |
| `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS` | unset (`1` to enable) | `judge.judge_findings` | Counter-hypothesis gate: when `1`, a solo (single-pool, uncorroborated) CONFIRMED finding collapses to INFERRED unless cross-pool corroboration raises it back — a CONFIRMED claim must survive the other pool's challenge. Default-off; trades recall for a stricter corroboration bar (the verifier + ≥2-artifact-class gate already cover this in the default pipeline). |
| `FIND_EVIL_REQUIRE_ARTIFACT_REBIND` | unset (`1` to enable) | `verifier.reverify_finding` | Evidence re-binding gate: when `1`, the verifier re-derives the artifact from the cited tool_call's recorded `*_path` argument(s) and REJECTS (`drift_class=artifact_rebind_mismatch`) a finding whose claimed `artifact_path` does not match what the cited call read — hardens against a real `tool_call_id` glued to a fabricated artifact. A preflight (runs before replay); a call with no `*_path` argument is not gated. Default-off until finding emitters set `artifact_path` to the cited call's path. |
| `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING` | unset (`1` to enable) | `events.Finding` validator + `verifier.reverify_finding` | Anti-coherence "too clean" gate: when `1`, a CONFIRMED finding MUST carry a non-blank `counter_hypothesis` (the benign alternative it ruled out); the schema validator rejects construction and the verifier preflight rejects re-verify (`drift_class=counter_hypothesis_missing`). Binds only CONFIRMED (the strongest tier); lower tiers exempt. Complements the judge.py `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS` discipline. Default-off until emitters populate the field. |
| `FIND_EVIL_REQUIRE_TOOL_CALL_ID` | `1` (unset); `0` disables | `events.Finding` validator | Evidence-anchor firewall, **default-ON**: a CONFIRMED/INFERRED finding must carry a non-blank `tool_call_id` at construction time. Set to `0` as an escape-hatch opt-out. HYPOTHESIS is exempt. |
| `FIND_EVIL_REQUIRE_EXPECTATION` | unset (`1` to enable) | `verifier.reverify_finding` | Falsifiable-expectation gate: when `1`, a finding that committed to a refutable `expectation` prediction is demoted if the re-run evidence holds a contradicting value. Default-off so default verdicts never change. |
| `FIND_EVIL_REQUIRE_FP_SUPPRESSORS` | unset (`1` to enable) | `correlator_suppressors` | False-positive suppressor gate: when `1`, curated demoting suppressors (e.g. known-good-hash / vendor-signed-path context) can soften a finding's confidence — never on non-clearable signatures (credential-dumping, log-clearing, backup-destruction, defense-impairment). Default-off. |
| `FIND_EVIL_REQUIRE_TEMPORAL_COUPLING` | unset (`1` to enable) | `correlator_temporal` | Timing-source gate: when `1`, a timing ("when it ran") claim resting solely on a catalog/registration/`$SI`/`$FN`-class timestamp (not an execution timestamp) is demoted. Downgrade-only, evidence-agnostic. Default-off. |
| `FIND_EVIL_REQUIRE_BENIGN_EVIDENCE` | unset (`1` to enable) | `correlator.py` (`correlator_benign`) | Exoneration gate: when `1`, a curated benign-clearance library can HOLD (never clear or raise) a finding — never softens a non-clearable signature. Default-off. |
| `FIND_EVIL_REQUIRE_WHY_NOT_HIGHER` | unset (`1` to enable) | `correlator.py` | Mirrors the benign-gate flag style: opt-in, downgrade-only, custody-neutral. Default-off. |

## Evidence location

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FINDEVIL_EVIDENCE_ROOT` | repo-root `evidence/` | `scripts/find_evil_auto.py` | Override the default evidence drop directory; precedence is explicit CLI path > `$FINDEVIL_EVIDENCE_ROOT` > repo-local `evidence/`. |
| `FINDEVIL_HOME` | `${PROJECT_LOCAL}/findevil` (contained under `.project-local/`) | `scripts/lib/project-env.sh`, Rust tools (`case_open`, `disk.rs`, `bulk_extract.rs`, `pst_parse.rs`, `srum_parse.rs`), Python agent config | Case-store root: where `case_open` creates the per-case directory tree. Falls back to `~/.findevil` when `$HOME`/`$USERPROFILE` is set and `FINDEVIL_HOME` is unset. |

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
| `FINDEVIL_SIGNER` | `ed25519` | `make_signer` (manifest sealing) | Signer tier: `ed25519` (real local signature, verifies offline), `sigstore` (identity + transparency log; customer tier), `stub` (dev placeholder) |
| `FINDEVIL_SIGNING_KEY` | `~/.findevil/signing.key` | `LocalEd25519Signer` | Path to the local Ed25519 private key (auto-generated on first use, `0600`) |

## External DFIR tool binary overrides (Rust server resolves env-var first, then PATH)

| Var | Backs | Default resolution |
|---|---|---|
| `VOLATILITY_BIN` | `vol_pslist/psscan/psxview/malfind` | then `vol`/`vol.py`/`volatility3` on PATH |
| `HAYABUSA_BIN` | `hayabusa_scan` | then `hayabusa` on PATH |
| `HAYABUSA_RULES_BASE` | `hayabusa_scan` (Sigma rule dir) | then `$XDG_DATA_HOME`, then `$HOME`-relative default |
| `VELOCIRAPTOR_BIN` | `vel_collect` | then `velociraptor` on PATH |
| `TSHARK_BIN` / `ZEEK_BIN` | `pcap_triage` / `zeek_summary` | then `tshark` / `zeek` on PATH |
| `FINDEVIL_FLS_BIN` / `FINDEVIL_ICAT_BIN` | `disk_extract_artifacts` (Sleuth Kit enumerate/extract) | then `fls` / `icat` on PATH |
| `EWF_MOUNT_BIN` | `disk_mount` (E01 mount) | then `ewfmount` on PATH |
| `FINDEVIL_MOUNT_BIN` / `FINDEVIL_UMOUNT_BIN` | `disk_mount` / `disk_unmount` | then `mount` / `umount` on PATH |
| `EZTOOLS_DIR` | `ez_parse` (Eric Zimmerman tools) | then EZ tools on PATH |
| `PLASO_DIR` | `plaso_parse` (log2timeline) | then plaso on PATH |
| `MAC_APT` | `mac_triage` | then `mac_apt.py`/`mac_apt` on PATH |
| `JOURNALCTL_BIN` | `journalctl_query` | then `journalctl` on PATH |
| `LAST_BIN` | `login_accounting` | then `last` on PATH |
| `AUSEARCH_BIN` | `ausearch` | then `ausearch` on PATH |
| `NFDUMP_BIN` | `nfdump_query` | then `nfdump` on PATH |
| `SURICATA_BIN` | `suricata_eve` | then `suricata` on PATH |
| `INDXPARSE_BIN` | `indx_parse` | then `INDXParse.py` on PATH |
| `FINDEVIL_ESEDBEXPORT_BIN` | `srum_parse` (libesedb) | then `esedbexport` on PATH |
| `FINDEVIL_PFFEXPORT_BIN` | `pst_parse` (libpff) | then `pffexport` on PATH |
| `FINDEVIL_VSHADOWINFO_BIN` / `FINDEVIL_VSHADOWMOUNT_BIN` | `vss_list` / `vss_mount` (libvshadow) | then `vshadowinfo` / `vshadowmount` on PATH |
| `FINDEVIL_BULK_EXTRACTOR_BIN` | `bulk_extract` | then `bulk_extractor` on PATH |
| `FINDEVIL_BULK_KEYWORD_FILE` | `bulk_extract` (keyword/regex scan) | unset — no default keyword file |
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
| `FINDEVIL_ENABLE_N8N` | unset (`1` to enable) | `scripts/verdict-setup.sh` | Opt-in: actively start a local n8n and wait for it before the run (post-verdict automation/grounding stays skipped otherwise) |

## QMD memory sidecar (operator-local, optional)

| Var | Default | Read by | Purpose |
|---|---|---|---|
| `FINDEVIL_ENABLE_QMD` | `0` | `scripts/run-mcp-qmd.sh` | Explicit opt-in for the local operator memory sidecar. |
| `INDEX_PATH` | `~/.cache/qmd/<index>.sqlite` | local `qmd-mcp.mjs` | Forces the QMD SQLite store when an operator supplies a local `obsidian-mind/` vault. |

The public release does not ship an operator memory vault. `scripts/run-mcp-qmd.sh`
exits cleanly unless `FINDEVIL_ENABLE_QMD=1` is set and
`obsidian-mind/.claude/scripts/qmd-mcp.mjs` is present as a real local file.
