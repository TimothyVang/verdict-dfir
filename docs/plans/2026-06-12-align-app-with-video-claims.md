# Plan: align the app with the demo-video claims (2026-06-12)

## Context

The demo narration makes the product sound effortless and strong. An adversarial
verification (11 agents, code + run artifacts) found 4 places the app falls short of
the claim. Rather than keep softening the script, raise the app:

1. **One-command fleet** — today the multi-host fleet is three scripts run by hand
   (`fleet_investigate.py` → `fleet_correlate.py` → `render_fleet_report.py`).
2. **Real signature by default** — demo runs are stub-"signed"
   (`signature_verified=false`); sigstore is opt-in and needs OIDC + network.
3. **Show the two-team debate** — disk cases have ZERO Pool A emitters
   (registry persistence keys are queried but only feed the timeline), so
   `detect_contradictions` can never fire on disk-only cases.
4. **Verifier + fleet polish** — sha256 drift on a CONFIRMED finding silently
   downgrades (never re-checked); fleet correlations lack epistemic labels.

Execution order: Gap 2 (crypto core, no dependents) → Gap 3 (engine emitters) →
Gap 4 (verifier policy + fleet labels) → Gap 1 (one-command fleet, consumes 4c).
TDD per repo §7: failing test → implement → green → one conventional commit per task.

## Gap 2 — real signature by default (Tasks 1–5)

- **T1 `feat(crypto): add LocalEd25519Signer with auto-generated local keypair`**
  RED: `services/agent/tests/test_crypto_signer.py::TestLocalEd25519Signer` (tmp_path key;
  kind=="ed25519"; bundle has public_key_b64+signature_b64; key file 0o600; stable
  cert_fingerprint across instances; round-trip verify with cryptography Ed25519PublicKey).
  GREEN: `services/agent/findevil_agent/crypto/signer.py` — `LocalEd25519Signer(key_path)`,
  `_default_key_path()` honoring `FINDEVIL_SIGNING_KEY` (default `~/.findevil/signing.key`,
  dir 0o700, file 0o600, lazy cryptography import). cryptography==46.0.7 already locked via sigstore.
- **T2 `feat(crypto): default signer ed25519; stub becomes explicit opt-in`**
  RED: rewrite `test_default_is_stub` → `test_default_is_ed25519`; env `FINDEVIL_SIGNER=ed25519` case.
  GREEN: `make_signer` default `"ed25519"`, new branch.
- **T3 `feat(crypto): offline cryptographic verification of ed25519-signed manifests`**
  RED: `test_crypto_manifest.py` — build manifest with ed25519 signer → `verify_manifest`
  ⇒ `signature_verified is True`, kind=="ed25519", overall true; tampered body/bundle ⇒ reason string.
  GREEN: `manifest.py` `_signature_verified(sig, manifest_obj)` — ed25519 branch reconstructs
  canonical body (manifest minus `signature`) and verifies. Stub/sigstore strings preserved verbatim.
  `overall` stays presence-based (live-test gate safe).
- **T4 `feat(agent-mcp): ed25519 signer tier in manifest_finalize; sigstore degrades to ed25519`**
  RED: `services/agent_mcp/tests/test_manifest_tools.py` — signer="ed25519" finalize
  (monkeypatch FINDEVIL_SIGNING_KEY) → effective ed25519 + verify True; default-omitted → ed25519;
  engine test: ed25519-sealed manifest still does NOT unlock customer release (policy pinned).
  GREEN: `manifest_finalize.py` Literal["stub","ed25519","sigstore"] default "ed25519";
  chains: ed25519→Fallback(ed25519, stub); sigstore→Fallback(sigstore, Fallback(ed25519, stub)).
  `find_evil_auto.py` --signer choices+default (lines ~10082); release-gate predicate at 8940 UNCHANGED
  (sigstore-only customer tier — explicit policy decision); blocker wording updated.
  `render_report.py:1900` label uses `signature.kind` instead of hardcoded "Sigstore".
- **T5 `docs(crypto): document the ed25519 default signing tier`**
  `docs/cryptographic-attestation.md` (3 signer tiers), `docs/reference/environment-variables.md`
  (FINDEVIL_SIGNER, FINDEVIL_SIGNING_KEY), `agent-config/TOOLS.md` manifest_finalize blurb.

## Gap 3 — Pool A disk persistence emitters (Tasks 6–7)

- **T6 `feat(engine): classify non-default Run/RunOnce values and suspicious service entries`**
  RED: new `services/agent/tests/test_registry_persistence.py` — pure-function cases:
  user-writable Run target → run_key candidate; SecurityHealth → filtered; System32 svchost →
  filtered; service ImagePath under \Users\ → service candidate; empty → [].
  GREEN: `BENIGN_REGISTRY_RUN_VALUES` (conservative lowercase allowlist) +
  `registry_persistence_candidates(entries, key_path)` in `find_evil_auto.py` (~line 647,
  near `suspicious_prefetch_tool_hint`; reuse COMMON_WIN_PROCS import for basename check).
- **T7 `feat(engine): emit Pool A persistence Findings from extracted-disk registry triage`**
  RED: integration-shaped test — `_emit_registry_persistence_findings` with synthetic candidates
  + `prefetch_exes={"evil.exe":"tc-pf-1"}` ⇒ CONFIRMED `f-A-reg-persist-*` citing the registry tcid,
  derived_from includes prefetch tcid, service finding description starts "hypothesis: ",
  pool_origin=="A".
  GREEN: emitter method; hook into registry loop (~line 7432); collect `prefetch_exes` in the
  prefetch loop (~7300). Run-key existence = CONFIRMED ("persistence mechanism present", NOT an
  execution claim); services = HYPOTHESIS (T1543.003); run keys = T1547.001.
  RISK (highest): any CONFIRMED ⇒ SUSPICIOUS (compute_verdict ~9210) — the suspicious-tell gate +
  allowlist prevents benign disks flipping; validate with live tests before commit.

## Gap 4 — verifier drift reject + fleet labels (Tasks 8–10)

- **T8 `feat(verifier): reject CONFIRMED findings on sha256 drift, re-dispatch once before downgrade`**
  RED: `test_verifier.py` — confirmed drift ⇒ rejected; with `downgrade_on_drift=True` ⇒ downgraded;
  INFERRED drift ⇒ immediate downgrade. `test_verifier_redispatch.py` — drift rejection re-dispatches
  once with force_fresh_replay + downgrade_on_drift; persistent drift terminal = downgraded (kept).
  GREEN: `verifier.py` drift branch (~141–155) gains `downgrade_on_drift: bool = False`;
  `verify_finding.py` MCP input field; `_redispatch_rejections` retry args (drift_class
  `material_drift` is already re-dispatchable — gate at 8359 untouched).
  Watch: recovered drift must not become a replay-failure blocker (add the drift twin of
  `test_recovered_redispatch_is_not_a_replay_failure_blocker`).
- **T9 `feat(engine): add verifier_hash_mismatch_once fault-injection mode`**
  RED: `test_fault_injection.py` — hash-mode mirrors F1–F4; audit record mode field; once per run;
  reject-mode unchanged.
  GREEN: `fault_inject_spec` accepts both modes; `_consume_fault_targets` returns dict[id,mode];
  corruption branch sets `output_sha256="f"*64` for the hash mode.
- **T10 `feat(fleet): HYPOTHESIS epistemic labels on cross-host correlations`**
  RED: extend `scripts/fleet-policy-smoke.py` — clusters + cross-host hits carry
  `epistemic_label=="HYPOTHESIS"`.
  GREEN: `fleet_correlate.py` `_cluster_to_dict` (~358) + per-hit dicts (~311); "hypothesis: "
  narrative prefixes in fleet_correlate + render_fleet_report md; `docs/false-positives.md` sync.

## Gap 1 — one-command fleet (Tasks 11–13)

Decision: bash, not a new orchestrator — `scripts/verdict` stays THE entry point;
`run-whole-case-local.sh` already solves local enumeration + resume (skip-if-summary-exists).
Missing piece: a fleet.json adapter for correlate.

- **T11 `feat(fleet): build fleet.json from local whole-case results`**
  RED: `services/agent/tests/test_fleet_local.py` — synthetic results.jsonl (3 rows, one without
  case_dir) → fleet.json results carry host+case_dir; round-trip via `fleet_correlate.load_verdicts`.
  GREEN: new `scripts/fleet_local.py` (~60 lines stdlib, `results_to_fleet()` + main);
  invoke from `run-whole-case-local.sh` after the loop (~line 75).
- **T12 `feat(verdict): one-command fleet — auto-detect multi-host case folders, run all three stages`**
  RED: `services/agent/tests/test_verdict_fleet_launcher.py` — subprocess dry-run on a tmp case-root
  with hosts/h1/ names all three stages; flat single-file evidence does NOT enter fleet mode.
  GREEN: `scripts/verdict` — `--fleet` flag (arg loop 58–73) + auto-detect (dir containing hosts/ or
  disks/) after evidence resolution (~151); local: run-whole-case-local.sh → fleet_local.py →
  fleet_correlate.py → render_fleet_report.py (render degrades with warn, doesn't fail);
  SIFT: fleet_investigate.py → correlate → render; fleet dir `tmp/fleet-runs/fleet-local-<name>`
  (stable = resumable, matches the `fleet-*` glob); staging-refusal message (~211) now points at
  `--fleet`. Per-host targets contain no hosts|disks subdirs ⇒ no recursion.
- **T13 `docs(fleet): document one-command fleet mode`**
  `docs/using/fleet-analysis.md` (lead with the one command; 3 scripts become "under the hood"),
  `docs/using/whole-case-local-run.md`, `docs/using/running-verdict.md`, CLAUDE.md §4 entry-points line.

## Risks

1. Gap 3 verdict inflation (CONFIRMED ⇒ SUSPICIOUS) — tell-gate + allowlist; live-validate on a
   benign disk + NIST before commit; fallback: demote uncorroborated run-key findings one tier.
2. Signer default change — `overall` presence-based so gate safe; tests must monkeypatch
   FINDEVIL_SIGNING_KEY; ed25519→stub fallback covers HOME-less CI; committed stub sample runs still
   verify (stub branch preserved verbatim); render_report label fixed.
3. Gap 4a — drift on CONFIRMED costs one extra replay; audit-chain shape changes for drift cases only.
4. Fleet labels are additive keys — render/_cross_host_counts verified safe.
5. CI: verify in a clean checkout (git archive) — gitignored files differ from working tree.

## Verification (done gate)

- Per task: `uv run pytest` (agent + agent_mcp), `cargo test --workspace --locked`,
  `fleet-policy-smoke.py`, `verdict-policy-smoke.py`, `report-policy-smoke.py`,
  `launcher-smoke.py`, `ruff check` on touched files.
- Live tests:
  1. `scripts/verdict <real disk> --no-dashboard --unattended` → manifest_verify.overall true AND
     `signature_verified == true` with kind "ed25519"; Pool A `f-A-reg-persist-*` present on a
     disk with real run-key persistence; benign disk stays honest.
  2. `FIND_EVIL_FAULT_INJECT=verifier_hash_mismatch_once:<fragment> scripts/verdict <evidence>` →
     audit shows fault_injection → rejected (drift) → verifier_redispatch → approved.
  3. `scripts/verdict evidence/cases/srl-2018 --no-dashboard` → auto-detected fleet: per-host table,
     fleet.json + fleet_correlation.json (epistemic_label HYPOTHESIS) + FLEET_REPORT.md;
     re-run skips completed hosts (resume proof).
