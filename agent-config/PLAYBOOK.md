# PLAYBOOK.md — Investigation tool sequences

**Read after AGENTS.md, before TOOLS.md.** This file tells you (the supervisor) the canonical tool sequences for common evidence types so you don't have to re-derive them every investigation. Treat these as **defaults**, not laws — when the case shape diverges, deviate and say so explicitly in the audit trail.

---

## Activation rule

When the analyst says **"investigate &lt;path&gt;"**, **"find evil in &lt;path&gt;"**, **"do DFIR on &lt;path&gt;"**, or any clear analog:

1. Call `case_open` with the path. Read the returned `image_hash`, `image_size_bytes`, and `id` (the case_id you'll use everywhere).
2. Inspect the path's extension and the case-open size to pick a playbook below.
3. Fork **two subagents** via Claude Code's native Task mechanism — one with the Pool A persistence prompt, one with Pool B exfil prompt (see `AGENTS.md`). Each pool reads this file and runs its biased-but-still-overlapping tool sequence. (Note: `CLAUDE_CODE_FORK_SUBAGENT=1` is a build-time internal; do not set it in the product.)
4. After both pools return Findings, run `detect_contradictions` → resolve (or auto-pass under `--unattended`) → `verify_finding` per Finding → `judge_findings` → `correlate_findings` → `report_qa` → `manifest_finalize` (terminal step under Amendment A5; the prior `ots_stamp` Bitcoin anchor was removed). The report QA lands in the audit chain BEFORE finalize so it is part of the cryptographic attestation — the agent doesn't get to revise it after the chain is sealed.
5. Render the verdict + manifest path. The verdict/report may include `attck_practitioner_coverage`, `normalized_timeline`, `report_evidence_cards`, and `source_bibliography`; treat those as coverage/reporting aids, not new evidence classes.

Report fields to interpret consistently:

- `attck_practitioner_coverage` maps current evidence and typed-tool output to GCFA/GNFA/GREM-style practitioner lanes. It is honest coverage accounting, not a claim that the product replaces certified analysts.
- `normalized_timeline` preserves source timestamp, artifact class, `tool_call_id`, and source record reference. Timeline context does not become a Finding without artifact-backed semantics.
- `report_evidence_cards` are generated exhibits for the PDF. Each card must point back to parsed tool output and source citations; visuals do not create Findings or raise confidence.
- `source_bibliography` resolves external source citation IDs used for ATT&CK/data-source/report interpretation.
- `malware_triage` records memory-region, string, IOC, and YARA/malfind leads as triage-only context; it does not identify who operated code or prove execution.
- `analysis_limitations` records scope gaps. Auto disk mode currently records custody only unless mounted artifacts are supplied, so do not emit disk-content Findings from `case_open` alone.
- `attack_story`, `report_qa`, and `expert_signoff` are signoff/reporting aids derived from the same Findings, timeline, coverage, and limitations. They do not create Findings or raise confidence; they tell the 1% human expert whether the PDF is ready to review or blocked.

---

## Cross-case memory hooks (A3 §2.2)

Two MCP tools (`memory_recall`, `memory_remember`) and one structured-handoff tool (`pool_handoff`) wire into the standard sequence above. The supervisor's job is to make sure they fire at the right beats:

- **Session start (supervisor):** resolve `MEMORY_STORE_PATH` once via the `Bash` tool, per the recipe in `AGENTS.md` § supervisor. Pass it to forked Pool A / Pool B / verifier subagents in their prompts so they don't re-derive it.
- **Pre-Finding (each pool):** before each pool emits a Finding, it calls `memory_recall(store_path=MEMORY_STORE_PATH, query=<the IOC|hash|TTP|hostname>)`. A non-empty hit becomes a `prior_observations` field on the Finding for prioritization and context only. Prior-case memory is not current-case evidence and must not count toward the SOUL.md >=2 current-case artifact-class rule. An empty hit is also informative — note "no prior observations" so the analyst sees recall happened.
- **Post-judge (each pool, only for CONFIRMED Findings):** the originating pool calls `memory_remember(...)` with the IOC / hash / TTP that it would want a future investigation to recall. HYPOTHESIS-tier doesn't get remembered (the chain only keeps things the army stands behind).
- **Verifier → judge (always):** after each verdict, the verifier calls `pool_handoff(from_role="verifier", to_role="judge", payload={finding_id, action, replay_record_sha256})` so the judge receives structured input rather than parsing natural-language supervisor messages.
- **Pool A → Pool B (when relevant):** if Pool A surfaces evidence that the persistence is staging for exfil (e.g. a Run-key dropper that drops to `\Users\Public\`), it should `pool_handoff(from_role="pool_a", to_role="pool_b", payload={persistence_path, dropped_artifacts, ttps})` so Pool B can pick up the thread. Use the same `correlation_id` for every handoff about that finding.

These hooks are additive — they do not change the per-evidence-type tool sequences below.

---

## Evidence-type playbooks

Pick the one whose extension matches the input. If multiple apply (e.g., a case directory containing both an `.e01` and a `.mem`), run them in order and let the case_id thread them together.

### `.e01` / `.E01` / `.dd` / `.raw` / `.aff` — full disk image

The deepest evidence type. Run all the disk-class tools.

Note: `scripts/find-evil-auto` intentionally deviates today for raw disk images: it performs `case_open`, hashes the image, records the limitation, and returns `INDETERMINATE` unless mounted/extracted artifacts are supplied for the typed disk tools below. Do not treat custody-only disk registration as a Finding.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `mft_timeline` | Master File Table — what existed when, with timestomp detection (`$SI` vs `$FN`) | both |
| 3 | `prefetch_parse` | Per-binary execution evidence (run_count, last 8 run times) | A |
| 4 | `usnjrnl_query` | Filesystem mutation log — corroborates MFT, surfaces deletes | both |
| 5 | `registry_query` | Run / RunOnce / IFEO / Services / WMI consumers / Scheduled Tasks | A |
| 6 | `evtx_query` | Security.evtx (4624/4625/4688/7045), System.evtx, Application.evtx | A |
| 7 | `hayabusa_scan` | Sigma rules over the EVTX dir — surfaces persistence + lateral movement patterns | A |
| 8 | `yara_scan` | YARA-Forge rules over `\Users\*\AppData\Roaming\` and any `.exe`/`.dll` newer than 30d | B |
| 9 | `vel_collect` (optional) | Pull additional OS-level artifacts the wrappers above don't cover (browser history, scheduled tasks raw) | both |

### `.mem` / `.raw` / `.dmp` / `.vmem` — memory image

Memory tells you what was *running*, not just what was *installed*.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `vol_pslist` | Process list from `PsActiveProcessHead` (active-list walk) | both |
| 3 | `vol_psscan` | EPROCESS pool-memory signature scan — finds blocks unlinked from the active list | both |
| 4 | `vol_psxview` | Cross-view process enumeration — identifies which process views miss recovered processes | both |
| 5 | `vol_malfind` | RWX VADs + MZ headers in unexpected places (code injection) | both |
| 6 | `yara_scan` | YARA over the raw memory image — catches in-memory-only payloads | B |

**The `vol_pslist` + `vol_psscan` pair is mandatory, not optional.** pslist walks the kernel's active list; psscan signature-scans EPROCESS pool memory for blocks unlinked from that list. **Divergence between the two outputs IS the forensic finding** — `pslist=0` + `psscan>0` is the textbook MITRE ATT&CK T1014 (Rootkit) DKOM signature. Always emit a `vol_psscan` call after `vol_pslist`, even if pslist returned a healthy count, so the audit chain has both for cross-validation. When the pair diverges, run `vol_psxview` next to identify which process-enumeration views miss each recovered PID.

After memory: if a disk image for the same host is available, **cross-reference** PIDs from `vol_pslist` against `prefetch_parse` run lists. A process running in memory with no Prefetch entry is a strong signal of an unprefetched (likely manual or scripted) execution — surface as a Finding.

### `.evtx` — single Windows event log

The lightweight case (matches our `--real-evidence` smoke flow).

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `evtx_query` | Parse the log; pull EID histogram | both |
| 3 | `hayabusa_scan` (optional, if a `.evtx` directory is available) | Sigma rule scan | A |

### Velociraptor `.zip` collection

Triage zips produced by `velociraptor` collection.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | Velociraptor zip extraction | Safely extract supported contained artifacts to the case work dir; reject zip-slip and oversized members | both |
| 3 | Per-artifact tools | E.g. if the zip contains a Prefetch artifact, run `prefetch_parse` against the extracted file; if it contains EVTX, run `evtx_query` / `hayabusa_scan` | both |

### Mixed case directory (most realistic)

A case dir contains a disk image, a memory image, a Velociraptor zip, and a few EVTX files extracted out-of-band. Run each per its type playbook above; the supervisor stitches case_ids together via the `case_id` argument every tool accepts.

---

## Pool biases (recap from `AGENTS.md`)

The same tool sequence runs in both pools, but each pool's **prompt** biases interpretation:

- **Pool A — Persistence.** Looks for "the attacker is staying": Run keys, Services, IFEO, ScheduledTasks, WMI subscription consumers, LSASS-injected modules, browser-helper-objects, autoruns. Findings cite MITRE T1547 / T1543 / T1546 / T1053 / T1574.
- **Pool B — Exfiltration / general malware.** Looks for "the attacker took something": staging directories (often `\Users\Public\`, `\Temp\`), `certutil`/`bitsadmin`/`curl`/`wget`/`Invoke-WebRequest` execution, cloud-sync clients, USB writes, large-file rename-then-delete patterns, suspicious outbound network endpoints in EVTX or memory. Findings cite MITRE T1041 / T1567 / T1048 / T1052 / T1110.

Where the pools see the same artifact and disagree on confidence or interpretation, **`detect_contradictions` is supposed to fire** — that's the architectural feature, not a bug. Surface it before the judge.

---

## Unattended-mode policy (`--unattended`)

When the analyst is not present (CI runs, batch processing, demo recordings):

- **Contradictions** are auto-resolved by trusting the higher-credibility pool, and the auto-trust decision is logged with `approved_by: "auto"` in the audit chain. This is auditable; it is not a free pass.
- **HYPOTHESIS-tier Findings are kept** rather than dropped — the verifier vetoes only Findings without a `tool_call_id`.
- **Network-touching tools** (`vel_collect` artifacts that hit external systems; sigstore Rekor submission inside `manifest_finalize`) still run. If network is unreachable, log the failure to the audit chain and continue; don't abort the manifest. (Pre-A5 this list also included `ots_stamp`; that tool was removed.)
- **Final verdict** is rendered to stdout AND written to `$FINDEVIL_HOME/cases/<id>/verdict.json` so a downstream process can read it without re-parsing terminal output.

In attended mode, the supervisor pauses at:
1. Contradiction surface (Trust A / Trust B / Flag)
2. Verifier veto (re-run cited tool to re-confirm)
3. Final manifest review before signing

These pause points are **resumable** — the audit chain is hash-chained, so the supervisor can be killed mid-run and resume from the last record.

---

## Stop conditions (the agent must stop and ask)

Even in unattended mode, halt and surface to the analyst when:

- A tool returns a `BinaryNotFound` error (the user's environment is missing a SIFT tool — they need to install it, not the agent's call to make).
- Two consecutive iterations produce no new Findings AND no new contradictions (you're stuck; further tool calls won't help).
- A Finding's `confidence` is `CONFIRMED` but the corroboration count from `correlate_findings` is < 2 artifact classes (SOUL.md violation; auto-downgrade is the right answer but flag it explicitly).
- The case's evidence vault is mid-run modified (a write to `/evidence/<case_id>/` from outside the agent loop) — this means the chain of custody is compromised; refuse to sign the manifest.

---

## What this playbook is NOT

- **Not a script.** The supervisor is the agent; this file is its prior. If a case looks weird, deviate.
- **Not exhaustive of DFIR.** It covers what the 19 typed Rust MCP tools can reach. If the case needs Plaso/log2timeline, Sleuthkit's `fls`/`icat`, Bulk Extractor, broad interactive packet carving, or browser-history extraction, those are out of our automation scope today; surface that as a gap to the analyst.
- **Not a substitute for SOUL.md or AGENTS.md.** Read those first; this file is the operational layer that sits below the epistemic and role-definition layers.
