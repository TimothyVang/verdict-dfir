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

- `attck_practitioner_coverage` maps current evidence and typed-tool output to DFIR analysis-domain lanes (Host & Endpoint, Memory, Windows Event & Account, Network, Malware, Live Response). It is honest coverage accounting, not a claim that the product replaces certified analysts.
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

## Two execution paths (keep them in sync)

This file is read by **agent mode** (interactive `claude` → "investigate `<path>`"): *you*, the
supervisor, read these sequences and run the tools. The **headless engine**
(`scripts/verdict` → `scripts/find_evil_auto.py`) does **not** read this file — it implements the
same sequences hardcoded in its `investigate_*` methods. **When you change a sequence here, change
the matching `investigate_*` method too, or the two paths drift.**

---

## Tool inventory (45 product tools)

The complete typed surface both paths can drive. Argument/output shapes live in `TOOLS.md`; this is
the at-a-glance map of *what exists* and *when it runs*.

### Rust `findevil-mcp` (32) — DFIR primitives, read-only on evidence, SHA-256 every output

| Tool | What | Runs for |
|---|---|---|
| `case_open` | SHA-256 the evidence, open the Case, derive `case_id` | **every** run (first call) |
| `disk_mount` | Loop/EWF-mount a disk image read-only (`ewfmount`+inner volume via TSK) | disk |
| `disk_extract_artifacts` | Carve MFT/USN/Prefetch/Registry/yara-targets from the mount; recovers deleted-but-metadata-intact files (`__deleted__/<inode>/`, realloc'd inodes skipped) | disk |
| `disk_unmount` | Release the mount (finally-block) | disk |
| `mft_timeline` | `$MFT` timeline, `$SI` vs `$FN` timestomp detection | disk |
| `usnjrnl_query` | `$UsnJrnl` change log — corroborates MFT, surfaces deletes | disk |
| `prefetch_parse` | Per-binary execution evidence (run_count, last-run times) | disk |
| `registry_query` | Run/RunOnce/IFEO/Services/WMI/Tasks keys | disk |
| `browser_history` | Visited-URL timeline from an extracted Chrome/Edge `History` or Firefox `places.sqlite` (read-only, `immutable=1`) | disk (browser DB) |
| `evtx_query` | Parse a single `.evtx` (EID histogram, 4624/4625/4688/7045…) | evtx, disk, velo |
| `hayabusa_scan` | Sigma rules over an EVTX **directory** (dir-based; not single files) | evtx-dir, velo, disk-extracted |
| `yara_scan` | YARA over a memory image or extracted disk yara-targets | memory, disk (if targets) |
| `vol_pslist` | Active-list process walk | memory |
| `vol_psscan` | EPROCESS pool signature scan (DKOM detection vs pslist) | memory |
| `vol_psxview` | Cross-view process enumeration (conditional on pslist≠psscan) | memory |
| `vol_malfind` | RWX VADs / injected MZ headers | memory |
| `sysmon_network_query` | Sysmon network-connection events | network |
| `zeek_summary` | Zeek conn/dns/http summaries | network |
| `pcap_triage` | PCAP/PCAPNG triage (can drive Zeek internally) | network |
| `vel_collect` | Velociraptor live-collection (note: velo **zips** are unzipped + re-dispatched locally, not via this tool) | velociraptor |

### Python `findevil-agent-mcp` (13) — reasoning, crypto/custody, memory; run in the reason/seal phase

| Tool | What | When |
|---|---|---|
| `audit_append` | Append a record to the hash-chained `audit.jsonl` | every tool call / decision |
| `audit_verify` | Standalone replay-verify of the chain | offline (not in the in-run flow) |
| `detect_contradictions` | Surface Pool A ↔ Pool B disagreements | after both pools |
| `verify_finding` | Re-run a Finding's cited tool, compare SHA-256 | per Finding |
| `judge_findings` | Credibility-weighted merge of verified Findings | after verify |
| `correlate_findings` | Enforce the ≥2-artifact-class rule, downgrade unsupported | after judge |
| `manifest_finalize` | Build the Merkle tree, sign — terminal, seals the Case | last |
| `manifest_verify` | Verify the signed manifest in-run | after finalize |
| `memory_recall` | Hermes FTS5 recall before a Finding (`prior_observations`, non-evidentiary) | pre-Finding |
| `memory_remember` | Remember a CONFIRMED Finding's IOC/TTP for future cases | post-judge, CONFIRMED only |
| `pool_handoff` | Structured ACP handoff (verifier→judge, pool_a→pool_b) | per handoff |
| `expert_miss_capture` | Record a 1% expert correction as a future playbook/gate | on expert edit |
| `accuracy_compare` | Read-only TP/FP/FN + precision/recall/F1/hallucination diagnostic of a finished Case's `verdict.json` vs a curated golden — a **diagnostic, never a Finding** | offline (post-Case QA, not in the in-run flow) |

The 4 **non-product** MCP servers (`n8n-mcp`, `playwright`, `puppeteer`, `qmd`) never touch evidence
and never emit Findings — they are not in this inventory.

---

## Evidence-type playbooks

Pick the one whose extension matches the input. If multiple apply (e.g., a case directory containing both an `.e01` and a `.mem`), run them in order and let the case_id thread them together.

### `.e01` / `.E01` / `.dd` / `.raw` / `.aff` — full disk image

The deepest evidence type. Run all the disk-class tools.

Note: `scripts/find-evil-auto` intentionally deviates today for raw disk images: it performs `case_open`, hashes the image, records the limitation, and returns `INDETERMINATE` unless mounted/extracted artifacts are supplied for the typed disk tools below. Do not treat custody-only disk registration as a Finding.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `disk_mount` | Mount read-only — EWF container via `ewfmount`, then the inner volume via TSK. **Local mode mounts the container only; the inner-volume mount needs the SIFT VM (`--sift`).** | both |
| 3 | `disk_extract_artifacts` | Carve MFT/USN/Prefetch/Registry (and yara-targets, if any) to the work dir; deleted-but-metadata-intact files recover under `__deleted__/<inode>/` | both |
| 4 | `mft_timeline` | Master File Table — what existed when, timestomp detection (`$SI` vs `$FN`) | both |
| 5 | `prefetch_parse` | Per-binary execution evidence (run_count, last 8 run times) | A |
| 6 | `usnjrnl_query` | Filesystem mutation log — corroborates MFT, surfaces deletes | both |
| 7 | `registry_query` | Run / RunOnce / IFEO / Services / WMI consumers / Scheduled Tasks | A |
| 8 | `evtx_query` | Security.evtx (4624/4625/4688/7045), System.evtx, Application.evtx | A |
| 9 | `browser_history` | Extracted Chrome/Edge/Firefox browser DBs | B |
| 10 | `ez_parse` | LNK, JumpLists, Amcache, and modern Recycle Bin decoders | both |
| 11 | `plaso_parse` | Legacy EVT, IE index.dat, task, and Recycle Bin timelines | both |
| 12 | `hayabusa_scan` | Sigma rules over the **extracted EVTX directory** (dir-based) | A |
| 13 | `yara_scan` | YARA over extracted yara-target files — **skipped when extraction yields no yara-targets** (see gap note) | B |
| 14 | `vel_collect` (optional) | Additional OS-level artifacts the wrappers don't cover | both |
| 15 | `disk_unmount` | Release the mount (finally-block) | both |

The headless engine runs steps 4-7 **in parallel** across a pool of `findevil-mcp` connections
(`--parallel`, default on; `--workers 2`); records stay serial so the verdict is identical to serial.

> **Coverage gap (yara on disk).** `yara_scan` runs only over files `disk_extract_artifacts`
> classified as yara-targets; on a stock image that can be 0, so yara is skipped. A fallback that
> recursively YARA-scans the whole mount is *possible* but perf-sensitive on large images (a 23GB
> mount) — left as a deliberate follow-up, not bolted on.

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

After memory: if a disk image for the same host is available, **cross-reference** PIDs from `vol_pslist` against `prefetch_parse` run lists. A process running in memory with no Prefetch entry is a strong signal of an unprefetched (likely manual or scripted) execution. This is an **analyst-driven cross-artifact check** the interactive agent performs when both classes are present; the headless engine does not yet auto-emit it as a Finding (a documented depth gap, not an implemented automated Finding — do not claim it as one).

### `.evtx` — single Windows event log

The lightweight case (matches our `--real-evidence` smoke flow).

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `evtx_query` | Parse the log; pull EID histogram | both |
| 3 | `hayabusa_scan` (optional, if a `.evtx` directory is available) | Sigma rule scan | A |

A **single** `.evtx` file gets `evtx_query` only. `hayabusa_scan` is **directory-based** (it walks a
folder), so it runs only when an EVTX *directory* is supplied — e.g. a Velociraptor zip's `Logs/`, or
a mixed case dir with ≥2 logs in one folder. To get Sigma coverage on one log, put it in a directory
and point the run there. (This is a deliberate design choice, not a missing tool.)

### `.pcap` / `.pcapng` / Sysmon-EVTX / Zeek logs — network evidence

What talked to what. The engine runs `investigate_network_artifacts`; each tool fires only when its
artifact class is present.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | `sysmon_network_query` | Sysmon EID 3 network-connection events (needs a Sysmon EVTX) | both |
| 3 | `zeek_summary` | Zeek conn/dns/http summaries (needs Zeek logs) | both |
| 4 | `pcap_triage` | PCAP/PCAPNG triage — can drive Zeek internally for protocol summaries | both |

Pool B leans on outbound endpoints / exfil patterns; Pool A on C2 beaconing.

### Velociraptor `.zip` collection

Triage zips produced by `velociraptor` collection.

| Order | Tool | Purpose | Pool |
|---|---|---|---|
| 1 | `case_open` | SHA-256 + case_id | both |
| 2 | Velociraptor zip extraction | Safely extract supported contained artifacts to the case work dir; reject zip-slip and oversized members | both |
| 3 | Per-artifact re-dispatch | Route each extracted artifact to its type playbook: **memory** → `vol_pslist`/`vol_psscan`/`vol_psxview`/`vol_malfind`+`yara_scan`; **EVTX** → `evtx_query` (+ `hayabusa_scan` on folders with ≥2 logs); **disk** artifacts → `mft_timeline`/`usnjrnl_query`/`prefetch_parse`/`registry_query`; **network** → `sysmon_network_query`/`zeek_summary`/`pcap_triage` | both |

### Mixed case directory (most realistic) — the breadth path

A case dir holding a disk image, a memory image, a Velociraptor zip, and EVTX/PCAP files is how you
exercise the **whole** tool surface in one run. The engine's directory/inventory mode
(`case_open_directory` → `investigate_inventory`) classifies every artifact and dispatches each to its
type playbook above — memory → `vol_*`, disk → mount/extract/parse, evtx → `evtx_query` + hayabusa-on-dirs,
network → sysmon/zeek/pcap, velociraptor → unzip + re-dispatch (now including any **memory** dumps
inside the zip). **A single-file input can only ever trigger that one type's branch — point `/verdict`
at a mixed directory for full breadth.** The supervisor stitches case_ids together via the `case_id`
argument every tool accepts.

### Multi-host fleet (many hosts / many disk images) — the scale path

When the case root holds a `hosts/` and/or `disks/` subfolder (many machines, not one), run a fleet
instead of one host at a time:

```bash
scripts/verdict <case-root> --fleet           # local
scripts/verdict <case-root> --fleet --sift    # SIFT — recommended for disk images
```

This runs each host as its own audit-chained Case, then cross-host correlation (`fleet_correlate`),
then a fleet report (`render_fleet_report`); outputs land in `tmp/fleet-runs/<fleet-id>/`. It is
**resumable** — a host whose run-summary already exists is skipped — so a long fleet can be driven in
one command. How to operate it well:

1. **Validate on one host first.** Run a single representative host end to end (verdict + `manifest_verify.overall=true`) before fanning out, so a pipeline problem surfaces on host 1, not host 7.
2. **SIFT mount-in-place for large images.** Evidence already inside the VM (e.g. a read-only shared folder) is mounted read-only *in place* — pass the in-VM path and skip copy-staging tens of GB per host. VERDICT treats an evidence path that is not on the host but exists in the VM as an in-VM path.
3. **Manage VM space.** Per-host extracts accumulate; on a small VM, clean a finished host's extracted/mount dirs before the next host. Never delete source evidence or another tool's data without operator approval.
4. **Fuse disk + memory for ≥2-class corroboration.** Put a host's disk image **and** its memory image in one folder so they run as a single cross-artifact Case (the memory lane first, disk lane last). This is how an EVTX-only execution/persistence lead reaches the two-artifact-class bar — pairing adds a class, it does not lower the bar.
5. **Close the on-disk YARA gap.** Per the disk coverage-gap note above, set `FIND_EVIL_DISK_YARA_RULES` to a ruleset so `yara_scan` runs over extracted yara-targets; and when a service/driver ImagePath is flagged (e.g. an EID 7045 install), recover and scan that specific file off the mount — the yara-target heuristic may not include it. Do
that analysis with an **audit-chained** tool (`yara_scan` / typed parse) so the file's attributes carry a
`tool_call_id`; raw shell triage (vol/file/sha256sum) is a lead only and will not trace under
`manifest_verify`, so a "2-artifact-class" claim needs **both** classes cited, not one in-chain + one asserted.
6. **Custody stays per host.** Each host has its own `run.manifest.json`; the fleet correlation report is a derivative summary, not a substitute for per-host `manifest_verify`.

See `MEMORY.md` for the interpretation traps that bite at scale (EID 1102 build-residue vs incident
clears, malfind RWX false positives, and truncated-capture `pslist=0`/`malfind=0` that is "not
analyzable," not clean).

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
- **Not exhaustive of DFIR.** It covers what the 32 typed Rust MCP tools can reach, including the allow-listed `plaso_parse`, `vol_run`, `ez_parse`, `mac_triage`, and `cloud_audit` long-tail verbs. If the case needs broad unstructured carving, a parser outside the allow-lists, or interactive packet reconstruction beyond `pcap_triage` / `zeek_summary` / `suricata_eve`, surface that as a gap to the analyst. (Browser history IS covered now — see `browser_history`.)
- **Not a substitute for SOUL.md or AGENTS.md.** Read those first; this file is the operational layer that sits below the epistemic and role-definition layers.
