# Dataset Documentation

What the agent was tested against, the source of each dataset, and what it found.

This document covers every fixture VERDICT was tested against. All fixtures are either public domain, permissively licensed, or pulled from SANS's own starter case data. None are bundled in the git tree; `scripts/fetch-fixtures.sh` pulls them at CI time.

---

## Primary golden: SANS starter case data

| Attribute | Value |
|---|---|
| Source | SANS official starter case data |
| URL | `https://sansorg.egnyte.com/fl/HhH7crTYT4JK` |
| License | Distributed as starter case data by SANS Institute |
| Content | Sample disk images + memory captures |
| Purpose | Intended **primary** L3 golden-run fixture — the primary reference golden fixture. Still a pending stub: `goldens/sans-starter/expected-findings.json` has no findings enumerated and has never been run or scored. |
| SHA-256 | Required as `SANS_STARTER_SHA256` when `SANS_STARTER_URL` is set; recorded in `fixtures/sha256sums.txt` |
| Expected findings | *(enumerated in `goldens/sans-starter/expected-findings.json` after first manual walk-through)* |

**Rationale for primary status:** This dataset is published by SANS and is widely familiar to working DFIR practitioners. Optimizing for it aligns our accuracy metrics with a recognized reference baseline.

---

## Secondary: NIST CFReDS Hacking Case

| Attribute | Value |
|---|---|
| Source | NIST Computer Forensics Reference Data Sets |
| URL | `https://cfreds.nist.gov/all/NIST/HackingCase` |
| License | Public domain (17 USC 105 — U.S. government works are not copyrightable) |
| Content | EnCase E01 (~4.5 GB compressed / ~4.8 GB raw NTFS); Windows host evidence |
| Purpose | Canonical DFIR benchmark case; industry-standard ground truth |
| SHA-256 | *(recorded on first pull)* |
| Expected findings | **14 canonical findings** — enumerated in `goldens/nist-hacking-case/expected-findings.json` |
| Expected VERDICT top-line | `SUSPICIOUS` when corroborated; older goldens may still use `CONFIRMED_EVIL` as a scoring label |

**Rationale:** NIST's authority makes this a standard reference. Multiple DFIR tools publish accuracy against it, so our DFIR-Metric score is directly comparable to any competitor.

### Lightweight extract — single Security.evtx for fast smoke

For developer-laptop iteration we don't always want the 4.5 GB E01. `scripts/fetch-nist-fixture.sh` pulls **one small Security.evtx** at `fixtures/single-evtx/Security.evtx`, used by `python scripts/rust-mcp-smoke.py --real-evidence`. Source URL is intentionally NOT hardcoded — set via env vars so operators can point at a vetted mirror without an upstream URL change breaking CI:

```sh
NIST_FIXTURE_URL=https://example.org/path/to/Security.evtx \
NIST_FIXTURE_SHA256=<64-hex-digits> \
bash scripts/fetch-nist-fixture.sh
```

Vetted candidate sources (any one is sufficient):
- An OTRF Security-Datasets sample with a single standalone `.evtx` payload (the `datasets/atomic/windows/credential_access` and `datasets/atomic/windows/defense_evasion` subtrees ship sub-MB EVTX files).
- An internal team mirror of CFReDS Hacking Case `Security.evtx` extracted via The Sleuth Kit's `fls`+`icat` from `SCHARDT.001`.
- A small synthetic EVTX produced by `wevtutil epl` on a clean Win10 host.

The fetch script is deliberately strict: SHA pin enforced when supplied, magic-byte sanity check (`ElfFile\0`) on every download, atomic rename, provenance recorded at `fixtures/single-evtx/PROVENANCE.txt`. The smoke harness skips silently when the fixture is absent so offline runs still pass.

---

## Secondary: OTRF Security-Datasets (formerly Mordor)

| Attribute | Value |
|---|---|
| Source | Open Threat Research Forge |
| URL | `https://github.com/OTRF/Security-Datasets` |
| License | MIT License |
| Content | EVTX / JSON / Zeek replay datasets for specific attack scenarios (APT3, APT29, Empire, Covenant, Cobalt Strike) |
| Purpose | Behavior-specific validation; exercises Hayabusa Sigma rules and event-correlation paths |
| SHA-256 | *(per-dataset, recorded on pull)* |
| Expected findings | Per-dataset; scenario-specific (e.g., APT3-Mordor expects lateral movement T1021.006) |
| Verdict | Varies per dataset |

**Rationale:** Each dataset isolates a named attack pattern, so Hayabusa rule coverage can be validated precisely. Used in L2 smoke tests (non-blocking advisory) and L3 matrix runs.

---

## Secondary: Volatility Foundation Memory Samples

| Attribute | Value |
|---|---|
| Source | Volatility Foundation |
| URL | `https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples` |
| License | Creative Commons Attribution (CC-BY) — redistribute with attribution |
| Content | Known-good + known-malicious memory dumps (Cridex, Stuxnet, SpyEye samples, etc.) |
| Purpose | Volatility3 plugin validation; exercises `vol_pslist`, `vol_malfind`, cross-artifact memory→disk correlation |
| SHA-256 | *(per-sample)* |
| Expected findings | Per-sample (e.g., Cridex: injected PID list, malfind RWX regions) |
| Verdict | Varies per sample |

**Rationale:** Memory-specific ground truth. Windows profile auto-detection tested here before L3 runs.

---

## Synthetic benign baseline

| Attribute | Value |
|---|---|
| Source | Internal, synthetic (generated by the build process) |
| URL | *(not applicable — produced at CI time)* |
| License | MIT (our own generation script) |
| Content | Clean Windows 10 install, patched, no tradecraft, representative baseline activity only |
| Purpose | Negative control — the agent must NOT produce false-positive findings |
| SHA-256 | *(per-generation)* |
| Expected findings | **0** (verdict: `NO_EVIL`) |
| Verdict | `NO_EVIL` |

**Rationale:** A tool that only finds evil on evil data is useless. This fixture verifies that the agent distinguishes benign systems from compromised ones — addresses the "hallucination" criticism that Valhuntir explicitly warns about but does not measure.

---

## Synthetic decoy (planted bait)

| Attribute | Value |
|---|---|
| Source | Internal, synthetic (generated by the build process) |
| URL | *(not applicable — produced at CI time by `scripts/fetch-fixtures.sh` §5b)* |
| License | MIT (our own generation script) |
| Content | Benign artifacts deliberately named/worded to look malicious: a plain-text file named `mimikatz.exe`, a `cobalt-strike-notes.txt`, a `decoy-dns.log` showing a lookup to a known sinkhole, and a `passwords.zip` of the user's own non-secret notes. No real malware, no malicious behaviour. |
| Purpose | Precision control — a correct run must surface the benign lookalikes WITHOUT escalating. Naming the mimicked malware, calling the sinkhole lookup C2, or calling the archive exfil is planted-bait false positive. |
| SHA-256 | *(per-generation; content is fixed so each file's hash is deterministic and pinnable in `fixtures/sha256sums.txt`)* |
| Expected findings | **0** (verdict: `NO_EVIL` or honest `INDETERMINATE`) |
| Verdict | `NO_EVIL` |

**Rationale:** synthetic-benign measures the false-positive *floor* on a clean
system; synthetic-decoy measures it under *adversarial naming*, where the names
themselves bait a hallucination. The golden
(`goldens/synthetic-decoy/expected-findings.json`) is closed-world
(`exhaustive: true`) and carries `known_negatives` describing each benign
lookalike plus a `named_claim_denylist` of the malware the decoys mimic
(`mimikatz`, `cobalt strike`, …). `scripts/score-recall.py` scores any decoy
escalation as `fp_planted > 0` and FAILS the run — a benign empty/NO_EVIL run
scores `fp_planted=0` PASS.

---

## Tiny regression fixture matrix

These are source-controlled smoke fixtures, not bundled evidence images. They keep
the final automation gates runnable on a laptop while larger public datasets stay
ignored under `fixtures/` and `goldens/`.

Run the matrix with:

```sh
python scripts/verdict-policy-smoke.py
```

| Scenario | Tiny fixture or smoke input | Locked behavior |
|---|---|---|
| Benign | Synthetic benign EVTX rows in `scripts/verdict-policy-smoke.py` | Parsed benign rows produce zero Findings and scoped `NO_EVIL`. |
| Planted decoy | `synthetic-decoy` fixture: benign artifacts with malicious-LOOKING names (`mimikatz.exe` text file, sinkhole DNS log, `passwords.zip`) | Decoys are surfaced as benign without escalation; scored `fp_planted=0` PASS, any escalation FAILS via `known_negatives` + `named_claim_denylist`. |
| EVTX-only | Synthetic Security EID 4698 scheduled-task row | Suspicious task creation emits one cited HYPOTHESIS Finding and remains `INDETERMINATE`. |
| Memory DKOM | Synthetic `pslist` / `psscan` divergence | Process-view divergence requires `psxview` follow-up and remains evidence-scoped. |
| Memory injection | Synthetic malfind RWX/MZ observable | Injection triage stays HYPOTHESIS and cites the malfind tool call. |
| Custody-only disk | Synthetic E01 `case_open`-only observable | Disk custody registration alone stays `INDETERMINATE` and does not mark disk contents touched. |
| Extracted-disk persistence | Synthetic extracted Prefetch plus Registry artifacts | Extracted disk artifacts dispatch to `prefetch_parse` and `registry_query`. |
| Network-only | Synthetic PCAP-only execution-overclaim QA packet | Report QA blocks network-only execution wording. |
| Velociraptor zip | Synthetic Velociraptor zip member inventory with contained Prefetch | Safe contained artifacts extract and dispatch to typed parsers. |
| Mixed full-case | Synthetic directory containing memory, EVTX, raw disk, and extracted disk artifacts | Mixed inventories mark supplied classes touched and can produce scoped `NO_EVIL` only after substantive parsers run. |

The matrix deliberately avoids fake production evidence and fake malicious demo
findings. It verifies policy behavior, dispatch coverage, and overclaim blockers
using tiny synthetic inputs; real-evidence accuracy still belongs to the public
goldens above and larger ignored fixtures.

---

## DFIR-Metric benchmark suite

| Attribute | Value |
|---|---|
| Source | DFIR-Metric research project |
| URL | `https://github.com/DFIR-Metric` |
| Paper | `https://arxiv.org/abs/2505.19973` |
| License | *(per repo — permissive, verified at Week 6)* |
| Content | 700 MCQs + 150 CTF tasks + 500 NIST cases, designed to evaluate LLMs on DFIR |
| Purpose | Standardized accuracy metric; external validation of agent quality |
| SHA-256 | *(per benchmark release)* |
| Expected findings | *(per case in the benchmark — documented by DFIR-Metric, not by us)* |
| Verdict | Scored per DFIR-Metric rubric |

**Rationale:** The only public DFIR-specific benchmark. Publishing our score here (via the M1 leaderboard) differentiates us from Valhuntir, which explicitly declines to publish any accuracy metric.

---

## DFRWS Rodeo and USB challenges

| Attribute | Value |
|---|---|
| Source | Digital Forensic Research Workshop, hosted on NIST CFReDS |
| URL | `https://cfreds.nist.gov/` |
| License | Public domain |
| Content | Small USB DD images (~500 MB each) with deliberate artifacts |
| Purpose | Fast smoke tests in L1/L2 (images small enough to cache in CI) |
| SHA-256 | *(per-image)* |
| Expected findings | Per-challenge (documented per-case) |
| Verdict | Varies |

**Rationale:** Small size + public domain = ideal for L1/L2 rapid iteration where full SIFT VM isn't needed.

---

## Fixture caching and integrity

All fixtures are fetched by `scripts/fetch-fixtures.sh` (Spec #3 Task 10). On first pull, each file's SHA-256 is computed and recorded in `fixtures/sha256sums.txt`. Subsequent runs verify the checksum; mismatches abort with clear error. This prevents a fixture swap from silently altering benchmark scores.

Storage policy:
- **Never committed to git.** `.gitignore` excludes `*.E01`, `*.ova`, `*.raw`, `*.mem`, `*.dd`, `*.aff`, `*.aff4`.
- **Not bundled in the release archive.** Fixture URLs documented here; operators fetch via `scripts/fetch-fixtures.sh`.
- **Cached in GHA via `actions/cache`** keyed on `fixtures/sha256sums.txt` hash.

### Operator-hosted artifact mirror

A view-only Google Drive folder is available as an operator-hosted convenience mirror for larger DFIR artifacts used during local VERDICT testing:

<https://drive.google.com/drive/folders/1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv?usp=drive_link>

It is organized by artifact class:

- `disk-images/`
- `memory-images/`
- `network-captures/`
- `windows-event-logs/`
- `mixed-cases/`
- `security-datasets/`
- `synthetic-controls/`
- `derived-artifacts/`
- `manifests/`

Browser downloads work from the Drive link. For rclone, Google Drive's backend still requires each downloader to use their own authenticated Google Drive remote, even for a view-only link-shared folder:

```sh
rclone config create gdrive drive scope drive
rclone copy --drive-root-folder-id 1j4nPm3vjAcRwVdKOauIVc8yurxoADhOv gdrive: ./verdict-dfir-artifacts --progress
scripts/verdict ./verdict-dfir-artifacts/network-captures/nitroba/nitroba.pcap
```

This mirror is not a GitHub release asset and is not the source of truth for licensing or provenance. Honor each upstream dataset's terms and use the canonical source URLs above when redistribution terms require it.

---

## Public DFIR benchmark suite (one scenario per artifact class)

Public and candidate benchmark datasets are onboarded so we can do live
runs against every DFIR artifact class. Each has an answer-key file at
`goldens/<case-id>/expected-findings.json`, is fetched by `scripts/fetch-fixtures.sh`
(§6), and is scored offline by `scripts/score-recall.py` (recall vs `min_recall_percent`
plus honest verdict consistency). Run + score loop:

```sh
bash scripts/fetch-fixtures.sh                       # stage evidence (env vars below)
bash scripts/verdict fixtures/<case-id>/<evidence>   # or --sift for disk classes
python scripts/score-recall.py tmp/auto-runs/<case-id>   # recall vs golden
```

**Tier** is the thread's data-quality ranking, recorded as a *caveat only* — per project
decision it is NOT a scoring gate (training-data contamination is not modeled). Tiers:
🟢 score against (trustworthy) · 🟡 build/test, score with care (answers gated) ·
🟠 practice only (solutions public — likely in model training data) · 🔴 not ready.

| # | Case id | Class | Tier | Fetch | Expected outcome | Recall target |
|---|---|---|---|---|---|---|
| 1 | `nitroba` | network (pcap) | 🟢 | `NITROBA_URL` (default digitalcorpora) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 80% |
| 2 | `nist-data-leakage` | disk (insider exfil) | 🟢 | `DATA_LEAKAGE_URL` + `DATA_LEAKAGE_SHA256` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 3 | `nist-hacking-case` | disk (XP) | 🟢 | default cfreds URL (already wired) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 71% |
| 4 | `otrf-apt3-mordor` | Windows logs (EVTX/Sysmon/JSON) | 🟢 | sparse clone from OTRF Security-Datasets | SUSPICIOUS | 60% |
| 5 | `memlabs-lab1` | Windows memory | 🟡 | `MEMLABS_LAB1_URL` + `MEMLABS_LAB1_SHA256` (extracted memory dump direct URL or `file://`) | SUSPICIOUS | 67% |
| 6 | `memlabs-lab2` | Windows memory | 🟡 | `MEMLABS_LAB2_URL` + `MEMLABS_LAB2_SHA256` (extracted memory dump direct URL or `file://`) | SUSPICIOUS | 67% |
| 7 | `memlabs-lab3` | Windows memory | 🟡 | `MEMLABS_LAB3_URL` + `MEMLABS_LAB3_SHA256` (extracted memory dump direct URL or `file://`) | SUSPICIOUS | 67% |
| 8 | `digitalcorpora-lonewolf` | Windows disk + memory | 🟡 | `LONEWOLF_URL` + `LONEWOLF_SHA256` (large full Digital Corpora bundle) | INDETERMINATE candidate | 0% |
| 9 | `alihadi-09-encrypt` | disk (crypto) | 🟡 | `ALIHADI09_URL` | **INDETERMINATE** (false-positive control) | 50% |
| 10 | `alihadi-01-webserver` | disk + memory | 🟡 | `ALIHADI01_URL` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 11 | `dfrws-2008-linux` | memory+disk+network | 🟡 | pinned git clone (`DFRWS2008_REF`) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |
| 12 | `m57-jean` | disk/email | 🟠 | `M57_JEAN_URL` (default digitalcorpora) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 13 | `alihadi-07-sysinternals` | disk (E01) | 🟠 | `ALIHADI07_URL` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |
| 14 | `dfrws-2011-android` | mobile/disk | 🔴 | `DFRWS2011_URL` | UNKNOWN (stub) | 40% |
| 15 | `volatility-cridex` | memory | 🔴 (sourcing) | `CRIDEX_URL` (canonical link dead) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |

**Notable cases**
- **Windows-focused golden expansion.** The Windows-heavy lane now covers logs
  (`otrf-apt3-mordor`), memory (`memlabs-lab1` through `memlabs-lab3`), and combined
  disk+memory (`digitalcorpora-lonewolf`) in addition to the existing NIST and Ali Hadi
  disk images. This is intentionally metadata/answer-key only; raw evidence remains under
  `fixtures/` when staged locally and is never committed.
- **`alihadi-09-encrypt` is the false-positive control.** Encryption tooling is present
  but its presence is not proof of malice. The golden verdict is `INDETERMINATE`; a run
  that escalates to `SUSPICIOUS` (or the legacy scoring label `CONFIRMED_EVIL`) FAILS the asymmetric verdict-match check
  in `score-recall.py`. Findings are intentionally `INFERRED`/`HYPOTHESIS`.
- **`dfrws-2011-android` TRAP:** the upstream README hashes are labeled MD5 but are
  actually **SHA1** — do not chase a phantom mismatch. Evidence is on a personal Dropbox
  that may vanish; mirror and recompute MD5+SHA256 before relying on it. The golden is a
  stub (verdict `UNKNOWN`) pending a verified mirror + manual walkthrough.
- **`volatility-cridex` sourcing is dead:** the canonical
  `downloads.volatilityfoundation.org` link no longer serves the image. Set `CRIDEX_URL`
  to a verified mirror (a SANS-hosted copy with published hashes was requested in the
  thread). The IOCs themselves are canonical (`reader_sl.exe` ← `explorer.exe`, malfind
  injection, C2).
- **`otrf-apt3-mordor` is the strongest Windows log expansion.** It comes from OTRF
  Security-Datasets' compound Windows APT3 telemetry and MITRE ATT&CK Evaluations Round 1
  emulation material. `scripts/fetch-fixtures.sh` sparse-clones the compound APT3 tree plus
  focused atomic Windows credential-access, defense-evasion, lateral-movement, and
  persistence telemetry. This is a log-correlation golden, not a disk/memory image.
- **`memlabs-lab1` through `memlabs-lab3` are Windows memory CTF labs.** They are useful for
  Volatility coverage and extraction behavior, but the committed goldens intentionally record
  flag counts/objectives and source hashes, not the actual flag values. The upstream downloads
  are Mega/browser-oriented, so fetch is env-gated via `MEMLABS_LAB{1,2,3}_URL` and requires
  the matching `MEMLABS_LAB{1,2,3}_SHA256` to point at a vetted direct mirror or `file://` URL
  for the extracted memory dump, not the compressed archive. The upstream archive MD5 remains
  in each golden for provenance; the fetch helper verifies the staged memory dump MD5 before L3.
- **`digitalcorpora-lonewolf` is a large Windows disk+memory candidate.** Digital Corpora
  publishes the E01 segments, `memdump.mem`, `pagefile.sys`, FTK log, and commercial forensic
  outputs, but the teacher guide is password-protected/faculty-gated. Fetch is opt-in and requires
  `LONEWOLF_SHA256`; until an authorized guide is available, the committed file records required
  artifacts and non-scored lead hypotheses instead of reportable expected Findings.
- **Disk classes need mount/extract prerequisites.** Local raw `.dd/.E01` runs can parse supported
  artifacts when Sleuth Kit/libewf are present; otherwise they return `INDETERMINATE`
  (custody-only). SIFT remains the recommended parity path. `INDETERMINATE` is an honest PASS of
  the live-test gate when coverage is limited, but it will score below the recall target until
  supported artifacts are parsed.

### Candidate public corpus backlog

These URL references are backlog candidates only. They are not scored until a
specific fixture is staged with a verified hash and a committed
`goldens/<case-id>/expected-findings.json` answer key.

Status definitions:
- **Scoreable golden candidate**: likely usable for public scoring after fixture pinning and manual answer-key review.
- **Needs walkthrough**: public data needs an analyst walkthrough before promotion or rejection.
- **Practice**: useful for analyst/agent practice, but not a headline benchmark because solutions, flags, or walkthroughs are public.
- **Parser validation**: useful for ingestion and parser coverage, not incident-outcome recall.

| Candidate | Artifact class | Status | URL reference |
|---|---|---|---|
| DFRWS 2023 Troubled Elevator | multisource challenge | Scoreable golden candidate | [DFRWS forensic challenges](https://dfrws.org/forensic-challenges/) |
| Digital Corpora m57-patents | disk / email | Practice | [Digital Corpora scenarios](https://digitalcorpora.org/corpora/scenarios/) |
| Digital Corpora 2012-ngdc | disk / mixed | Needs walkthrough | [Digital Corpora scenarios](https://digitalcorpora.org/corpora/scenarios/) |
| Digital Corpora 2019-narcos | disk / mobile / mixed | Needs walkthrough | [Digital Corpora scenarios](https://digitalcorpora.org/corpora/scenarios/) |
| Digital Corpora 2019-owl | disk / mixed | Needs walkthrough | [Digital Corpora scenarios](https://digitalcorpora.org/corpora/scenarios/) |
| Digital Corpora 2019-tuck | disk / mixed | Needs walkthrough | [Digital Corpora scenarios](https://digitalcorpora.org/corpora/scenarios/) |
| Digital Corpora Android 7-13 / iOS 13 | mobile | Parser validation | [Digital Corpora mobile](https://digitalcorpora.org/corpora/mobile/) |
| Digital Corpora NPS disk images | disk | Parser validation | [Digital Corpora disk images](https://digitalcorpora.org/corpora/disk-images/) |
| Digital Corpora SQLite Forensic Corpus | SQLite | Parser validation | [Digital Corpora corpora](https://digitalcorpora.org/corpora/) |
| Malware-Traffic-Analysis.net PCAP exercises | network (pcap) | Practice | [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/) |
| Netresec public PCAP index | network (pcap) | Parser validation | [Netresec PCAP files](https://www.netresec.com/?page=PcapFiles) |
| DFRWS 2017/2018/2021 IoT or multisource challenges | IoT / disk / network / mixed | Needs walkthrough | [DFRWS forensic challenges](https://dfrws.org/forensic-challenges/) |
| Volatility memory samples beyond Cridex | memory | Parser validation | [Volatility Memory Samples](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples) |
| MemLabs Labs 4-6 | memory | Practice | [MemLabs](https://github.com/stuxnet999/MemLabs) |

### Run results (recall against golden)

*(Populated as each obtainable dataset is run + scored. No fabricated numbers — gated/
unfetchable-on-host datasets are marked "staged, run pending evidence".)*

| Case id | Run? | Verdict | Recall | Notes |
|---|---|---|---|---|
| `nitroba` | yes (local, tshark) | INDETERMINATE | **5/5 (100%) — PASS** (bar=80%; committed under `docs/sample-run/nitroba`, custody-verified) | Network-playbook gaps fixed (see below). Surfaces all five: anonymous-email contact, source host (192.168.15.4), Gmail-cookie attribution, authenticated Facebook login, and the send-vs-browsing timeline correlation. |
| `otrf-apt3-mordor` | staged, run pending evidence | — | — | strongest Windows EVTX/Sysmon/JSON candidate; sparse clone only, no raw evidence committed |
| `memlabs-lab1` | staged, run pending evidence | — | — | Windows memory CTF; requires extracted memory dump URL or local file URL |
| `memlabs-lab2` | staged, run pending evidence | — | — | Windows memory CTF; requires extracted memory dump URL or local file URL |
| `memlabs-lab3` | staged, run pending evidence | — | — | Windows memory CTF; requires extracted memory dump URL or local file URL |
| `digitalcorpora-lonewolf` | staged, run pending evidence | — | — | large Windows disk+memory scenario; teacher guide gated |
| `nist-data-leakage` | staged, run pending evidence | — | — | needs `--sift` (disk) |
| `nist-hacking-case` | yes (measured 2026-07-01, `benchmark/RESULTS.md`) | SUSPICIOUS | 10/14 (71%) — passes at floor | coverage gap (not custody); reproduces at 10/14 across repeat runs from `evidence/SCHARDT.dd`. Matches nhc-001 (ACMru search history), nhc-004 (hacking-tool files in the MFT), nhc-005 (prefetch execution), nhc-006 (IE internet history), nhc-007 (shellbag removable-media navigation), nhc-008 (LNK removable-media traces), nhc-009 (Recycle Bin staging), nhc-010 (suspiciously-named SAM account), nhc-011 (OpenSaveMRU installers), nhc-014 (service/named-pipe recon). The four unmatched: nhc-002 (USB insertion history — `USBSTOR` queried but empty on this image), nhc-003 (recovered deleted email — carve gap), nhc-012 (logon `.evt` — the golden's `SecEvent.Evt` is empty, unsatisfiable), nhc-013 (thumbcache — no `Thumbs.db` on this image). |
| `alihadi-09-encrypt` | staged, run pending evidence | — | — | false-positive control; expect INDETERMINATE |
| `alihadi-01-webserver` | staged, run pending evidence | — | — | disk+memory correlation |
| `dfrws-2008-linux` | staged, run pending evidence | — | — | Linux memory+disk+network |
| `m57-jean` | staged, run pending evidence | — | — | practice only |
| `alihadi-07-sysinternals` | staged, run pending evidence | — | — | practice only |
| `dfrws-2011-android` | not ready | — | — | source unreliable; golden is a stub |
| `volatility-cridex` | staged, run pending evidence | — | — | source mirror needed |

### Network-playbook fix (driven by the Nitroba false negative)

The first Nitroba run returned `NO_EVIL` with 0 findings. Root cause was three
compounding bugs, now fixed:

1. **Packet cap.** `pcap_triage` read only the first 10,000 of 83,153 packets; the
   harassment traffic sits at packets ~79,800–83,100. Raised the cap
   (`services/mcp/src/tools/pcap_triage.rs`) and the engine call
   (`scripts/find_evil_auto.py`) to read the whole capture.
2. **Truncated-pcap intolerance.** Reading to the end hit a truncated final packet;
   tshark exits non-zero on that but still emits every readable packet first. The
   tool now triages the packets it got instead of discarding all output when stdout
   is non-empty.
3. **No anonymous-email recognition + judge over-collapse.** Added extraction of HTTP
   requests (src→host, method, cookie) plus an anonymous/disposable/self-destruct
   email-service host category, cookie-based attribution for both webmail and
   social-media logins, and a send-vs-browsing timeline correlation (per-request
   timestamps added to `pcap_triage`) (`scripts/find_evil_auto.py`). The judge's
   `_group_key` collapsed *all* findings
   from one tool call into one (it keyed on `(tool_call_id, artifact_path)` despite a
   docstring claiming otherwise); it now keys on the claim
   (`services/agent/findevil_agent/judge.py`), so a single `pcap_triage` call can yield
   multiple distinct findings.

The recall scorer's matcher was also hardened (`scripts/score-recall.py`): from
symmetric Jaccard to expected-coverage (recall asks whether the run *surfaced* each
ground-truth claim, so a verbose-but-correct finding should match a concise expected
one), then to **maximum bipartite matching** with a coverage floor of 0.5 and no
MITRE-technique shortcut. This enforces a 1:1 assignment (one run finding can't
satisfy two claims), requires the claim's *distinctive* tokens rather than generic
DFIR vocabulary, and finds the optimal assignment rather than a greedy one — so the
recall count can neither be inflated by a single broad finding nor under-counted by
match order. Controls were re-validated (synthetic-benign PASS, alihadi-09
over-confident FAIL, nist-hacking-case partial still below target).

---

## Findings corpus (what the agent found)

*(Populated incrementally as fixtures are run + scored. The public release keeps only small answer keys and evidence summaries; raw case outputs stay local.)*

```
goldens/
├── sans-starter/
│   └── expected-findings.json    (ground truth / answer key)
├── nist-hacking-case/
│   └── expected-findings.json
├── otrf-apt3-mordor/
│   └── expected-findings.json
├── memlabs-lab1/
│   └── expected-findings.json
├── memlabs-lab2/
│   └── expected-findings.json
├── memlabs-lab3/
│   └── expected-findings.json
├── digitalcorpora-lonewolf/
│   └── expected-findings.json
├── volatility-cridex/
│   └── expected-findings.json
├── synthetic-benign/
│   └── expected-findings.json    (expected empty findings)
└── synthetic-decoy/
    └── expected-findings.json    (planted bait: known_negatives + named_claim_denylist)
```

Completed case outputs are generated locally under `tmp/auto-runs/<case-id>/` and are intentionally not shipped. Each generated `run.manifest.json` is verifiable offline by any third party — the entry points are the `verify_manifest` library function (`from findevil_agent.crypto.manifest import verify_manifest`) or the `manifest_verify` MCP tool. The pre-A2 `find-evil verify <manifest>` CLI was dropped along with `findevil_agent/cli.py`. See `docs/cryptographic-attestation.md` "How a third party verifies offline" for the working recipe.

---

## Licensing summary

| Fixture | License | Redistribute? |
|---|---|---|
| SANS starter data | SANS starter case data | No (fetch from SANS) |
| NIST CFReDS | Public domain | Yes, by URL reference |
| OTRF Security-Datasets | MIT | Yes, by URL reference (attribution via fetch script) |
| Volatility samples | CC-BY | Yes, by URL reference (attribution via fetch script) |
| Synthetic benign | MIT (our script) | Yes |
| Synthetic decoy | MIT (our script) | Yes |
| DFIR-Metric | Permissive (verified Week 6) | Yes, by URL reference |
| DFRWS Rodeo | Public domain | Yes |
| Digital Corpora (Nitroba, M57-Jean) | Freely redistributable (research/education) | Yes, by URL reference |
| NIST Data Leakage | Public domain (17 USC 105) | Yes, by URL reference |
| Ali Hadi challenges (#1/#7/#9) | Free for research/education (answers gated) | By URL reference |
| DFRWS 2008/2011 | Public for research/education | By URL reference |

None of these licenses contaminate our Apache-2.0 licensed release repo because we redistribute only URLs and SHA-256 hashes, not the fixtures themselves.
