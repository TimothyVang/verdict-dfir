# Dataset Documentation

**Devpost Required Component #5** — what the agent was tested against, source of data, and what it found.

This document covers every fixture the Find Evil! submission was tested against. All fixtures are either public domain, permissively licensed, or pulled from SANS's own starter case data. None are bundled in the git tree; `scripts/fetch-fixtures.sh` pulls them at CI time.

---

## Primary golden: SANS starter case data

| Attribute | Value |
|---|---|
| Source | SANS Find Evil! official starter case data |
| URL | `https://sansorg.egnyte.com/fl/HhH7crTYT4JK` |
| License | Distributed as hackathon starter data by SANS Institute |
| Content | Sample disk images + memory captures (hackathon-specific) |
| Purpose | **Primary** L3 golden-run fixture — what judges are most likely to test submissions against |
| SHA-256 | *(recorded by `scripts/fetch-fixtures.sh` at first download; see `fixtures/sha256sums.txt`)* |
| Expected findings | *(enumerated in `goldens/sans-starter/expected-findings.json` after first manual walk-through)* |

**Rationale for primary status:** This dataset ships with the hackathon and is what Rob Lee and the judges are most familiar with. Optimizing for it aligns our accuracy metrics with the judging experience.

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

**Rationale:** A submission that only finds evil on evil data is useless. This fixture verifies that the agent distinguishes benign systems from compromised ones — addresses the "hallucination" criticism that Valhuntir explicitly warns about but does not measure.

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
- **Not bundled in Devpost submission zip.** Fixture URLs documented here; judges fetch via `scripts/fetch-fixtures.sh`.
- **Cached in GHA via `actions/cache`** keyed on `fixtures/sha256sums.txt` hash.

---

## Public DFIR benchmark suite (one scenario per artifact class)

Ten verified public datasets (Anna Tchijova's ranked list) onboarded so we can do live
runs against every DFIR artifact class. Each has a ground-truth answer key at
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
| 2 | `nist-data-leakage` | disk (insider exfil) | 🟢 | `DATA_LEAKAGE_URL` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 3 | `nist-hacking-case` | disk (XP) | 🟢 | default cfreds URL (already wired) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 71% |
| 4 | `alihadi-09-encrypt` | disk (crypto) | 🟡 | `ALIHADI09_URL` | **INDETERMINATE** (false-positive control) | 50% |
| 5 | `alihadi-01-webserver` | disk + memory | 🟡 | `ALIHADI01_URL` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 6 | `dfrws-2008-linux` | memory+disk+network | 🟡 | git clone | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |
| 7 | `m57-jean` | disk/email | 🟠 | `M57_JEAN_URL` (default digitalcorpora) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 60% |
| 8 | `alihadi-07-sysinternals` | disk (E01) | 🟠 | `ALIHADI07_URL` | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |
| 9 | `dfrws-2011-android` | mobile/disk | 🔴 | `DFRWS2011_URL` | UNKNOWN (stub) | 40% |
| 10 | `volatility-cridex` | memory | 🔴 (sourcing) | `CRIDEX_URL` (canonical link dead) | SUSPICIOUS (legacy golden label: CONFIRMED_EVIL) | 50% |

**Notable cases**
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
- **Disk classes need `--sift`.** Locally, raw `.dd/.E01` runs return `INDETERMINATE`
  (custody-only) because host-side disk-content tooling is a known gap; real disk verdicts
  come from `scripts/verdict --sift`. `INDETERMINATE` is an honest PASS of the live-test
  gate but will score below the recall target until run under SIFT.

### Run results (recall against golden)

*(Populated as each obtainable dataset is run + scored. No fabricated numbers — gated/
unfetchable-on-host datasets are marked "staged, run pending evidence".)*

| Case id | Run? | Verdict | Recall | Notes |
|---|---|---|---|---|
| `nitroba` | yes (local, tshark) | INDETERMINATE | **5/5 (100%) — PASS** (bar=80%) | Network-playbook gaps fixed (see below). Surfaces all five: anonymous-email contact, source host (192.168.15.4), Gmail-cookie attribution, authenticated Facebook login, and the send-vs-browsing timeline correlation. |
| `nist-data-leakage` | staged, run pending evidence | — | — | needs `--sift` (disk) |
| `nist-hacking-case` | yes (committed run) | SUSPICIOUS | 5/14 (36%) | coverage gap (not custody). Up from 1/14 after Gap-5 disk-artifact emitters: now matches nhc-004 (hacking-tool files in Program Files/Desktop, from the MFT), nhc-005 (prefetch execution), nhc-010 (suspiciously-named SAM account "Mr. Evil"), nhc-011 (OpenSaveMRU recently-opened installers), nhc-007 (NTUSER shellbag navigation to a `\\4.220.254\Temp` staging share + tool folders). Still below the 71% bar — the remaining nine: nhc-002 (USBSTOR absent in this image), nhc-001 (ACMru absent), and nhc-003 (email carving), nhc-006 (IE index.dat), nhc-008/009 (LNK + Recycler\INFO2 — not yet pulled by `disk_extract_artifacts`), nhc-012 (XP `.evt`, not EVTX), nhc-013 (thumbcache), nhc-014 (named-pipe enum) are not yet parsed. |
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

*(Populated incrementally as Week 5 acceptance criteria (AC-01 through AC-10) are verified against each fixture. Each subdirectory contains the full agent run manifest and audit.jsonl (post-A5 signed manifest; no OTS receipt).)*

```
goldens/
├── sans-starter/
│   ├── expected-findings.json    (ground truth — populated from manual walkthrough)
│   ├── run-manifest.json         (cryptographically-signed)
│   ├── audit.jsonl               (hash-chained audit log)
│   └── run.manifest.json         (post-A5 signed manifest; no OTS receipt)
├── nist-hacking-case/
│   └── …same layout…
├── otrf-apt3-mordor/
│   └── …same layout…
├── volatility-cridex/
│   └── …same layout…
└── synthetic-benign/
    └── …same layout (expected empty findings)…
```

Each `run.manifest.json` is verifiable offline by any third party — under Amendment A2 the entry points are the `verify_manifest` library function (`from findevil_agent.crypto.manifest import verify_manifest`) or the `manifest_verify` MCP tool. The pre-A2 `find-evil verify <manifest>` CLI was dropped along with `findevil_agent/cli.py`. See `docs/cryptographic-attestation.md` "How a third party verifies offline" for the working recipe.

---

## Licensing summary

| Fixture | License | Redistribute? |
|---|---|---|
| SANS starter data | Hackathon starter | No (fetch from SANS) |
| NIST CFReDS | Public domain | Yes, by URL reference |
| OTRF Security-Datasets | MIT | Yes, by URL reference (attribution via fetch script) |
| Volatility samples | CC-BY | Yes, by URL reference (attribution via fetch script) |
| Synthetic benign | MIT (our script) | Yes |
| DFIR-Metric | Permissive (verified Week 6) | Yes, by URL reference |
| DFRWS Rodeo | Public domain | Yes |
| Digital Corpora (Nitroba, M57-Jean) | Freely redistributable (research/education) | Yes, by URL reference |
| NIST Data Leakage | Public domain (17 USC 105) | Yes, by URL reference |
| Ali Hadi challenges (#1/#7/#9) | Free for research/education (answers gated) | By URL reference |
| DFRWS 2008/2011 | Public for research/education | By URL reference |

None of these licenses contaminate our MIT-licensed submission repo because we redistribute only URLs and SHA-256 hashes, not the fixtures themselves.
