# Evidence Intake — staging conventions

> **Status: ACTIVE.** How to stage Observables for a Case: where evidence lives, how to
> fetch public test data, which file types map to which PLAYBOOK tool sequence, and the
> read-only + SHA-256-at-`case_open` custody guarantee.

VERDICT investigates whatever you point it at. The fastest path is to drop a file (or a
mixed case folder) into `evidence/` and run `scripts/verdict`. This doc covers the
conventions that keep that intake clean, reproducible, and forensically sound.

---

## 1. The `evidence/` directory

`evidence/` is the **default drop location** for a local-host Case. It ships in the repo
(its `README.md` + `.gitkeep` are tracked so the convention travels), but **its contents
never enter git** — the `.gitignore` rule is:

```
/evidence/*
!/evidence/README.md
!/evidence/.gitkeep
```

So every memory image, disk image, EVTX log, PCAP, or case folder you stage there is
ignored by git. Evidence is never committed.

How the path is resolved (precedence, from `scripts/find_evil_auto.py`):

1. An explicit path you pass: `scripts/verdict <path>`
2. `$FINDEVIL_EVIDENCE_ROOT` if that environment variable is set
3. Otherwise this repo's `evidence/` directory

If you rely on the default and the directory holds only `README.md` / `.gitkeep`, the
engine prints a clear error telling you to drop evidence in or pass a path — it does not
silently produce a `NO_EVIL`.

### `--watch`: drop-and-go

`scripts/verdict --watch` blocks until something lands in `evidence/`, then investigates
it. The watcher is **debounced** so it doesn't fire on a half-copied file: it polls the
newest entry's size (recursive `du -sb` for a directory, `stat -c%s` for a file) once a
second and only proceeds when the size stops growing and is non-zero. It ignores
`README.md` and `.gitkeep`. A dropped directory is kept as the entry itself (the watcher
does not expand it), so a mixed case folder is investigated as one unit.

```bash
scripts/verdict --watch            # wait for a fresh drop into evidence/
scripts/verdict                    # no path + no --watch: use the NEWEST file already in evidence/
scripts/verdict evidence/case-42/  # or just point at a path explicitly
```

---

## 2. Staging public test data

Real Observables are large and gitignored, so they are fetched on demand, not stored in
the tree. `scripts/fetch-fixtures.sh` pulls the public datasets enumerated in
[`docs/DATASET.md`](../DATASET.md) into `fixtures/` and verifies each against
`fixtures/sha256sums.txt`.

```bash
bash scripts/fetch-fixtures.sh
```

Behavior worth knowing:

- **Checksum-gated.** Each fixture is downloaded atomically (`.tmp` → checksum → rename).
  A SHA mismatch against a pinned `<NAME>_SHA256` aborts; a first pull records the new
  SHA into `fixtures/sha256sums.txt` and becomes an idempotent re-verify on later runs.
- **Direct vs. gated sources.** Public-domain sources (NIST CFReDS `SCHARDT.001`,
  digitalcorpora Nitroba PCAP, OTRF Security-Datasets, Volatility `cridex.vmem`) have a
  default URL you can override with an env var; a failed pull WARNs and continues. Gated
  sources (SANS starter data, NIST Data Leakage, the Ali Hadi / DFRWS challenges) **SKIP
  with instructions** until you set their `<NAME>_URL` env var, because their filenames
  vary per item.
- **Not in git.** Nothing `fetch-fixtures.sh` downloads is committed — the same gitignore
  discipline as `evidence/`.

`docs/DATASET.md` is the source-of-truth for every URL, license, and SHA-256. Read it
before fetching; some sources are public domain and some require attribution (CC-BY).

Fixtures live in `fixtures/`; to investigate one, point `verdict` at it directly
(`scripts/verdict fixtures/nitroba/nitroba.pcap`) or copy it into `evidence/`.

---

## 3. Supported evidence types and their PLAYBOOK path

`case_open` inspects the path's extension and size, then the supervisor picks one of the
[`agent-config/PLAYBOOK.md`](https://github.com/TimothyVang/verdict-dfir-beta/blob/main/agent-config/PLAYBOOK.md) sequences below. The tool
names map to the typed product surface documented in
[`docs/reference/mcp-and-tools.md`](../reference/mcp-and-tools.md).

| Drop this | Detected as | PLAYBOOK tool sequence (after `case_open`) |
|---|---|---|
| `.mem` `.raw` `.img` `.vmem` `.dmp` `.lime` | Memory image | `vol_pslist` → `vol_psscan` → `vol_psxview` → `vol_malfind` → `yara_scan` |
| `.evtx` | Windows event log | `evtx_query` (EID histogram) → `hayabusa_scan` (if an EVTX *dir* is present) |
| `.e01` `.E01` `.dd` `.raw` `.aff` `.aff4` | Disk image | `disk_mount` / `disk_extract_artifacts` → `mft_timeline` → `prefetch_parse` → `usnjrnl_query` → `registry_query` → `evtx_query` → `hayabusa_scan` → `yara_scan` |
| `.pcap` `.pcapng` | Network capture | `pcap_triage` → `zeek_summary` (and `sysmon_network_query` for Sysmon EVTX) |
| `.zip` (Velociraptor) | Triage collection | safe zip extraction (reject zip-slip / oversized members) → per-artifact tools (`prefetch_parse`, `evtx_query`, etc.) on the extracted files |

Notes that change what you should expect:

- **Memory: the `vol_pslist` + `vol_psscan` pair is mandatory.** Divergence between the
  active-list walk and the pool-memory scan *is* the DKOM / T1014 Finding — but
  disambiguate a real rootkit from an acquisition smear before asserting it (see the
  `vol_pslist` caveat in `mcp-and-tools.md`). `vol_psxview` is the follow-up when they
  diverge.
- **Disk is custody-first.** `scripts/find_evil_auto.py` intentionally registers a raw
  disk image (SHA-256 + limitation note) and returns **`INDETERMINATE`** unless mounted /
  extracted artifacts are supplied for the typed disk tools. Custody-only registration is
  not a Finding — an `INDETERMINATE` on a disk you haven't mounted is the honest Verdict.
- **`.raw` is ambiguous** — it appears under both memory and disk. `case_open` uses size
  and content alongside the extension; if you know which it is, the mixed-folder layout in
  §4 removes the ambiguity.
- **Every Finding cites a `tool_call_id`.** The verifier vetoes any Finding without one,
  regardless of evidence type.

---

## 4. Mixed case directories (the realistic case)

A real Case is rarely one file. Stage a **folder** containing a memory image, an EVTX
directory, a disk image, and network captures together, and point `verdict` at the
folder:

```bash
scripts/verdict evidence/cases/host-7/
```

```
evidence/cases/host-7/
├── memory.mem            # → vol_pslist / vol_psscan / vol_psxview / vol_malfind
├── logs/
│   ├── Security.evtx     # → evtx_query
│   └── Sysmon.evtx       # → sysmon_network_query (Pool B endpoint outbound)
├── disk.e01              # → disk_mount → mft/prefetch/usnjrnl/registry
└── capture.pcapng        # → pcap_triage → zeek_summary
```

The supervisor runs each contained Observable through its own type playbook and threads
them together via the single `case_id` that every tool accepts — so a process seen in
`vol_pslist` with no matching `prefetch_parse` entry, or an EVTX logon that lines up with
a PCAP conversation, can corroborate across artifact classes toward the SOUL.md
≥2-artifact-class rule. The `--watch` debounce keeps a directory as one entry, so a folder
copy is investigated only after it finishes copying.

---

## 5. The custody guarantee: read-only + SHA-256 at `case_open`

Every Case starts with `case_open`, and that step is the chain-of-custody anchor:

- **SHA-256 at open.** `case_open` hashes the image and returns `{id, image_path,
  image_hash, size_bytes, opened_at}`. The hash is the **first leaf** of the hash-chained
  audit log. If you pass `expected_sha256` and it doesn't match, `case_open` errors before
  any other tool runs.
- **Read-only, always.** No product tool mutates evidence. Reads operate on read-only
  mounts; the original `.e01` is opened via **libewf** and stays byte-for-byte untouched.
  Adding a write path or an `execute_shell` verb is a non-negotiable invariant violation.
- **Mid-run tamper is fatal.** If the evidence is modified out-of-band during a run, the
  chain of custody is compromised and the supervisor refuses to sign the manifest.
- **The 48 product tools are the only audit-chained surface** (34 Rust + 14 Python).
  `.mcp.json` registers 6 servers total; the other 4 are non-product conveniences and
  are not part of the signed chain. See
  [`docs/reference/mcp-and-tools.md`](../reference/mcp-and-tools.md) for the full map and
  [`docs/reference/dependencies.md`](../reference/dependencies.md) for which external DFIR
  binaries each evidence type needs.

The output of a run (audit JSONL, signed manifest, `verdict.json`, and the report) lands in
`tmp/auto-runs/<case-id>/`, never back in `evidence/`. Your staged Observables are read,
hashed, and left exactly as you dropped them.
