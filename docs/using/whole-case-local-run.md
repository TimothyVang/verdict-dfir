# Whole-case local run — staging a multi-host corpus and automating it end to end

> **Status: ACTIVE.** How to pull a full SANS-style evidence corpus from a public
> Egnyte share and run VERDICT against **every host locally** (no SIFT VM), with a
> single whole-case verdict table. Worked example: the SANS HACKATHON-2026
> *SRL-2018 Compromised Enterprise Network* corpus (7 disk E01s + 22 memory captures).

This complements [fleet-analysis.md](./fleet-analysis.md): the fleet pipeline correlates
*across* hosts but needs the SIFT VM over SSH; this flow runs each host's full Verdict
pipeline **locally** and rolls the per-host verdicts into one table.

> **Shortcut:** `scripts/verdict <case-root>` now does all of this (plus the cross-host
> correlation + FLEET_REPORT) in one command — a folder with `hosts/` or `disks/` is
> auto-detected as a fleet. The script below remains the per-host stage it chains, and is
> still useful standalone when you want only the per-host verdict table.

Evidence files are **git-ignored** (`*.E01`, `*.img`, `*.raw`, …) — only the tooling below is
in the repo. The corpus stays on the local host.

---

## Prerequisites

- **Node + Playwright** (for the downloader): `npm i -g playwright && npx playwright install chromium`
  (or set `PLAYWRIGHT_DIR` to a dir containing the `playwright` module).
- **The Sleuth Kit + libewf** (for disk E01 runs): `sudo apt install sleuthkit ewf-tools`.
  Without `fls`/`icat`/`mmls`/`ewfmount`, `disk_extract_artifacts` fails and disk cases
  degrade to custody-only `INDETERMINATE`.
- **p7zip** (to extract memory archives): `sudo apt install p7zip-full`.
- The usual VERDICT toolchain (run `scripts/verdict --help` / the preflight doctor).

---

## 1. Download the corpus

Egnyte's **"Download Folder"** zip returns HTTP 400 on large public shares (zip-folder needs a
login), so files are pulled **individually** through the browser. `scripts/stage-egnyte-corpus.mjs`
drives a fresh browser per file (no cross-file SPA navigation), with retries, magic-byte
verification, and skip-if-present (so it is resumable).

```bash
# manifest lists the share URL + the files in each (sub)folder and where they land
node scripts/stage-egnyte-corpus.mjs scripts/egnyte-corpus.srl-2018.json \
  evidence/cases/srl-2018 --dry-run        # preview the 29 files + URLs
node scripts/stage-egnyte-corpus.mjs scripts/egnyte-corpus.srl-2018.json \
  evidence/cases/srl-2018                  # download (~120 GB; resumable)
```

Result: disk E01s in `evidence/cases/srl-2018/disks/`, memory archives in
`evidence/cases/srl-2018/mem_archives/`. To stage a different corpus, copy the manifest and
edit the `share` / `rootPath` / `groups` (folder UI → file names + which subfolder).

## 2. Extract + verify the memory images

```bash
scripts/extract-mem-archives.sh \
  evidence/cases/srl-2018/mem_archives evidence/cases/srl-2018/hosts
```

Each archive becomes `hosts/<name>/<name>.img` and is **MD5-checked against the `dc3dd`
acquisition hash** it ships (`MD5_OK` / `MD5_MISMATCH` / `NO_MD5`). The archive is deleted after
a successful extract to reclaim space.

## 3. Run every host locally

```bash
scripts/run-whole-case-local.sh evidence/cases/srl-2018
```

Enumerates and runs `scripts/verdict` on:
- `hosts/<host>/` — each staged memory-image directory,
- `disks/*.E01` — each disk image,
- root-level `base-file-cdrive.E01` and `base-file-memory.img` as standalone targets when present,
- `<out>/_xartifact/base-file/` — a derived base-file disk+memory cross-artifact case staged under the output directory, not under the evidence root.

It is **resumable** (skips hosts whose run-summary already exists) and prints a final table of
`verdict` + offline `manifest_verify` per host. Output lands in
`tmp/whole-case-local/<case>/`.

---

## Worked result — SRL-2018 partial local run

Full corpus staged and integrity-verified: **7 disk E01s** (EVF-magic verified) + **22 memory
images** (21/22 MD5-matched to their `dc3dd` hashes; `base-wkstn-01-mem.zip` shipped without an
embedded MD5). The historical local result captured 28 completed rows, but target accounting was
incomplete: standalone `disk:base-file-cdrive` and `mem:base-file-memory` must not be replaced by
the optional `xart:base-file` combined case. Current accounting is 29 standalone source artifacts,
plus the optional derived `xart:base-file` target when cross-artifact review is desired.

```
verdict tally:  INDETERMINATE 25 · NO_EVIL 3
manifest_ok:    all 28 recorded rows in that historical run
```

- **NO_EVIL** (scoped-clean disks): `base-dc`, `base-wkstn-05`, `dmz-ftp`.
- **INDETERMINATE** (leads found, single-artifact-class → stay `HYPOTHESIS` per the ≥2-class
  rule in `CLAUDE.md` "Non-Negotiable Guardrails"): the 22 memory hosts, 3 disks, and the base-file cross-artifact case.
  Example lead: `base-file` memory flagged uncommon processes incl. `Rar.exe` and
  `subject_srv.ex` (staging/exfil signals) — honest leads to corroborate, not confirmed evil.

Every Finding in those recorded rows cites a `tool_call_id`; each recorded row's
`manifest_verify.overall` is `true`. Treat that run as a partial local automation artifact, not a
customer-release proof, until the missing standalone base-file targets and report-QA blockers are
rerun and reviewed.

### Gotcha — disk pipeline prerequisites

If disk runs come back with 0 findings and `disk_extract_artifacts ... io error at fls` (or
`disk_mount ... case not found` from stale MCP instances), install `sleuthkit` + `ewf-tools`
and re-run. The runner is resumable, so only the disk targets re-execute.
