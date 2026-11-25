# Detection Fallbacks Review

Review note for fallback, degraded, unsupported, or partial-coverage paths that can prevent VERDICT from finding more malicious activity. This is not a product claim by itself; each item points at existing code or documentation that should be checked before we claim broader coverage.

## Summary

- Raw scan found 191 fallback, limitation, missing, skipped, or degraded-coverage terms across Markdown, JSON, JSONL, and text artifacts.
- Roughly 21 categories appear detection-impacting after removing report/UI/release-only fallbacks.
- The highest-value fixes are parser/tool availability, disk extraction breadth, Plaso/legacy Windows coverage, same-host disk+memory fusion, and evidence-rule handling for thin but real signals.

## Highest Priority Gaps

| Gap / fallback | Why it can miss evil | Evidence |
|---|---|---|
| Plaso unavailable | Legacy timelines, XP `.evt`, IE `index.dat`, Recycle Bin, task, and other Plaso-normalized artifacts may stay partial. | `docs/release-evidence/stage-two-evidence.md:40`; `docs/release-evidence/nist-schardt-disk-summary.json:29-34` |
| Raw disk custody-only | If `disk_mount` / `disk_extract_artifacts` fails or yields no supported artifacts, disk contents are not examined. | `agent-config/PLAYBOOK.md:113-119`; `docs/DATASET.md:260-264` |
| Missing external DFIR binaries | Volatility, Hayabusa, Velociraptor, tshark/Zeek, EZ tools, Plaso, mac_apt, journalctl, last, ausearch, nfdump, Suricata, and INDXParse can become missing-tool lanes. | `docs/analyst/tool-playbooks.md:139`; `scripts/doctor.sh:243-270` |
| Disk extraction caps | Large or noisy disks can lose tail artifacts due to default artifact byte and count limits. | `services/mcp/src/tools/disk.rs:22`; `services/mcp/src/tools/disk.rs:280-287`; `services/mcp/src/tools/disk.rs:1387-1389` |
| Failed file extraction skips artifacts | Individual `icat` extraction failures are skipped, so downstream parsers never see those artifacts. | `services/mcp/src/tools/disk.rs:1054-1056`; `services/mcp/src/tools/disk.rs:1090-1092` |
| Deleted / non-file disk entries skipped | Deleted-file recovery and non-regular NTFS artifact analysis are limited in the current extraction path. | `services/mcp/src/tools/disk.rs:913-923` |
| Disk YARA only scans extracted targets | Whole-mount recursive YARA is not implemented; `yara_scan` only runs over extracted yara-target files. | `agent-config/PLAYBOOK.md:136-139`; `agent-config/PLAYBOOK.md:227-230` |
| Single EVTX skips Hayabusa | A single `.evtx` gets `evtx_query` only; Sigma/Hayabusa coverage requires an EVTX directory. | `agent-config/PLAYBOOK.md:166-171` |
| Memory translation failures | `malfind=0` or empty active-list results can mean not analyzable, not clean. | `agent-config/MEMORY.md:21`; `docs/troubleshooting.md:36-45` |
| Parser / result caps | Volatility, Hayabusa, and PCAP outputs can truncate high-volume cases or top lists. | `services/mcp/src/tools/hayabusa_scan.rs:371-374`; `services/mcp/src/tools/pcap_triage.rs:13-20` |
| PCAP/network scope is triage | Interactive packet reconstruction and broad payload carving are outside current automated scope. | `agent-config/PLAYBOOK.md:282`; `docs/artifact-semantics.md:153-164` |
| Same-host disk+memory fusion pending | Disk and memory are demonstrated separately; same-host disk-vs-memory discrepancy correlation is not fully automated/committed. | `docs/release-evidence/stage-two-evidence.md:42-43`; `agent-config/PLAYBOOK.md:156` |
| Conservative corroboration suppresses thin signals | Real but single-source signals may remain `HYPOTHESIS` if only one artifact class supports them. | `docs/accuracy-report.md:181-187`; `docs/red-team-challenge.md:27-31` |
| Cloud provider allow-list | Cloud/SaaS evidence outside supported providers is not parsed by the `cloud_audit` lane. | `services/mcp/src/tools/cloud_audit.rs:29-38`; `agent-config/EXPERT.md:70-74` |
| Long-tail tools not real-run proven | Some typed tools are unit-tested but not exercised broadly on committed real evidence. | `docs/reference/mcp-and-tools.md:70-75`; `agent-config/TOOLS.md:24-29` |

## Known Misses Already Written Up

The clearest public list is the NIST Hacking Case recall gap: 7 of 14 expected findings matched on the richer committed runs (5 of 14 on leaner runs — run-to-run variance disclosed in `../accuracy-report.md`). The missing classes are valuable because they map directly to parsers or playbooks that would find more evil.

| Missing class | Why it matters |
|---|---|
| ACMru / search history | May reveal attacker searches and staging discovery. |
| USB history | May reveal removable-media staging or exfil paths. |
| Email carving | May reveal phishing, exfil, or command channels. |
| IE `index.dat` / browser history | May reveal downloads, C2 panels, webmail, or tooling sources. |
| XP `.evt` | May reveal legacy Windows event evidence not covered by EVTX-only parsing. |
| Thumbcache | May reveal viewed files, images, or documents even after deletion. |
| Named-pipe enum | May reveal malware, lateral movement, or IPC artifacts. |

Evidence: `docs/DATASET.md:280`; `docs/release-evidence/l3-local-sift.json:40-63`.

## More Detection-Impacting Fallbacks To Review

| Area | Current behavior / concern | Evidence |
|---|---|---|
| Unsupported artifact classes | If no parser/tool extracts an artifact class, VERDICT cannot reason over it. | `docs/red-team-challenge.md:17-25`; `README.md:45-48` |
| SIFT setup fallback | SIFT setup can fall back to local mode; VirtualBox path is stubbed, so full disk-image parity may not be available. | `QUICKSTART.md:38-57`; `README.md:211-215` |
| Memory/Volatility failures | Memory runs can become empty or partial and still seal honestly as `INDETERMINATE`. | `docs/troubleshooting.md:36-45`; `docs/troubleshooting.md:58-69` |
| EVTX XPath | XPath is accepted for forward compatibility but not applied by the shipped Rust tool. | `agent-config/TOOLS.md:36-39`; `services/mcp/src/tools/evtx_query.rs:9-11` |
| Remote ZIP / collection extraction | Unsupported ZIP members and sample-limited summaries can underrepresent unsupported artifact volume. | `scripts/find_evil_auto.py:880-903`; `scripts/find_evil_auto.py:1111-1124` |
| Exfil without network | Staging alone remains unsupported or `HYPOTHESIS` without movement telemetry. | `docs/red-team-challenge.md:30`; `agent-config/EXPERT.md:55-74` |
| Malware capability without reverse engineering | Malfind/YARA/process evidence does not prove full malware capability. | `agent-config/EXPERT.md:55-74`; `agent-config/EXPERT.md:81-89` |
| Unsupported cloud/SaaS, mobile, OT/ICS | These are partial/escalation-only where dedicated typed parsers are absent. | `agent-config/EXPERT.md:70-74` |

## MemProcFS Note

No current product support was found for MemProcFS. Search hits were unrelated `memfs` package-lock entries, not MemProcFS tooling. Treat MemProcFS as a future capability candidate unless a typed MCP wrapper is added and documented.

Potential value if added later:

- Better memory/filesystem fusion workflows.
- Process, handle, module, and registry views through a mounted memory filesystem.
- Possible bridge for same-host disk+memory discrepancy analysis.

Do not claim MemProcFS support until it exists as a typed, allow-listed product tool.

## Suggested Priority Order

1. Close the Plaso/log2timeline install and docs gap, or make the `plaso_parse` failure path clearer in reports.
2. Add parser coverage for the seven known NIST misses, especially XP `.evt`, IE `index.dat`, USB history, and thumbcache.
3. Improve disk extraction visibility: count skipped `icat` files, cap hits, and unsupported artifact classes prominently in `coverage_manifest` and reports.
4. Implement same-host disk+memory fusion as an automated finding candidate, with strict corroboration rules.
5. Decide whether MemProcFS deserves a new typed wrapper seed.
6. Revisit result caps for high-volume cases so truncation is visible and tunable.
7. Add tests or committed runs for long-tail tools currently described as unit-tested but not real-run proven.

## Review Questions

- Which of these should become Seeds issues first?
- Should Plaso be installable by `scripts/install-dfir-tools.sh`, or only documented as install-first?
- Should MemProcFS be a real typed product tool, or remain a future research note?
- Do we want to prioritize NIST recall fixes or same-host disk+memory fusion first?
- Which fallback categories should be surfaced in the public README versus kept in analyst/runbook docs?
