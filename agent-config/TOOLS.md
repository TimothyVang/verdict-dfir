# TOOLS.md — MCP Surface

The agent has access to two MCP servers, both auto-spawned by Claude Code via `.mcp.json` at session start. **No `execute_shell` exists** — the typed surface below is the only verb set the agent has.

| Server | Lang | Tools |
|---|---|---|
| `findevil-mcp` | Rust (`services/mcp/`) | 42 typed DFIR tools |
| `findevil-agent-mcp` | Python (`services/agent_mcp/`) | 14 crypto + ACH + memory + ACP + expert-feedback + accuracy + AI-signature tools (post-A5; the `ots_stamp` + `ots_verify` pair was removed) |

Every successful tool call carries `_meta.output_sha256` (hex SHA-256 of the canonical JSON output). Findings cite tool calls by `tool_call_id`. The verifier vetoes any finding that doesn't.

> **Finding-authoring invariant.** Every CONFIRMED execution/intent Finding MUST populate `counter_hypothesis` with the benign explanation considered and discarded (presumption of benignity). Empty on such a Finding is a gate failure under `FIND_EVIL_REQUIRE_COUNTER_HYPOTHESIS_FINDING`; the correlator downgrades it and the schema/verifier reject it.

> **This file is the agent read-order catalog of the 46 typed PRODUCT tools** (the only verbs in
> the audit chain). The *full* set of MCP servers actually registered in `.mcp.json` (incl. the
> operator-runtime `n8n-mcp`, `playwright`, `puppeteer` that emit no Findings) and the external
> DFIR binaries + dependency pins are inventoried in
> [`docs/reference/mcp-and-tools.md`](../docs/reference/mcp-and-tools.md) and
> [`docs/reference/dependencies.md`](../docs/reference/dependencies.md). Tool counts here are
> authoritative — keep them in sync, don't diverge.

---

## Rust DFIR tools (`findevil-mcp`)

**Maturity note.** The long-tail verbs `vol_run`, `ez_parse`, `plaso_parse`, `mac_triage`,
`cloud_audit`, `journalctl_query`, `login_accounting`, `ausearch`, `nfdump_query`,
`suricata_eve`, `indx_parse`, `thumbcache_parse`, and `hashset_lookup` are implemented as typed,
allow-listed, shell-free tools and unit-tested against synthetic fixtures, but they have not yet
been exercised on real evidence in a committed case run. The committed sample runs prove the core disk/registry/EVTX/MFT/Prefetch/YARA/
USN/Hayabusa/Sysmon/Zeek/PCAP, `vol_*`, `vel_collect`, and `browser_history` paths.

> **Long-tail tool availability.** `scripts/setup` installs `volatility3`, `hayabusa` (+ Sigma
> rules), `chainsaw`, `velociraptor`, and `pandoc`/`matplotlib`, plus the long-tail wrappers it can
> install cleanly: `indx_parse` (INDXParse) and `plaso_parse` (log2timeline, best-effort pip) go in
> user-space via `install-dfir-tools.sh`, and `ausearch` (auditd), `nfdump_query` (nfdump), and
> `suricata_eve` (suricata) are apt-installed by `install.sh` under `--bootstrap` (which
> `scripts/setup` passes). `ez_parse` (Eric Zimmerman tools, .NET) and `mac_triage` (mac_apt) ship
> on the SANS SIFT VM and are reported (not auto-installed) elsewhere, since neither has a clean
> cross-distro user-space installer. Any tool still missing returns a typed `BinaryNotFound` error
> and the run continues (graceful skip); it never crashes the server. `scripts/doctor.sh` reports which are
> present, and the install hint is in each tool's `BinaryNotFound` error message.

### case_open
Args: `{image_path: str, expected_sha256?: str, label?: str}`
Returns: `{id, image_path, image_hash, size_bytes, opened_at}`
Use when: starting an investigation. **Must be called first** — every subsequent tool needs the `case_id`. The image hash is the first audit-chain leaf; if the agent passes `expected_sha256` and it doesn't match, `case_open` errors before any other tool runs.

### bulk_extract
Args: `{case_id, image_path, scanners?: enum[], find_regexes?: str[], keyword_file?: str, limit?}`
Returns: `{bulk_extractor_available, engine_version, scanners_requested[], features[]: {feature_type, offset, feature, context}, features_seen, staged_files[]: {feature_type, path, sha256, line_count}, stderr_tail, note}`
Use when: a raw/E01 disk image is in scope and you need FEATURES from the whole byte stream — allocated files AND unallocated/free space, slack, and deleted regions the filesystem no longer references. This is the deleted-email / free-space feature-recovery surface that the live-filesystem parsers (`mft_timeline`, `disk_extract_artifacts`) cannot reach: it recovers an email whose directory entry is gone. Wraps `bulk_extractor` (Simson Garfinkel). `scanners[]` is the allow-listed set of real scanner names (`email` — which also emits the rfc822/url/domain recorders — `accts`, `httplogs`, `gps`, `exif`, `json`, `net`, `zip`, `gzip`, `pdf`, `sqlite`, `utmp`, `winlnk`, `winprefetch`, `ntfsusn`, `ntfsmft`, `evtx`, `find`); empty runs bulk_extractor's defaults. Keyword/regex hits come ONLY from `find_regexes[]` or an operator `keyword_file` (or `$FINDEVIL_BULK_KEYWORD_FILE`) — NEVER image-specific literals. DETERMINISTIC for `verify_finding` replay: runs single-threaded (`-j 1`), sorts feature rows in-tool, records case-relative staged paths with per-file SHA-256, and puts the bulk_extractor version (never a wall-clock) in the hashed body. INSTALL-FIRST — degrades to `bulk_extractor_available=false` (custody-only, not an error). `$FINDEVIL_BULK_EXTRACTOR_BIN` then PATH. HONEST SCOPE: a recovered feature CONFIRMS the string was present in the imaged bytes; it does not by itself prove authorship, intent, or a live filesystem path.

### evtx_query
Args: `{case_id, evtx_path, eids?: int[], xpath?: str, limit?}`
Returns: `{rows[], row_count, records_seen, parse_errors}`
Use when: account/logon/service/scheduled-task/process-creation questions. In-process via `evtx = 0.11.2` (~1600× faster than python-evtx). `eids` is the cheap EventID filter; `xpath` is accepted for forward compatibility but not applied by the shipped Rust tool today. Always pair Type 3 (Network logon) findings with the source IP — internal RFC1918 is almost always benign.

### prefetch_parse
Args: `{case_id, prefetch_path}`
Returns: `{executable_name, run_count, last_run_times[], volumes[], file_references[], prefetch_hash}`
Use when: confirming execution. Every `.pf` file proves the named binary ran on this host at the named UTC times — not just "was registered." Prefer this over Amcache (which is *catalog*-registration time, not execution).

### mft_timeline
Args: `{case_id, mft_path, since_iso?, until_iso?, limit?}`
Returns: `{rows[], rows_seen, parse_errors}` where each row is `{ts, src_attr ($SI/$FN), path, size, inode, is_allocated}`
Use when: filesystem creation/modification ordering, especially for "what changed in the compromise window?" Prefer `$FN` over `$SI` (anti-forensics tooling stomps `$SI`, rarely `$FN`). Read `is_allocated` to detect deleted files.

### registry_query
Args: `{case_id, hive_path, key_path, value_name?, recursive?, depth?, limit?}`
Returns: `{entries[]}` with `{key, name, type, data}` formatted by RegValue type (REG_SZ→text, REG_MULTI_SZ→pipe-joined, REG_DWORD→decimal, REG_BINARY→hex truncated at 4096B)
Use when: persistence questions (Run/RunOnce, Services, IFEO, AppInit_DLLs), user-context (NTUSER.DAT shellbags, MRUs), ShimCache, BAM. Pass the primary hive only; transaction logs (`.LOG1` / `.LOG2`) are not auto-merged. `recursive=true` walks depth-first capped at 16 by default.

### yara_scan
Args: `{case_id, target_path, rules_path, recursive?, limit?}`
Returns: `{matches[], files_scanned, rules_compiled, scan_errors}`
Use when: IOC matching. In-process via `yara-x = 1.12.0` (BSD-3-Clause, VirusTotal pure-Rust YARA). Each match shows `{rule_name, namespace, tags, pattern_matches[]}` with offset+length+64-byte hex preview. **Always cite the rule name in findings.** Prefer YARA-Forge `core` tier (curated low-FP); `extended`/`community` tiers without corroboration are FP-prone.

### usnjrnl_query
Args: `{case_id, usnjrnl_path, since_iso?, until_iso?, reasons[]?, limit?}`
Returns: `{entries[], records_seen, parse_errors, row_count, major_version}`
Use when: tracking filesystem changes the MFT can't show (deleted-file event sequences, rename chains, hard-link manipulation). `reasons[]` filters by USN reason flag names (FILE_CREATE, FILE_DELETE, RENAME_NEW_NAME, etc.; case-insensitive). Multi-GB journals stream — no OOM.

### hayabusa_scan
Args: `{case_id, evtx_dir, rules_dir?, min_level?, limit?}`
Returns: `{events[], events_seen, stderr_tail}` where each event is `{timestamp_iso, rule, level, channel, event_id, computer, details}`
Use when: Sigma-rule sweep over an EVTX directory. Subprocess to `hayabusa` (AGPL — never linked). `min_level` ∈ {informational, low, medium, high, critical}. Pre-compiled Hayabusa rules expected at `~/hayabusa/rules` unless `rules_dir` is overridden. False-positive note: routine admin activity (Sysinternals tools, scheduled WMI, AV updates) trips medium-severity rules; pair every Hayabusa hit with `prefetch_parse` and `evtx_query 4624` cross-corroboration before believing it.

### sysmon_network_query
Args: `{case_id, evtx_path, event_ids?, since_iso?, until_iso?, image_contains?, destination_ip?, destination_port?, limit?}`
Returns: `{rows[], row_count, records_seen, parse_errors}` where each row normalizes Sysmon network fields (`Image`, `SourceIp`, `DestinationIp`, ports, protocol, user) and preserves raw fields.
Use when: Sysmon Operational logs are available and Pool B needs endpoint-side outbound connection evidence. Event ID 3 is the default. This is EVTX parsing in-process, not a shell wrapper.

### zeek_summary
Args: `{case_id, zeek_path, limit?}`
Returns: `{log_files, rows_seen, conn_count, dns_count, http_count, tls_count, top_hosts[], top_dns_queries[], top_http_hosts[], notable_connections[], parse_errors}`
Use when: Zeek logs are supplied directly or produced from PCAP. Pure parser for Zeek TSV logs; treats rows as network telemetry leads, not exfil proof by itself.

### pcap_triage
Args: `{case_id, pcap_path, analyzer?: "auto"|"tshark"|"zeek", limit?}`
Returns: `{analyzer, packets_seen, conversations[], dns_queries[], http_hosts[], zeek?, stderr_tail}`
Use when: raw PCAP/PCAPNG is supplied. Uses fixed `tshark`/`zeek` subprocess argv only; no raw shell. `auto` prefers tshark, then Zeek. Missing binaries are an environment limitation, not evidence absence.

### vol_pslist
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` where each process is `{pid, ppid, image_name, create_time_iso, exit_time_iso?, threads, handles, session_id, wow64}`
Use when: enumerating processes from a memory image via the kernel's active list. **Always pair with `vol_psscan` for DKOM cross-validation.** pslist=0 + psscan>0 *can* be the T1014 (Rootkit) signature — but **disambiguate from an acquisition smear / kernel-global read failure before asserting T1014**: if `psscan` recovered core OS singletons (System/csrss/lsass) or duplicate `System` (PID 4) EPROCESS, or `windows.info` shows `KeNumberProcessors`=0, the active-list walk failed for the whole image (smear) rather than a rootkit unlinking a few processes — label it a HYPOTHESIS and require ≥2 artifact classes for T1014. Subprocess to `volatility3` (BSD-2 — never linked, env var `$VOLATILITY_BIN` first then PATH).

### vol_psscan
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` — same shape as `vol_pslist` but with `offset_v` (EPROCESS virtual address)
Use when: cross-validating `vol_pslist` for DKOM detection. psscan signature-scans EPROCESS pool memory, finding orphaned `_EPROCESS` blocks unlinked from the active list. **The redundancy is deliberate** — divergence between pslist and psscan IS the rootkit finding.

### vol_psxview
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{processes[], processes_seen, stderr_tail}` where each process is `{pid, image_name, offset_v?, pslist?, psscan?, thrdproc?, pspcid?, csrss?, session?, deskthrd?, exit_time_iso?}`
Use when: corroborating DKOM process hiding after `vol_pslist` and `vol_psscan` diverge. `psxview` cross-references multiple process-enumeration views so the analyst can see which views miss a process and which views still recover it. This is the direct follow-up whenever pslist and psscan disagree on a process.

### vol_malfind
Args: `{case_id, memory_path, pid_filter?: int[], limit?}`
Returns: `{injections[], injections_seen, stderr_tail}` where each injection is `{pid, image_name, vad_start_hex, vad_end_hex, protection, mz_match: bool, sample_hex}` (64-byte preview)
Use when: hunting injected code (T1055). `mz_match=true` + RWX `protection` + non-Microsoft-signed parent process = high-confidence injection. Slowest of the vol_* tools — give it a 30-minute timeout on 5GB+ memory images (the orchestrator already does).

### vel_collect
Args: `{case_id, artifact: str, args?: {str: str}, format?, limit?}`
Returns: `{rows[], rows_seen, stderr_tail}` — `rows` are free-form (every Velociraptor artifact has its own column shape; typed-here would be hostile)
Use when: any of Velociraptor's 200+ DFIR artifacts (`Windows.Forensics.Prefetch`, `Generic.Forensic.LocalHashes`, etc.). `artifact` validated against dotted-path pattern, `args` keys validated against `[A-Za-z_][A-Za-z0-9_]*` to block flag injection. Subprocess to `velociraptor` (Apache-2.0; env var `$VELOCIRAPTOR_BIN` first then PATH).

### browser_history
Args: `{case_id, history_path: str, limit?: int}`
Returns: `{browser_family, rows[]: {url, title, last_visit_time_iso, visit_count}, rows_seen}`
Use when: an extracted browser history DB — Chrome/Edge `History` or Firefox `places.sqlite` — is in scope (downloaded-payload URL, phishing visit, C2 panel). Opened read-only + `immutable=1` (no `-wal`/`-journal` write on evidence); browser auto-detected by schema; timestamps normalized to ISO-8601Z from each native epoch (Chrome WebKit µs-since-1601, Firefox µs-since-1970). HONEST SCOPE: a row CONFIRMS a URL was *recorded as visited* at T — a browser-artifact fact, NOT execution, so a single `browser_history` Finding is a legitimate CONFIRMED browser fact and never trips the ≥2-artifact-class rule; intent is a separate `hypothesis:` layer. In-process via `rusqlite` (MIT, vendored SQLite).

### vol_run
Args: `{case_id, memory_path, plugin: str, pid?: int, limit?}`
Returns: `{plugin, rows[]: per-plugin JSON columns, rows_seen, stderr_tail}`
Use when: a memory plugin beyond the four bespoke `vol_*` pivots is needed. `plugin` MUST be one of the curated canonical-name allow-list (windows/linux/mac cmdline, netscan, svcscan, consoles, handles, dlllist, cred trio, hollow/rootkit, etc.); any off-list value — including a shell-injection-shaped string — is rejected with `PluginNotAllowed` BEFORE any subprocess (the no-shell guarantee for a parameterized verb). Output is generic rows because plugin schemas differ. Subprocess to `volatility3` (`$VOLATILITY_BIN` first then PATH). This is the long-tail memory verb; the four typed `vol_*` tools stay for the pivots playbooks depend on.

### ez_parse
Args: `{case_id, tool: str, artifact_path, limit?}`
Returns: `{tool, rows[]: per-tool CSV columns, rows_seen, csv_files[], stderr_tail}`
Use when: decoding a carved Windows artifact. `tool` ∈ `{lecmd, jlecmd, amcacheparser, appcompatcacheparser, rbcmd, sbecmd, wxtcmd}` (LNK / JumpLists / Amcache / ShimCache / Recycle Bin / shellbags / Win10 Timeline); off-list/injection values reject with `ToolNotAllowed` before any subprocess. Runs the Eric Zimmerman tool's fixed-argv CSV invocation and parses the result. **Amcache LastModified ≠ execution** (catalog-registration time) — it is a ≥2-artifact corroborator for Prefetch, never proof alone. Binary discovery `$EZTOOLS_DIR` then PATH; graceful `BinaryNotFound`.

### plaso_parse
Args: `{case_id, parser: str, artifact_path, limit?}`
Returns: `{parser, events[]: normalized plaso event objects, events_seen, stderr_tail}`
Use when: a cross-OS log plaso normalizes (`syslog`, `bash_history`, `zsh_extended_history`, `utmp`, `dpkg`, `selinux`, legacy `winevt`/`msiecf`/`winjob`, `recycle_bin`, `viminfo`, macOS `asl_log`/`macwifi`). `parser` validated against the allow-list before argv. Two-stage fixed-argv run (`log2timeline.py` → `psort.py json_line`); `$PLASO_DIR` then PATH. For modern Windows `.evtx`, prefer the in-process `evtx_query`. **Deterministic-absence degradation:** plaso is an optional subprocess (absent off the SIFT VM). When `log2timeline.py` is not found, the orchestrator records one `course_correction` (`mechanism=tool_failure_resequence`), marks plaso absent for the run, and **early-stops** — INFO2 recycle-bin routes to `ez_parse:rbcmd`; remaining plaso classes (`legacy_evt`/`ie_history`/`scheduled_task`) are skipped with a recorded coverage-degradation note rather than re-issuing the same doomed call per artifact. The skip is an honest coverage gap, not a silent fallback.

### mac_triage
Args: `{case_id, module: str, image_path, limit?}`
Returns: `{module, rows[]: per-module CSV columns, rows_seen, csv_files[], stderr_tail}`
Use when: triaging a mounted macOS image. `module` ∈ allow-listed `mac_apt` modules (`UNIFIEDLOGS`, `FSEVENTS`, `AUTOSTART`, `KNOWLEDGEC`, `QUARANTINE`, `TCC`, `SAFARI`, `SPOTLIGHT`, `INSTALLHISTORY`, `BASHSESSIONS`, …); off-list/injection rejects with `ModuleNotAllowed` before subprocess. Intended as the macOS analogue of `disk_extract_artifacts`; once `mac_apt` is provisioned it covers most macOS classes, but this verb is not yet exercised on a real macOS image in a committed run. `$MAC_APT` then PATH; graceful `BinaryNotFound`.

### cloud_audit
Args: `{case_id, provider: str, log_path, limit?}`
Returns: `{provider, events[]: {timestamp, actor, source_ip, action, resource, outcome, raw}, events_seen}`
Use when: a cloud/identity audit log is in scope (the modern attacker center of gravity). `provider` ∈ `{cloudtrail, entra_signin, entra_audit, m365_ual, gcp_audit, workspace, k8s_audit, vpc_flow}`; off-list rejects with `ProviderNotAllowed`. **Pure Rust — no subprocess, no external binary.** Accepts JSON arrays, `{Records}`/`{value}` containers, JSONL, M365 UAL CSV `AuditData`, and space-delimited VPC flow; normalizes every provider into one envelope so the agent reasons across clouds.

### journalctl_query
Args: `{case_id, journal_path: str, since?: str, until?: str, limit?}`
Returns: `{rows[]: free-form systemd-field maps, rows_seen, stderr_tail}`
Use when: a binary systemd journal (`*.journal`) is carved. Fixed `journalctl --file <path> -o json` subprocess (GPL, subprocess-only). Optional `since`/`until` (UTC ISO-8601). `$JOURNALCTL_BIN` then PATH; graceful `BinaryNotFound`.

### login_accounting
Args: `{case_id, accounting_path: str, limit?}`
Returns: `{rows[]: {user, line, host, login_iso?, logout_iso?, raw}, rows_seen, stderr_tail}`
Use when: a Linux wtmp/btmp login-accounting DB is carved (lateral-movement / brute-force triage). Fixed `last -f <path> -F -w` subprocess, deliberately keeping the recorded remote host column. `$LAST_BIN` then PATH.

### ausearch
Args: `{case_id, audit_log_path: str, limit?}`
Returns: `{rows[]: free-form type=... record maps, rows_seen, stderr_tail}`
Use when: a Linux auditd `audit.log` is carved (highest-fidelity execve/syscall record). Fixed `ausearch -i -if <path>` subprocess. INSTALL-FIRST (absent on stock SIFT) — graceful `BinaryNotFound`. `$AUSEARCH_BIN` then PATH.

### nfdump_query
Args: `{case_id, flow_path: str, limit?}`
Returns: `{rows[]: flow-record column maps, rows_seen, stderr_tail}`
Use when: a NetFlow/IPFIX capture (`nfcapd`-style) is in scope (Pool B exfil-volume / beaconing). Fixed `nfdump -r <path> -o json`; **no free-text filter field** (injection guard). INSTALL-FIRST. `$NFDUMP_BIN` then PATH.

### suricata_eve
Args: `{case_id, pcap_path: str, limit?}`
Returns: `{events[]: eve.json event maps, events_seen, stderr_tail}`
Use when: a PCAP needs IDS replay (alert/dns/http/tls/fileinfo by `event_type`). Fixed `suricata -r <pcap> -l <outdir>` (GPL, subprocess-only) → reads `eve.json` from a temp outdir. INSTALL-FIRST. `$SURICATA_BIN` then PATH.

### indx_parse
Args: `{case_id, indx_path: str, limit?}`
Returns: `{rows[]: INDX column maps, rows_seen, stderr_tail}`
Use when: a carved NTFS `$I30`/INDX stream may hold slack entries for deleted files (anti-forensic-deletion corroboration). Fixed `INDXParse.py <path>` subprocess; parses its `,\t`-delimited table. INSTALL-FIRST (`pip install INDXParse`). `$INDXPARSE_BIN` then PATH.

### oe_dbx_parse
Args: `{case_id, artifact_path}`
Returns: `{is_oe_dbx, is_message_store, message_subject_count, subjects[], senders[], newsgroups[], hacking_newsgroups[]}`
Use when: a carved Outlook Express `.dbx` mail/news store is in scope. **Pure Rust, in-process — no subprocess, no external binary** (no other parser reads DBX). Validates the OE file signature (`CF AD 12 FE`) before walking the store and extracts RFC822 `Subject`/`From`/`Newsgroups` headers. HONEST SCOPE: header-level only — no message bodies and no deleted-message recovery — so a recovered subject or newsgroup CONFIRMS store *content* (a mail/news-artifact fact at header granularity), never execution; intent stays a separate `hypothesis:` layer.

### thumbcache_parse
Args: `{case_id, thumbcache_path, limit?}`
Returns: `{format: "olecfb_xp"|"cmmm", entries[]: {index?, cache_entry_hash?, original_filename?, modified_iso?, data_size_bytes, content_sha256?}, entries_seen, parse_errors[]}`
Use when: a carved XP `Thumbs.db` or Vista+ `thumbcache_*.db` / `iconcache_*.db` (Explorer thumbnail cache) is in scope. **Pure Rust, in-process** (`cfb` crate for the XP OLE container; hand-rolled CMMM records for Vista+). Format detected by magic bytes, never filename. HONEST SCOPE: a cache entry CONFIRMS an image *existed and was rendered by Explorer* (surviving file deletion) — it is viewing/presence evidence at cache granularity, never execution and never proof the user opened the file at a specific time; XP catalog `modified_iso` is the cache's own timestamp. Fixture-tested only until exercised on a real image.

### hashset_lookup
Args: `{case_id, hashes[] (hex MD5/SHA1/SHA256, ≤10k), hashset_paths?[]: {path, disposition: known_good|known_bad, name?}}`
Returns: `{results[]: {hash, disposition: known_good|known_bad|unknown, matched_sets[]}, sets_loaded[], hashes_checked}`
Use when: triaging extracted/recovered file hashes against NSRL known-good or operator known-bad sets. **Pure Rust, in-process** — text sets stream (never loaded whole), SQLite sets (NSRL RDS v3 `FILE` schema or generic `hashes(hash)`) open read-only-immutable, parameterized queries only. Defaults to `$FINDEVIL_HASHSET_DIR/known_good/**` + `known_bad/**`; no sets configured degrades to all-`unknown`, never an error. HONEST SCOPE: `known_good` supports demotion/suppression, `known_bad` is a lead requiring corroboration — a hash match alone is never execution evidence. Fixture-tested only; not yet run against a full NSRL RDS download.

### email_parse
Args: `{case_id, artifact_path}`
Returns: `{is_email, format: "eml"|"mbox", message_count, messages[]: {from?, to[], subject?, date?, attachment_names[], attachment_count}, unique_senders[], unique_recipients[], subjects[], attachment_names[]}`
Use when: a loose `.eml` message or `mbox` archive is in scope (no other tool reads them; `oe_dbx_parse` is Outlook Express `.dbx`). **Pure Rust, in-process** (`mail-parser`). HONEST SCOPE: headers + attachment **filenames** only — it never decodes or writes body/attachment payloads, so a surfaced sender/subject CONFIRMS mail *content* at header granularity, never execution or exfil. Deterministic for replay.

### exif_parse
Args: `{case_id, artifact_path}`
Returns: `{has_exif, camera_make?, camera_model?, software?, datetime_original?, datetime?, gps_decimal?: [lat, lon], artist?, copyright?, other_fields[], field_count}`
Use when: a user-content image (JPEG/TIFF/HEIF/…) may carry EXIF — camera/software fingerprint, capture timestamps, and GPS geolocation. **Pure Rust, in-process** (`kamadak-exif`); reads clean ASCII values (never quoted). HONEST SCOPE: metadata is a device/location LEAD (a photo's GPS is where the shot was taken, not where a person was); no pixel bytes leave the tool. Feeds on carved/extracted images.

### bits_parse
Args: `{case_id, artifact_path}`
Returns: `{format: "binary_qmgr"|"ese_qmgr_db"|"unknown", is_bits, ese_requires_external_tool, url_count, urls[], local_path_count, local_paths[], suspicious_url_count}`
Use when: a Windows BITS state store (`qmgr*.dat` legacy binary, or `qmgr.db` ESE) is in scope — BITS is abused for stealthy download + persistence (MITRE **T1197**). **Pure Rust, in-process**; conservatively extracts embedded UTF-16LE URLs/paths from the legacy format and DETECTS (does not decode) the Win10 1709+ ESE `qmgr.db`. HONEST SCOPE: reports strings actually present (not decoded job state); raw-IPv4 hosts + executable payloads are flagged as T1197 leads, never proof.

### srum_parse
Args: `{case_id, artifact_path}`
Returns: `{esedbexport_available, table_found, row_count, rows[]: {app_id, interface_luid?, bytes_sent, bytes_recvd, timestamp?}, total_bytes_sent, total_bytes_recvd, top_talkers[]}`
Use when: the SRUM database `SRUDB.dat` is in scope — per-app network BytesSent/BytesRecvd per hour, the closest Windows has to a built-in data-transfer-volume ledger. Two-stage: `esedbexport` (libesedb) dumps the ESE tables, then the network table is decoded in Rust. INSTALL-FIRST — degrades to `esedbexport_available=false`. `$FINDEVIL_ESEDBEXPORT_BIN` then PATH. HONEST SCOPE: byte volume is an exfil-VOLUME lead requiring finding-specific corroboration, never proof of exfiltration.

### pst_parse
Args: `{case_id, artifact_path}`
Returns: `{pffexport_available, message_count, messages[]: {from?, to[], subject?, delivery_time?, folder?, recovered}, recovered_deleted_count, unique_senders[], subjects[]}`
Use when: an Outlook `.pst`/`.ost` mail store is in scope (no other tool reads them). `pffexport -m all` (libpff) also RECOVERS deleted/orphaned messages from unallocated PST space. INSTALL-FIRST — degrades to `pffexport_available=false`. `$FINDEVIL_PFFEXPORT_BIN` then PATH. HONEST SCOPE: metadata only (from/to/subject/date/folder + recovered flag), never bodies; a recovered message CONFIRMS mail content at header granularity.

### wmi_persist_parse
Args: `{case_id, artifact_path}`
Returns: `{is_wmi_repository, consumer_classes_found[], filter_count, binding_count, command_strings[], script_strings[], persistence_pattern_present}`
Use when: the WMI CIM repository `OBJECTS.DATA` is in scope — WMI permanent event subscriptions are a fileless persistence primitive (MITRE **T1546.003**). **Pure Rust, in-process, conservative** (no `python-cim` dependency): scans for the persistence class-name signatures (`__EventFilter`, `CommandLineEventConsumer`/`ActiveScriptEventConsumer`, `__FilterToConsumerBinding`) and the command/script strings adjacent to a consumer. HONEST SCOPE: reports strings present (not decoded CIM objects); the consumer+filter+binding triad is flagged as a persistence LEAD, never proof the subscription is active.

### vss_list
Args: `{case_id, image_path}`
Returns: `{vshadowinfo_available, has_shadow_store, store_count, stores[]: {store_number, identifier?, creation_time?}}`
Use when: enumerating Windows Volume Shadow Copies in a volume image — snapshots often still hold a file/registry value deleted or changed on the live volume. `vshadowinfo` (libvshadow). INSTALL-FIRST — degrades to `vshadowinfo_available=false`. `$FINDEVIL_VSHADOWINFO_BIN` then PATH.

### vss_mount
Args: `{case_id, image_path, mount_point?}`
Returns: `{vshadowmount_available, mount_id, status, mount_point, shadow_store_paths[], command}`
Use when: mounting a volume image's shadow copies so a snapshot can be analyzed like any other volume (and diffed against the live one — anti-forensics signal). `vshadowmount` (libvshadow) exposes each snapshot as a `vssN` raw-volume file; returns a case-scoped `mount_id` the normal disk tools read unchanged. Read-only. INSTALL-FIRST — degrades to `vshadowmount_available=false`. `$FINDEVIL_VSHADOWMOUNT_BIN` then PATH.

---

## Python crypto + ACH tools (`findevil-agent-mcp`)

### audit_append
Args: `{path, kind, payload}`
Returns: `{seq, ts, kind, prev_hash, line_hash}`
Use when: writing any record to the hash-chained audit log. Every tool call, finding emission, and agent message goes here. The `prev_hash` is auto-computed.

### audit_verify
Args: `{path}`
Returns: `{ok: bool, record_count, error}`
Use when: replaying an audit chain to confirm integrity. Walk every `prev_hash` SHA-256 link; first mismatch reports the seq + field. The `manifest_verify` tool calls this internally.

### manifest_finalize
Args: `{case_id, run_id, started_at, audit_log_path, output_path, signer, extra?}`
Returns: `{leaf_count, merkle_root_hex, signature_payload_sha256}` — the on-disk manifest also has `signature.cert_fingerprint`, `leaves[]`, `finalized_at`
Use when: closing a case. Builds the rs_merkle tree over every audit-log leaf, signs the canonical body — `signer="ed25519"` (default: real local signature, verifies offline), `"sigstore"` (identity + transparency log; customer-release tier), or `"stub"` (explicit dev placeholder) — and writes `run.manifest.json`. Terminal crypto-custody step under Amendment A5 (the OpenTimestamps + Bitcoin anchor that previously followed was removed — see `docs/cryptographic-attestation.md` for the FRE 902(14) trade-off).

### manifest_verify
Args: `{manifest_path, audit_log_path?}`
Returns: `{overall: bool, audit_chain_ok, merkle_root_ok, signature_present, ...}`
Use when: any third party wants offline verification. Replays the audit chain → recomputes the Merkle root from `leaves[]` → checks signature presence and reports `signature_kind` / `signature_verified`. Ed25519 signatures verify cryptographically offline; Sigstore bundles are recorded for identity-policy-aware verification; stub bundles are explicit placeholders. Tampering with `merkle_root_hex` produces a precise diagnostic naming both the declared and rebuilt roots.

### verify_finding
Args: `{finding, tool_call_index, findevil_mcp_command: list[str]}`
Returns: `{action, finding_id, reason, replay_tool_name, replay_expected_sha256, replay_actual_sha256, replay_matched, replay_error}`
Use when: re-running a finding's cited `tool_call_id` to confirm the original output's SHA-256 still matches. The verifier spawns its own short-lived findevil-mcp child process — same binary, same args, same hash, byte-for-byte. Budget 30s/finding per Spec #2 §8.1.

**Fact-fidelity (entailment).** A SHA-match proves the finding points at real, unchanged evidence — NOT that it READ that evidence right. So a CONFIRMED/INFERRED finding MUST declare `asserted_values`: the structured fact(s) it claims, each `{path, expected, match}` where `path` walks the cited tool's output JSON (e.g. `entries[*].values[*].name`, `run_count`) and `match` ∈ `exact | contains | iso_ts | int | record`. After the SHA reproduces, the verifier deterministically **re-extracts** each asserted value from the re-run output; a value that is not actually there — a misread laundered through a valid `tool_call_id` — **rejects** a CONFIRMED finding and **downgrades** a lower tier, the same policy as output drift. The matched evidence value is recorded on the approval, so the chain carries a **server-read fact, not your transcription**. HONEST SCOPE: structured-value fidelity only; an interpretive claim ("this is malicious") has no deterministic ground truth and stays a tiered `hypothesis:` lead.

### detect_contradictions
Args: `{case_id, pool_a, pool_b, resolution_required?: bool}`
Returns: `{contradictions[], pool_a_count, pool_b_count}`
Use when: surfacing Pool A vs Pool B disagreements BEFORE judging. Same-`tool_call_id` findings with different `confidence` levels or contradicting `mitre_technique` labels emit. **Surface the contradictions first; the analyst sees them before the judge merges.**

### judge_findings
Args: `{pool_a_findings, pool_b_findings, pool_a_verifier_actions, pool_b_verifier_actions, budget_seconds?}`
Returns: `{merged[], budget_exceeded: bool, budget_detail}`
Use when: credibility-weighted merge after verification. Each pool's score = `base_confidence × pool_credibility`. Pools that produced corroborating CONFIRMED findings build credibility; pools that produced HYPOTHESIS-only get downweighted.

### correlate_findings
Args: `{findings}`
Returns: `{refined[], outcomes[]}` where each outcome is `{finding_id, action: 'kept'|'downgraded'|'rejected', reason}`
Use when: enforcing the SOUL.md ≥2-artifact-class rule. A finding claiming "X executed" must cite ≥2 distinct artifact classes (Prefetch + Amcache+ShimCache, or EDR + memory). Single-source claims auto-downgrade.

### memory_remember
Args: `{store_path, case_id, kind, key, value, sha256, ts?, case_path?, audit_log_path?}`
Returns: `{case_id, kind, key, sha256}`
Use when: a Finding has been marked `CONFIRMED` by the judge and the IOC / hash / TTP / hostname / one-line summary is worth surfacing in future investigations on different cases. Hermes-pattern (A3 §2.2). The `store_path` is the session-constant `MEMORY_STORE_PATH` resolved by the supervisor at session start; `kind` ∈ `{ioc, hash, ttp, hostname, finding_summary}`; `sha256` is `sha256:` + 64 lowercase hex. Skip for HYPOTHESIS-tier — the memory chain only remembers things the army would stand behind. When `audit_log_path` is set, a `memory_remember` record is appended to the case audit JSONL as process provenance — hash-chained but **never a Merkle leaf and never a `tool_call_id`** (memory is never evidence).

### memory_recall
Args: `{store_path, query, kind?, limit?, audit_log_path?}`
Returns: `{hits: [{case_id, kind, key, value, sha256, ts, confidence}, …]}`
Use when: BEFORE drafting a Finding, to check whether you've seen this IOC / hash / TTP / hostname in a previous investigation. Hits become a `prior_observations` field on the Finding for prioritization and context only; a prior-case hit is not current-case evidence and must not satisfy the SOUL.md >=2 artifact-class rule. When `audit_log_path` is set, a `memory_recall` record is appended as process provenance — hash-chained but **never a Merkle leaf and never a `tool_call_id`**. Hits are returned ordered by BM25 relevance × 90-day decay, descending confidence. **Query semantics: exact phrase match** — the query is phrase-quoted before hitting FTS5, so `evil.com` and `T1059.001` are safe; multi-word queries (`powershell encoded`) become exact-phrase searches and may return zero hits even when both tokens exist separately. Pass single tokens for broad recall.

### pool_handoff
Args: `{audit_path, from_role, to_role, payload, correlation_id?}`
Returns: `{acp_version, from_role, to_role, correlation_id, ts}`
Use when: one role/pool needs to formally hand structured findings or context to another, distinct from natural-language supervisor messaging. Records a `kind="acp_handoff"` line in the case audit JSONL with the IBM-ACP envelope shape (Linux Foundation spec, A3 §2.3). Canonical use sites: **verifier → judge** (always, for each verdict); **Pool A → Pool B** (when handing exfil-staging context that Pool A surfaced while looking for persistence); **supervisor → any role** (when assigning a structured sub-task that includes payload data the receiver needs to act on). The `correlation_id` lets downstream roles thread replies — pass it on the handoff that originates a thread, then pass the same id on subsequent handoffs about the same finding.

### expert_miss_capture
Args: `{case_id, finding_id?, edit_type, edit_text, expert_name?, ledger_path}`
Returns: `{seq, ts, line_hash, prev_hash, github_issue_url?}`
Use when: a human expert edits the auto-drafted PDF before release. Records a `kind="expert_miss"` line in the hash-chained `expert_misses.jsonl` ledger so corrections become connector, playbook, rule, QA, escalation, or language follow-up work. GitHub issue creation is default-off and only attempted when `FINDEVIL_MISS_GH_ENABLED=1`; `FINDEVIL_MISS_GH_REDACT=1` redacts case IDs in issue text.

### accuracy_compare
Args: `{case_dir, golden_path?, audit_log_path?, coverage_manifest_path?}`
Returns: `{case_id, recall_percent, precision_percent, f1, hallucination_rate, negative_coverage, verdict_match, pass, matched[], unmatched[], extra[], false_positives[], ...}`
Use when: a finished Case's `verdict.json` needs to be scored against a curated golden (TP/FP/FN, precision/recall/F1, hallucination rate). Read-only ground-truth accuracy diagnostic only. HONEST SCOPE: **this is a DIAGNOSTIC, never a Finding** — it emits no `tool_call_id`, satisfies no Finding citation, mutates no evidence, and is never a Merkle leaf; it measures how the run scored against ground truth and never adds to or alters the Verdict.

### find_ai_signatures
Args: `{case_id, text?, paths?, categories?, limit?, preview_chars?}` — provide at least one of `text` / `paths`
Returns: `{case_id, confidence_tier: "HYPOTHESIS", lead_only: true, disclaimer, matches[], sources_scanned, chars_scanned, signatures_evaluated, read_errors[], truncated}` where each match is `{signature_id, category, description, source, occurrences, first_offset, preview}`
Use when: you want to know whether **LLM-assisted tooling or an autonomous agent framework** is fingerprinted in a recovered script, log slice, note, or text artifact. Typed read-only signature scanner (NOT a filesystem/shell surface): it reads only the inline `text` and the explicit `paths` you pass, opens files for read only, and never mutates evidence. The curated GENERAL signature list keys on LLM output boilerplate (refusals, "as an AI language model"), agent-framework module names (LangChain/LangGraph, LlamaIndex, Auto-GPT/BabyAGI, CrewAI, AutoGen, Semantic Kernel), the ReAct scratchpad shape, LLM API-client fingerprints (`api.openai.com`, `api.anthropic.com`, SDK imports, `system_fingerprint`), prompt scaffolding, and general model-family identifiers (`gpt-`/`claude-`/`llama-`/`mistral-`/`gemini-`) — no image-specific values. HONEST SCOPE: every match is a **HYPOTHESIS-tier LEAD** (`confidence_tier="HYPOTHESIS"`, `lead_only=true`). It suggests AI/agent involvement; it is **never** execution proof and **never** an attribution. A signature alone never satisfies the SOUL.md >=2-artifact-class corroboration gate — pair it with an independent artifact class before raising confidence. A file that cannot be read is reported in `read_errors` and skipped.

---

## Invariants

- **Every call emits a `tool_call_id`.** Findings cite it. Verifier vetoes uncited.
- **Every fact-bearing Finding is checkable.** A CONFIRMED finding declares `asserted_values` — the structured value(s) it claims — which the verifier re-extracts from the cited output and rejects on a misread. An INFERRED finding is a cross-fact inference (e.g. DKOM = pslist 0 AND psscan N>0): it has no single re-extractable value, so it either declares `asserted_values` or cites the confirmed facts it rests on (`derived_from`), whose own fidelity is checked. Interpretive claims have no deterministic ground truth — they stay `hypothesis:` and human-owned.
- **No tool mutates evidence.** All reads operate on read-only mounts; original images stay untouched.
- **No `execute_shell`.** The narrow typed surface above is the entire verb set. Adding shell pass-through breaks the architectural-guardrail story.
- **AGPL/GPL backing tools (Hayabusa, Volatility3, Velociraptor, YARA core) are subprocess-only — never linked.** Apache-2.0 license clean.
- **All timestamps UTC, ISO-8601, trailing `Z`.** SHA-256 preferred over MD5.
