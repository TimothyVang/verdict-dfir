> **Status: ACTIVE.** Operator-facing per-tool guidance for the under-documented corners of the typed MCP surface — the args, hive locations, scope caps, and failure modes that the per-tool entries in `agent-config/TOOLS.md` summarize but don't expand. Read this before driving these tools on a Case; read `agent-config/MEMORY.md` for the Tier-1 artifact caveats it builds on.

Scope: the 45 product tools (32 Rust `findevil-mcp` + 13 Python `findevil-agent-mcp`) are the only audit-chained surface; `.mcp.json` registers 6 servers total (4 non-product, incl. `qmd` dev-memory). Canonical inventory and pins:

- Tool inventory & server map → [`docs/reference/mcp-and-tools.md`](../reference/mcp-and-tools.md)
- Crate/binary versions → [`docs/reference/dependencies.md`](../reference/dependencies.md)
- Env-var overrides (`$VOLATILITY_BIN`, `$VELOCIRAPTOR_BIN`, `$TSHARK_BIN`/`$ZEEK_BIN`, YARA rule paths) → [`docs/reference/environment-variables.md`](../reference/environment-variables.md)

Every successful call carries `_meta.output_sha256`; every Finding cites a `tool_call_id`. Nothing below changes that contract.

---

## 1. `zeek_summary` — Zeek TSV roll-up

Pure in-process parser of Zeek TSV logs (no `zeek` binary needed — that's `pcap_triage`'s job). Point `zeek_path` at a single `conn.log`/`dns.log`/etc. or a **directory**, and it walks the directory collecting Zeek log files.

| Arg | Default | Notes |
|---|---|---|
| `case_id` | — | for audit correlation; not parsed |
| `zeek_path` | — | file OR directory of Zeek TSV logs |
| `limit` | `100_000` rows | cap across all files; `rows_seen` reports the pre-cap total |

Returns counts (`conn_count`, `dns_count`, `http_count`, `tls_count`), `top_hosts` / `top_dns_queries` / `top_http_hosts` (top 10 each), and `notable_connections` (per-conn `ts/src/dst/dst_port/proto/service/orig_bytes/resp_bytes/conn_state`).

Operator notes:
- These are **network telemetry leads, not exfil proof.** A `top_dns_queries` hit or a long-lived `conn_state=S1` flow is a lead — corroborate with an endpoint-side artifact class (`sysmon_network_query`, Prefetch of the process that opened the socket) before any exfil Finding. Per `MEMORY.md`, network rows are finding-support, not findings.
- `parse_errors` counts malformed TSV lines skipped; a nonzero value on a truncated capture is normal, not tamper.
- If you have raw PCAP rather than Zeek logs, run `pcap_triage` (which can shell out to `zeek`) first, then feed its output here.

---

## 2. `sysmon_network_query` — Sysmon EID 3 outbound connections

In-process EVTX parse of the Sysmon Operational channel for network-connection events. **Event ID 3 is the default** (`event_ids` unset → `[3]`); pass `event_ids` only to widen.

| Arg | Default | Notes |
|---|---|---|
| `evtx_path` | — | the Sysmon Operational `.evtx` (not Security.evtx) |
| `event_ids` | `[3]` | override to include other Sysmon EIDs |
| `since_iso` / `until_iso` | unset | ISO-8601Z window filter |
| `image_contains` | unset | case-insensitive substring on `Image` |
| `destination_ip` / `destination_port` | unset | exact-match post-filters |
| `limit` | `10_000` | `records_seen` reports records scanned pre-cap |

Each row normalizes `ts, record_id, event_id, computer, image, process_id, protocol, source_ip, source_port, destination_ip, destination_port, destination_hostname, user` plus a raw `fields` map.

**ProcessGuid vs PID (read this).** The row surfaces `process_id` (PID). Per `MEMORY.md`, the Sysmon **ProcessGuid is the correlation key, not the PID** — PIDs are reused within a boot, so a PID alone does not bind a connection to a specific `Image`/process lifetime. When you need to tie an EID 3 connection back to the EID 1 process-creation that spawned it, pull `ProcessGuid` out of the raw `fields` map and join on that, not on `process_id`.

Operator notes:
- RFC1918 `destination_ip` is almost always benign; weight external destinations.
- This is endpoint-side evidence; it pairs with `zeek_summary`/`pcap_triage` (wire-side) for the two-source exfil story.

---

## 3. `registry_query` — offline hive reader

Reads an offline hive **primary file** with no mount, normalizing all value types to strings so you can keyword-match persistence indicators directly.

### Hive locations

| Hive | On-disk path (under a mounted volume) | What lives there |
|---|---|---|
| `SYSTEM` | `Windows/System32/config/SYSTEM` | Services, `ControlSet00N`, ShimCache, BAM, mounted devices |
| `SOFTWARE` | `Windows/System32/config/SOFTWARE` | Run/RunOnce, IFEO, AppInit_DLLs, uninstall, install dates |
| `SAM` | `Windows/System32/config/SAM` | local account database |
| `SECURITY` | `Windows/System32/config/SECURITY` | LSA secrets, audit policy |
| `NTUSER.DAT` | per-user `Users/<name>/NTUSER.DAT` | per-user Run keys, shellbags, MRUs, UserAssist |
| `UsrClass.dat` | `Users/<name>/AppData/Local/Microsoft/Windows/UsrClass.dat` | per-user shellbags (classes) |

The tool also accepts any `*.dat` file by extension. An optional `HKLM\` / `HKCU\` / `HKU\` (or the long `HKEY_*` forms) prefix on `key_path` is stripped; `\` and `/` are both accepted as separators.

### Transaction logs are NOT auto-merged

`.LOG1` / `.LOG2` transaction logs are **not loaded.** If the host was shut down dirty, the primary hive can be stale and the newest persistence write may live only in the log. The tool reads the primary file as-is; if you suspect uncommitted writes, **pre-merge the logs externally** (e.g. `reglookup`/`hivex`-style replay) and pass the merged hive. Do not assume the primary is current.

### Recursion + caps

| Arg | Default | Notes |
|---|---|---|
| `key_path` | — | empty string returns the hive root key |
| `recursive` | `false` | depth-first descent into all subkeys |
| `limit` | `10_000` entries | hard cap on emitted entries |
| `depth cap` | **16** (fixed) | `MAX_RECURSION_DEPTH`; deeper subtrees are not visited |

`recursive=true` is bounded by **both** the entry `limit` and the **fixed depth cap of 16** — a pathologically deep key (or a Services tree wider than the limit) will be truncated silently. For a known-large path like `ControlSet001\Services`, raise `limit` and read `keys_visited` to confirm you saw the whole subtree. Each entry returns `key_path, last_write_time_iso` (UTC ISO-8601Z; `None` on a zero filetime), `values[]` (`name`, `value_type`, `data_str`), and direct `subkeys[]`. Value formatting: `REG_MULTI_SZ` is `|`-joined; `REG_DWORD`/`REG_QWORD` are decimal; `REG_BINARY` (and unknown types) are lowercase hex truncated at 4096 bytes with a `…[truncated, full N bytes]` tag.

---

## 4. `vel_collect` — Velociraptor artifact trampoline

Generic wrapper over `velociraptor artifacts collect <artifact> --format jsonl [--args k=v ...]`. The wrapper bakes in **no** artifact knowledge — you pick the artifact name and its parameters.

### Artifact dotted-path selection

`artifact` must be a **dotted ASCII path** (`Windows.Forensics.Prefetch`, `Generic.Forensic.LocalHashes`, `Windows.Persistence.Services`). The validator (`is_valid_artifact_name`) accepts only `[A-Za-z0-9_]` segments joined by single dots — no leading/trailing dot, no double dot, **no spaces, slashes, semicolons, or `--flags`**. That last point is the injection guard: the artifact name becomes argv, so `Has--Flag` or `Has/Slash` is rejected up front. Discover valid names out-of-band (`velociraptor artifacts list`) — this tool will not enumerate them for you.

### Arg validation (keys strict, values free)

`args` is a `key=value` map. **Keys** are validated to `[A-Za-z_][A-Za-z0-9_]*` (≤64 chars) — a key containing a dash or `=` is rejected because that's the only way to smuggle a flag into argv. **Values are deliberately NOT sanitized**: Velociraptor unquotes its own `--args` values and arbitrary path/glob content is the whole point. So `{"Path": "/mnt/case/Users/*/NTUSER.DAT"}` is fine; `{"max-size": "10"}` is rejected (dash in key — use `max_size`).

| Arg | Default | Notes |
|---|---|---|
| `artifact` | — | dotted path; validated |
| `args` | none | `key=value` map; keys validated, values passed through |
| `limit` | `10_000` rows | `rows_seen` reports the pre-cap total |

Rows are **free-form** (`{artifact, fields}`) — every artifact has its own column shape; do not assume a fixed schema. Output is parsed as JSONL with a single-JSON-array fallback for older Velociraptor builds.

---

## 5. `yara_scan` — YARA-X in-process scan

Compiles a rules file (or a directory of `.yar`/`.yara`/`.yarx`, merged into one ruleset) and scans `target_path`. Backed by `yara-x = 1.12.0` (pinned: 1.13+ needs rustc 1.89, repo is on 1.88).

| Arg | Default | Notes |
|---|---|---|
| `target_path` | — | file or directory |
| `rules_path` | — | rules file or directory of rules files |
| `recursive` | `false` | only meaningful when `target_path` is a directory |
| `limit` | `1_000` matches | total across all scanned files |

Each match returns `file_path, rule_name, namespace, tags[]`, and `pattern_matches[]` (`identifier`, `offset`, `length`, 64-byte `preview_hex`). `namespace` is typically the rules-file basename.

### Core tier vs extended/community tier — the FP tradeoff

- Prefer **YARA-Forge `core` tier** (curated, low false-positive). The `extended` and `community` tiers cast a wider net and are **FP-prone**: a `community` hit on a packer stub or a generic string is a lead, not a Finding.
- **Always cite the `rule_name`** (and namespace) in the Finding — "yara_scan matched" is uncitable; "rule `MAL_Cobalt_Strike_Beacon` (namespace `core`) hit at offset 0x…" is. A malfind/YARA preview is an IOC/string lead only and never identifies who ran code (per `MEMORY.md`).
- Rule-file overrides live in `$FIND_EVIL_MEMORY_YARA_RULES` / `$FIND_EVIL_DISK_YARA_RULES` — see [environment-variables.md](../reference/environment-variables.md).

---

## 6. Expected-failure / troubleshooting table

These are the conditions that look like results but aren't — read each before escalating a Finding.

| Symptom | Tool(s) | What it actually means | Operator action |
|---|---|---|---|
| **`vol_pslist` processes=0 + `vol_psscan` processes>0** | `vol_pslist` / `vol_psscan` | Could be T1014 (DKOM unlink) OR an **acquisition smear / kernel-global read failure**. Disambiguate first. | If `psscan` recovered **core OS singletons** (System/csrss/lsass) only, a **duplicate `System` (PID 4)** EPROCESS appears, or `windows.info` shows **`KeNumberProcessors`=0** → the active-list walk failed image-wide = **smear**. Label **HYPOTHESIS**, not T1014. Require ≥2 artifact classes before asserting Rootkit; corroborate with `vol_psxview`. Do not fold the three views — divergence is the signal. |
| **`BinaryNotFound`** | `vol_*`, `hayabusa_scan`, `vel_collect`, `pcap_triage` | The external tool isn't on PATH and its `$*_BIN` env var is unset. This is an **environment limitation, NOT evidence absence.** | Set the override (`$VOLATILITY_BIN`, `$HAYABUSA_BIN`, `$VELOCIRAPTOR_BIN`, `$TSHARK_BIN`/`$ZEEK_BIN`) or install the tool ([dependencies.md](../reference/dependencies.md)). Never report "no processes/no hits" — report the gap. The Verdict stays **INDETERMINATE** for that lane, not `NO_EVIL`. |
| **Nonzero `parse_errors`** | `evtx_query`, `mft_timeline`, `usnjrnl_query`, `sysmon_network_query`, `registry_query`, `zeek_summary` | Some records were malformed/unsupported and **skipped** — `records_seen`/`rows_seen` still counts them, the row list does not. | Read it as a coverage caveat: a high ratio of `parse_errors` to `records_seen` means partial coverage; surface it in the Finding's confidence, don't silently treat the row list as complete. A few errors on a large EVTX/journal is normal. |
| **Empty `memory_recall` hits** | `memory_recall` | A **useful signal**, not a failure — this IOC/hash/TTP has not been CONFIRMED in a prior Case. | Proceed on current-Case evidence. Note: query semantics are **exact-phrase** — a multi-word query (`powershell encoded`) becomes one phrase and may return zero even when both tokens exist separately. **Pass single tokens** (`certutil`, `T1059.001`) for broad recall before concluding "never seen." A prior-Case hit is context only; it never satisfies the ≥2-artifact-class rule. |
| **`SubprocessFailed` (nonzero exit)** | `vel_collect`, `vol_*`, `hayabusa_scan`, `pcap_triage` | The external tool ran but errored — check `stderr_tail` (capped 4096B) in the error. | Common causes: wrong artifact params, unreadable evidence path, wrong volatility symbol set. Fix the args; this is a tool error, not a Finding. |
| **`InvalidArtifactName` / `InvalidArgName`** | `vel_collect` | The boundary validator rejected an artifact name or arg **key** (injection guard) — nothing ran. | Use a dotted path with no spaces/slashes/flags; use identifier-shape arg keys (`max_size`, not `max-size`). Arg **values** are unrestricted. |
| **`OutputParse`** | `vel_collect` | Velociraptor stdout was neither JSONL nor a JSON array — usually a **version mismatch**. | Confirm the `velociraptor` build; the wrapper expects `--format jsonl`. |
| **Empty result on a custody-only disk** | any disk tool after `case_open` | `case_open` alone is an **analysis limitation**, not a clean Verdict. | Per `MEMORY.md`, this is **not** `NO_EVIL` — supply mounted artifacts or stay **INDETERMINATE**. `covered_no_finding` means scoped tools ran without qualifying evidence; it is not "cleared" or "disproven." |

---

## 7. See also

- [`docs/reference/mcp-and-tools.md`](../reference/mcp-and-tools.md) — full 45-tool inventory + the 6-server map.
- [`docs/reference/dependencies.md`](../reference/dependencies.md) — external-tool versions and install commands for the `BinaryNotFound` fix.
- [`docs/reference/environment-variables.md`](../reference/environment-variables.md) — every `$*_BIN` and YARA rule-path override.
- `agent-config/TOOLS.md` — the canonical per-tool args/returns/caveats this doc expands.
- `agent-config/MEMORY.md` — Tier-1 artifact-semantics caveats every Finding leans on.
