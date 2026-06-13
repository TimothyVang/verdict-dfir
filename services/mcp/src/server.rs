//! Stdio JSON-RPC 2.0 server for `findevil-mcp`.
//!
//! Hand-rolled rather than `rmcp`-based for two reasons:
//!
//! 1. **Wire-format stability.** Spec #2 commits to MCP 2024-11-05.
//!    A manual implementation pinned to that protocol revision is
//!    unaffected by future rmcp API churn.
//! 2. **Mirrored Python pattern.** The `findevil-agent-mcp` Python
//!    server uses the same line-delimited JSON-RPC dispatch shape.
//!    Two languages, one wire format, one mental model.
//!
//! Wire format (per the MCP spec):
//!
//! * One JSON object per line on stdin / stdout.
//! * Logs go to stderr only — anything on stdout that is not a
//!   valid JSON-RPC response corrupts the protocol stream.
//!
//! Methods handled:
//!
//! * `initialize` → echoes protocol version, advertises `tools` capability.
//! * `notifications/initialized` → no-op acknowledgement.
//! * `tools/list` → emits the tool catalog with JSON Schemas.
//! * `tools/call` → validates arguments, dispatches to the handler,
//!   returns content as a single `text` block of canonical JSON.
//!
//! Errors follow JSON-RPC 2.0:
//! * `-32601` method-not-found
//! * `-32602` invalid-params (input failed Pydantic-equivalent validation)
//! * `-32603` internal-error (handler panicked or returned an error)
//!
//! Spec #2 invariant: every successful tool response carries the
//! tool's typed output and a SHA-256 of the raw JSON text. The
//! SHA-256 lives in the `_meta` extension envelope so MCP clients
//! that only read `content[0].text` still get the typed payload.

use std::io::{BufRead, BufReader, Read, Write};

use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::tools::{
    browser_history::browser_history,
    case_open,
    disk::{disk_extract_artifacts, disk_mount, disk_unmount},
    evtx_query::evtx_query,
    ez_parse::ez_parse,
    hayabusa_scan::hayabusa_scan,
    mft_timeline::mft_timeline,
    pcap_triage::pcap_triage,
    prefetch_parse::prefetch_parse,
    registry_query::registry_query,
    sysmon_network_query::sysmon_network_query,
    usnjrnl_query::usnjrnl_query,
    vel_collect::vel_collect,
    vol_malfind::vol_malfind,
    vol_pslist::vol_pslist,
    vol_psscan::vol_psscan,
    vol_psxview::vol_psxview,
    vol_run::vol_run,
    yara_scan::yara_scan,
    zeek_summary::zeek_summary,
    BrowserHistoryInput, CaseOpenInput, DiskExtractArtifactsInput, DiskMountInput,
    DiskUnmountInput, EvtxQueryInput, EzParseInput, HayabusaInput, MftInput, PcapTriageInput,
    PrefetchInput, RegistryInput, SysmonNetworkInput, UsnJrnlInput, VelCollectInput,
    VolMalfindInput, VolPslistInput, VolPsscanInput, VolPsxviewInput, VolRunInput, YaraInput,
    ZeekSummaryInput,
};
use crate::CRATE_VERSION;

/// MCP protocol revision we speak. Hard-coded; any breaking change
/// ships behind a code update + spec amendment, not silent drift.
const PROTOCOL_VERSION: &str = "2024-11-05";

const SERVER_NAME: &str = "findevil-mcp";

// JSON-RPC standard error codes (kept for reference; we use INVALID_PARAMS
// for unknown methods/tools so the client gets actionable messages).
const ERR_INVALID_PARAMS: i64 = -32602;
const ERR_INTERNAL: i64 = -32603;

/// Tool descriptor — name, human-readable description, schema producer,
/// the dispatch closure, plus MCP annotations that agent UIs render
/// (e.g. a "destructive" badge or a network-icon).
struct ToolEntry {
    name: &'static str,
    description: &'static str,
    /// Behavior hints exposed via `annotations` on `tools/list`. Per
    /// the MCP 2024-11-05 spec these are advisory — clients use them
    /// to choose whether to auto-approve / surface warnings / batch.
    annotations: ToolAnnotations,
    /// Returns the JSON Schema for the input type. Computed lazily so
    /// the server only pays the schemars cost on `tools/list`.
    schema: fn() -> Value,
    /// Validates the arguments and returns the typed output as JSON.
    /// On invalid input returns `Err(ToolError::InvalidParams(_))`;
    /// on handler failure returns `Err(ToolError::Internal(_))`.
    handler: fn(Value) -> Result<Value, ToolError>,
}

/// MCP `tools.annotations` metadata. All four hints are *hints* —
/// behavior is unchanged whether they are honoured or not. The point
/// is to give the calling UI (Claude Code, Claude Desktop, `ChatGPT`)
/// enough metadata to render the right badge / confirmation prompt.
//
// clippy::struct_excessive_bools is disabled here because the MCP
// 2024-11-05 spec enumerates exactly four boolean hints (readOnly,
// destructive, idempotent, openWorld) and the wire format is bool-
// per-hint. Refactoring to enums would obscure the 1:1 mapping.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy)]
struct ToolAnnotations {
    /// Short human-readable display name (e.g. "Open Evidence Case").
    title: &'static str,
    /// True when the tool does not modify the environment (most of
    /// our DFIR tools are read-only over evidence; only `case_open`
    /// writes the case directory).
    read_only: bool,
    /// True if the tool may make destructive changes that cannot be
    /// undone. Always false here — Find Evil! never deletes evidence
    /// or its derivatives.
    destructive: bool,
    /// True when calling the tool repeatedly with the same input
    /// produces the same output. `case_open` mints a fresh UUID4
    /// per call so it's marked false; everything else is pure.
    idempotent: bool,
    /// True if the tool may interact with external systems (network).
    /// Only `vel_collect` qualifies — Velociraptor's catalog
    /// includes artifacts that hit the network. Everything else
    /// runs against on-disk evidence only.
    open_world: bool,
}

impl ToolAnnotations {
    fn to_json(self) -> Value {
        json!({
            "title": self.title,
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        })
    }
}

#[derive(Debug)]
enum ToolError {
    InvalidParams(String),
    Internal(String),
}

/// Run the stdio server until stdin closes. Returns on EOF or fatal
/// I/O error. Logs to stderr.
///
/// # Errors
/// Returns the underlying I/O error if reading from stdin or writing
/// to stdout fails. Per-message errors (validation, handler) are
/// returned to the client as JSON-RPC errors and do not abort the
/// loop.
pub fn run_stdio_server() -> std::io::Result<()> {
    run_stdio_server_with_streams(std::io::stdin().lock(), std::io::stdout().lock())
}

/// Test-friendly variant that takes arbitrary read/write streams.
///
/// # Errors
/// Returns the first I/O error from reading or writing.
pub fn run_stdio_server_with_streams<R, W>(input: R, mut output: W) -> std::io::Result<()>
where
    R: Read,
    W: Write,
{
    let registry = build_registry();
    let mut reader = BufReader::new(input);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            // EOF — peer closed.
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(response) = dispatch(trimmed, &registry) {
            writeln!(output, "{response}")?;
            output.flush()?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // grows linearly as we add tools; splitting hurts clarity
fn build_registry() -> Vec<ToolEntry> {
    vec![
        ToolEntry {
            name: "case_open",
            description:
                "FIRST tool to call when starting an investigation. Registers an evidence image \
                 (.e01, .raw, .dd, .mem) by computing its SHA-256, issuing a UUID4 case_id, and \
                 creating the case directory at $FINDEVIL_HOME/cases/<id>/. Idempotent per image \
                 hash — calling twice on the same file yields a new case_id but does not mutate \
                 evidence. Use the returned case_id in every subsequent tool call. \
                 ERRORS: ImageNotFound (check the path), ImageNotRegular (path is a directory; \
                 pass the file directly), ImageHashMismatch (only if expected_sha256 supplied — \
                 implies tampering or wrong file).",
            annotations: ToolAnnotations {
                title: "Open Evidence Case",
                read_only: false, // creates case directory + audit log
                destructive: false,
                idempotent: false, // mints fresh UUID4 each call
                open_world: false,
            },
            schema: || schema_for::<CaseOpenInput>(),
            handler: |args| dispatch_case_open(args),
        },
        ToolEntry {
            name: "disk_mount",
            description:
                "Register a read-only disk mount session resource for a raw/E01 image. In auto mode, \
                 uses fixed subprocess wrappers (ewfmount or mount -o ro,loop) on SIFT/Unix; on \
                 Windows use mode='mock' for unit-testable behavior with an already-populated \
                 mount_point. Writes cases/<case_id>/session_resources.json. No raw command \
                 passthrough is exposed.",
            annotations: ToolAnnotations {
                title: "Mount Disk Image Read-only",
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            schema: || schema_for::<DiskMountInput>(),
            handler: |args| dispatch_disk_mount(args),
        },
        ToolEntry {
            name: "disk_extract_artifacts",
            description:
                "Copy selected artifacts from a disk_mount fs_root into the case extraction area \
                 for existing typed parsers: $MFT, $UsnJrnl:$J exports, Prefetch, Registry hives, \
                 EVTX, and YARA target files. Updates the SessionResource ledger and returns \
                 extracted artifact paths for downstream mft_timeline/usnjrnl_query/\
                 prefetch_parse/registry_query/evtx_query/yara_scan calls. The optional \
                 max_artifact_bytes guard skips oversized files before copying them into the case \
                 workspace and reports artifacts_skipped_oversize.",
            annotations: ToolAnnotations {
                title: "Extract Disk Artifacts",
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            schema: || schema_for::<DiskExtractArtifactsInput>(),
            handler: |args| dispatch_disk_extract_artifacts(args),
        },
        ToolEntry {
            name: "disk_unmount",
            description:
                "Unmount a disk_mount session resource using a fixed umount subprocess on \
                 SIFT/Unix, or mode='mock' in tests/Windows. Marks the session resource \
                 unmounted in the ledger. Never deletes original evidence.",
            annotations: ToolAnnotations {
                title: "Unmount Disk Image",
                read_only: false,
                destructive: false,
                idempotent: false,
                open_world: false,
            },
            schema: || schema_for::<DiskUnmountInput>(),
            handler: |args| dispatch_disk_unmount(args),
        },
        ToolEntry {
            name: "evtx_query",
            description:
                "Parse a Windows Event Log (.evtx) file. Use AFTER case_open. Pass eids=[4624] \
                 for successful logons (Pool A persistence baseline), eids=[4688] for process \
                 creation, eids=[7045] for service install. Default limit 10000; lower it for \
                 dense system logs. Returns rows[] (event_id, ts, channel, record_id, data), \
                 parse_errors count (per-record failures swallowed, not aborted), and \
                 records_seen (pre-filter). \
                 ERRORS: EvtxNotFound (verify case_open succeeded and the path exists inside \
                 the mounted image), EvtxOpen (file is corrupt or not a real EVTX — check \
                 magic bytes 'ElfFile'), EvtxParseAllFailed (every record failed; the file \
                 is structurally broken — try a different copy of the log).",
            annotations: ToolAnnotations {
                title: "Query Windows Event Log",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<EvtxQueryInput>(),
            handler: |args| dispatch_evtx_query(args),
        },
        ToolEntry {
            name: "prefetch_parse",
            description:
                "Extract execution evidence from a Windows Prefetch (.pf) file. THIS IS THE \
                 CANONICAL 'did this binary actually run' artifact — combine it with \
                 amcache/shimcache for the SOUL.md ≥2 artifact-class corroboration rule. \
                 Handles MAM compression (Win10+) and uncompressed SCCA (Win7-/8.1) \
                 transparently. Returns executable_name, version (17/23/26/30 → \
                 XP/7/8.1/10), run_count, last_run_times_iso (UTC ISO-8601Z, up to 8 most \
                 recent on Win10+), file_references (DLLs/EXEs the binary loaded), and \
                 volume_paths. CAVEAT (per agent-config/MEMORY.md): prefetch can be disabled \
                 on SSDs (EnablePrefetcher=0); absence is NOT evidence of absence — surface \
                 that caveat in any finding that relies on prefetch absence. \
                 ERRORS: NotFound (verify the path), Unreadable (permissions / device error), \
                 ParseFailed (corrupt header or unsupported version — try a fresh copy).",
            annotations: ToolAnnotations {
                title: "Parse Windows Prefetch",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<PrefetchInput>(),
            handler: |args| dispatch_prefetch_parse(args),
        },
        ToolEntry {
            name: "mft_timeline",
            description: "Extract a timeline from an NTFS Master File Table ($MFT). Pair with \
                 prefetch_parse for the SOUL.md ≥2 artifact-class rule on execution claims: \
                 MFT proves the binary EXISTED on disk; Prefetch proves it RAN. Each row \
                 carries BOTH $SI (StandardInformation) and $FN (FileName) MAC times — the \
                 agent should compare them to detect timestomping ($SI is trivially \
                 stompable via SetFileTime; $FN updates only on rename/move and is \
                 tamper-evident). A binary whose $SI.modified is OLDER than $FN.modified is \
                 a strong tampering signal. Use since_iso/until_iso to focus on an incident \
                 window. Returns entries[] (record_number, parent_record, name, full_path, \
                 is_directory, is_allocated, logical_size, plus 4 $SI + 2 $FN times), \
                 parse_errors (per-record failures swallowed), and records_seen (pre-filter). \
                 ERRORS: MftNotFound (verify path), MftOpen (wrong magic — check the file is \
                 a real $MFT export, not a copy of the volume root), InvalidTimeFilter \
                 (since_iso/until_iso must be RFC 3339 / ISO-8601, e.g. 2026-04-25T00:00:00Z).",
            annotations: ToolAnnotations {
                title: "Build NTFS MFT Timeline",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<MftInput>(),
            handler: |args| dispatch_mft_timeline(args),
        },
        ToolEntry {
            name: "registry_query",
            description: "Read keys + values from an offline Windows Registry hive (NTUSER.DAT, \
                 SOFTWARE, SYSTEM, SECURITY, SAM, USRCLASS.DAT). PRIMARY POOL A persistence \
                 surface — Run / RunOnce / IFEO / Services / WMI subscription consumers / \
                 ScheduledTasks all live here. Use AFTER case_open with the hive_path \
                 pointing at the file inside the mounted image. \
                 key_path is RELATIVE TO THE HIVE ROOT (e.g. 'Microsoft\\Windows\\\
                 CurrentVersion\\Run' for a SOFTWARE hive). Optional 'HKLM\\\\' / 'HKCU\\\\' / \
                 'HKU\\\\' prefixes are stripped. Use either '\\' or '/' as separator. \
                 recursive=true walks all descendants depth-first (capped at depth 16 + \
                 limit). Default limit 10000. \
                 Returns entries[] (key_path, last_write_time_iso, values[], subkeys[]), \
                 keys_visited, parse_errors. Each value is normalized: REG_SZ/EXPAND_SZ \
                 → text, REG_MULTI_SZ → '|'-joined, REG_DWORD/QWORD → decimal, REG_BINARY \
                 → lowercase hex (truncated at 4096 bytes with marker). \
                 An absent key path is NOT an error: it returns empty entries[] with \
                 key_present=false (read it as 'no such key here'). Make sure the prefix \
                 matches the hive type, e.g. SOFTWARE keys live under 'Microsoft\\…' not \
                 'HKLM\\SOFTWARE\\Microsoft\\…'. \
                 ERRORS: HiveNotFound (verify path), HiveOpen (file is not a valid hive — \
                 wrong magic / corrupt header; try a fresh copy or a transaction-replayed \
                 version).",
            annotations: ToolAnnotations {
                title: "Read Windows Registry Hive",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<RegistryInput>(),
            handler: |args| dispatch_registry_query(args),
        },
        ToolEntry {
            name: "yara_scan",
            description: "Scan files against YARA rules in-process (yara-x, BSD-3, pure Rust). \
                 PRIMARY POOL B exfil + general malware-family hunting surface — works against \
                 YARA-Forge, Florian Roth's signature-base, internal IOC packs, anything in \
                 .yar/.yara format. Use AFTER case_open. \
                 target_path is a single file OR a directory; recursive=true walks all \
                 descendants (default false: top-level only). rules_path is a single rules \
                 file OR a directory of rules — directory mode walks recursively for \
                 .yar/.yara/.yarx and merges everything into one Rules instance with the \
                 file's basename as the namespace (so matches are attributable). Default \
                 limit 1000 matches across all files. \
                 Returns matches[] (file_path, rule_name, namespace, tags, pattern_matches[]) \
                 + files_scanned + rules_compiled + scan_errors. Each pattern match shows \
                 offset, length, and a 64-byte hex preview (full bytes are not returned to \
                 keep responses bounded). \
                 ERRORS: TargetNotFound / RulesNotFound (verify paths), NoRulesFiles (the \
                 rules directory contains no .yar/.yara/.yarx files), RulesCompileFailed \
                 (YARA syntax error or unsupported feature — yara-x is 99% libyara-compatible \
                 but the 1% that diverges shows up here; the error message names the file \
                 and line).",
            annotations: ToolAnnotations {
                title: "Scan with YARA Rules",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<YaraInput>(),
            handler: |args| dispatch_yara_scan(args),
        },
        ToolEntry {
            name: "usnjrnl_query",
            description: "Stream change records from an NTFS USN Journal ($UsnJrnl:$J). Use \
                 AFTER case_open. The USN journal records EVERY file-system mutation \
                 (create, delete, rename, write, EA change, ACL change) in a circular \
                 buffer — far more complete than the MFT alone, which only shows current \
                 state. Pair with mft_timeline to corroborate 'this file existed and was \
                 modified at time T'. \
                 Filters: since_iso/until_iso (UTC ISO-8601Z) bracket an incident window; \
                 reasons[] takes named flags (FILE_CREATE, FILE_DELETE, RENAME_OLD_NAME, \
                 RENAME_NEW_NAME, DATA_EXTEND, etc. — see schema for full set, \
                 case-insensitive). Default limit 10000. \
                 Returns entries[] (usn, timestamp_iso, mft_entry, parent_mft_entry, \
                 filename, reason_flags[], file_attributes, major_version) + parse_errors \
                 + records_seen + row_count. \
                 CAVEAT (per agent-config/MEMORY.md): UsnJrnl is CIRCULAR — older records \
                 get overwritten as the buffer wraps. Gaps in the USN sequence or \
                 timestamps are normal, not suspicious by themselves. Always pair USN \
                 absence with MFT corroboration before claiming 'no activity at time T'. \
                 ERRORS: UsnJrnlNotFound (verify the path), UsnJrnlOpen (file is not a \
                 valid $J — check it's the carved data stream, not the metadata file or \
                 a copy of the $UsnJrnl directory), InvalidTimeFilter (since_iso/until_iso \
                 must be RFC 3339), InvalidReason (an entry in reasons[] isn't a known \
                 flag name).",
            annotations: ToolAnnotations {
                title: "Stream NTFS USN Journal",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<UsnJrnlInput>(),
            handler: |args| dispatch_usnjrnl_query(args),
        },
        ToolEntry {
            name: "hayabusa_scan",
            description: "Run Hayabusa (Sigma rules engine for Windows EVTX) against a \
                 directory of .evtx files and parse its alerts. AGPL — invoked as a \
                 SUBPROCESS only per Spec #2 invariant. Pool A persistence detector: \
                 Hayabusa's bundled rule set surfaces suspicious logons, service \
                 installs, scheduled-task creates, persistence-classified events, \
                 and detection-rule patterns from the SIGMA project. \
                 Use AFTER case_open with evtx_dir pointing at the case's extracted \
                 EVTX directory. min_level filters Sigma severity (informational, low, \
                 medium, high, critical) — default 'low' (informational floods). \
                 Optional rule_set overrides the default rules dir; usually omit. \
                 Hayabusa binary discovery: $HAYABUSA_BIN env var first, then PATH \
                 lookup. Default limit 10000 alerts. \
                 Returns alerts[] (timestamp_iso, rule, level, channel, event_id, \
                 computer, details map) + alerts_seen + stderr_tail. The details map \
                 carries event-specific fields (SubjectUserName, TargetFilename, etc.) \
                 that vary by event type. \
                 ERRORS: EvtxDirNotFound / EvtxDirNotDirectory (verify path), \
                 RuleSetNotFound (path doesn't exist), BinaryNotFound (install Hayabusa \
                 from https://github.com/Yamato-Security/hayabusa/releases or set \
                 $HAYABUSA_BIN to its location), SubprocessFailed (Hayabusa returned \
                 non-zero — check stderr_tail), OutputParse (JSON malformed; rare and \
                 indicates a Hayabusa version mismatch — pin a known-good version), \
                 InvalidMinLevel (must be one of the 5 standard levels).",
            annotations: ToolAnnotations {
                title: "Run Hayabusa Sigma Detection",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<HayabusaInput>(),
            handler: |args| dispatch_hayabusa_scan(args),
        },
        ToolEntry {
            name: "sysmon_network_query",
            description: "Parse Sysmon network connection events (Event ID 3 by default) from an EVTX file. Use AFTER case_open on Microsoft-Windows-Sysmon/Operational logs. Optional filters include time window, image substring, destination IP, destination port, and event_ids. Returns normalized connection rows with source/destination IP/port, protocol, image, user, and raw Sysmon fields. ERRORS: sysmon evtx file not found / not regular (check path), invalid time filter (RFC3339/ISO-8601Z required), EVTX open failures for corrupt logs.",
            annotations: ToolAnnotations {
                title: "Query Sysmon Network Events",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<SysmonNetworkInput>(),
            handler: |args| dispatch_sysmon_network_query(args),
        },
        ToolEntry {
            name: "zeek_summary",
            description: "Summarize Zeek TSV logs from a file or directory using pure Rust/standard parsing. Handles conn.log, dns.log, http.log, ssl.log, and tls.log when present, returning top hosts, DNS queries, HTTP hosts, notable connections, row counts, and parse_errors. Use AFTER case_open on extracted Zeek logs. ERRORS: zeek path not found/unreadable.",
            annotations: ToolAnnotations {
                title: "Summarize Zeek Logs",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<ZeekSummaryInput>(),
            handler: |args| dispatch_zeek_summary(args),
        },
        ToolEntry {
            name: "pcap_triage",
            description: "Triage a PCAP/PCAPNG via fixed tshark or Zeek subprocess invocations only. analyzer=auto prefers tshark when available, otherwise Zeek. Returns packet/row counts, top conversations, DNS queries, HTTP hosts, optional embedded Zeek summary, and stderr_tail. ERRORS: pcap file not found/not regular, invalid analyzer, binary not found (install tshark or Zeek / set $TSHARK_BIN or $ZEEK_BIN), subprocess failed.",
            annotations: ToolAnnotations {
                title: "Triage PCAP Network Capture",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<PcapTriageInput>(),
            handler: |args| dispatch_pcap_triage(args),
        },
        ToolEntry {
            name: "vol_pslist",
            description: "Run Volatility 3's `windows.pslist` plugin against a memory image \
                 and return the live process list. THIS IS THE FIRST MEMORY-FORENSICS \
                 TOOL the agent should call on a `.mem` / `.raw` / `.dmp` / `.vmem` image \
                 — it walks the kernel's PsActiveProcessHead and surfaces what's running. \
                 Pair with vol_malfind for code-injection detection (different artifact \
                 class on the same image satisfies SOUL.md cross-artifact rule). \
                 Use AFTER case_open. memory_path is the image file. pid_filter narrows \
                 to specific PIDs after a coarse first sweep. Default limit 10000 \
                 (typical Windows host has 100-500 live processes). \
                 Returns processes[] (pid, ppid, image_name, create_time_iso, \
                 exit_time_iso?, threads, handles, session_id, wow64) + processes_seen \
                 + stderr_tail. \
                 Volatility binary discovery: $VOLATILITY_BIN env var first, then PATH \
                 lookup for vol/vol.py/volatility3/volatility (in that order — SIFT VM \
                 ships vol.py; pip installs put vol/volatility3 on PATH). \
                 ERRORS: MemoryNotFound / MemoryNotRegular (verify path), BinaryNotFound \
                 (install via `pip install volatility3` or use the SIFT VM), \
                 SubprocessFailed (Volatility returned non-zero — check stderr_tail; \
                 common causes: corrupt image, unsupported OS profile), OutputParse \
                 (JSON malformed; rare, indicates a Vol3 version mismatch).",
            annotations: ToolAnnotations {
                title: "List Memory Processes (Volatility)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<VolPslistInput>(),
            handler: |args| dispatch_vol_pslist(args),
        },
        ToolEntry {
            name: "vol_malfind",
            description: "Run Volatility 3's `windows.malfind` plugin against a memory image \
                 and return code-injection candidates. THE canonical code-injection detector: \
                 walks every process's VAD tree looking for memory regions that are RWX \
                 (read-write-execute, the classic injection footprint) AND/OR contain an MZ \
                 header in unexpected places — both strong indicators that something has \
                 been injected into a legitimate process. \
                 PAIR WITH vol_pslist for memory-context corroboration: pslist tells \
                 you WHAT processes exist, malfind tells you WHICH contain suspicious \
                 memory regions. This remains memory-only evidence; disk, event-log, \
                 or network artifacts are needed before execution or exfiltration claims. \
                 Use AFTER case_open. memory_path is the image. pid_filter narrows to \
                 specific PIDs (typically PIDs that vol_pslist flagged as suspicious — \
                 abnormal parent, unusual session, etc.). Default limit 10000 (a \
                 compromised host can have dozens of suspicious VADs per process). \
                 Returns injections[] (pid, image_name, vad_start_hex, vad_end_hex, \
                 protection, mz_match: bool, sample_hex of first 64 bytes) + \
                 injections_seen + stderr_tail. \
                 ERRORS: same as vol_pslist (MemoryNotFound, BinaryNotFound, \
                 SubprocessFailed, OutputParse). Same Volatility binary discovery \
                 ($VOLATILITY_BIN env var first, then PATH lookup).",
            annotations: ToolAnnotations {
                title: "Find Code Injection (Volatility)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<VolMalfindInput>(),
            handler: |args| dispatch_vol_malfind(args),
        },
        ToolEntry {
            name: "vol_psscan",
            description: "Run Volatility 3's `windows.psscan` plugin against a memory image \
                 — the cross-validation companion to vol_pslist. Where pslist walks \
                 the kernel's PsActiveProcessHead linked list, psscan scans the \
                 entire memory image for _EPROCESS signatures (much slower but \
                 catches DKOM-unlinked processes). \
                 PAIR WITH vol_pslist: divergence between the two outputs is \
                 itself the forensic finding. pslist=0 + psscan>0 is the textbook \
                 MITRE ATT&CK T1014 (Rootkit) signature — a kernel rootkit has \
                 unlinked malicious processes from the active list while leaving \
                 their _EPROCESS structures in pool memory. \
                 Use AFTER case_open. memory_path is the image. pid_filter narrows \
                 to specific PIDs. Default limit 10000. \
                 Returns processes[] (pid, ppid, image_name, create_time_iso, \
                 exit_time_iso?, threads, offset_v, session_id, wow64) + \
                 processes_seen + stderr_tail. The offset_v field is the \
                 _EPROCESS virtual offset where psscan recovered each object — \
                 useful for cross-referencing with manual analysis or psxview. \
                 Same Volatility binary discovery as vol_pslist ($VOLATILITY_BIN \
                 env var first, then PATH lookup). \
                 ERRORS: MemoryNotFound / MemoryNotRegular (verify path), \
                 BinaryNotFound (install via `pip install volatility3`), \
                 SubprocessFailed (check stderr_tail), OutputParse (rare; \
                 indicates a Vol3 version mismatch).",
            annotations: ToolAnnotations {
                title: "Cross-validate Memory Process List (Volatility psscan)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<VolPsscanInput>(),
            handler: |args| dispatch_vol_psscan(args),
        },
        ToolEntry {
            name: "vol_psxview",
            description: "Run Volatility 3's `windows.psxview` plugin against a memory image \
                 to cross-reference multiple process-enumeration methods. Use after \
                 vol_pslist + vol_psscan diverge: psxview shows which recovered \
                 processes are visible to pslist, psscan, thread/process, PspCid, \
                 CSRSS, session, and desktop-thread views. This is the direct \
                 corroborating tool for DKOM process hiding. \
                 Use AFTER case_open. memory_path is the image. pid_filter narrows \
                 to specific PIDs. Default limit 10000. \
                 Returns processes[] (pid, image_name, offset_v, pslist, psscan, \
                 thrdproc, pspcid, csrss, session, deskthrd, exit_time_iso?) + \
                 processes_seen + stderr_tail. Same Volatility binary discovery as \
                 vol_pslist ($VOLATILITY_BIN env var first, then PATH lookup). \
                 ERRORS: MemoryNotFound / MemoryNotRegular (verify path), \
                 BinaryNotFound (install via `pip install volatility3`), \
                 SubprocessFailed (check stderr_tail), OutputParse (rare; indicates \
                 a Vol3 version mismatch).",
            annotations: ToolAnnotations {
                title: "Cross-check Process Views (Volatility psxview)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<VolPsxviewInput>(),
            handler: |args| dispatch_vol_psxview(args),
        },
        ToolEntry {
            name: "vol_run",
            description: "Run ONE allow-listed Volatility 3 plugin against a memory image and \
                 return its raw rows. This is the generic memory verb: where vol_pslist / \
                 vol_psscan / vol_psxview / vol_malfind cover the high-value pivots with \
                 fully typed output, vol_run reaches the long tail of evil-hunting plugins \
                 through ONE verb instead of 40 bespoke tools. \
                 plugin MUST be a canonical Vol3 name on the allow-list — any other value \
                 (including a shell-injection-shaped string) is rejected with PluginNotAllowed \
                 BEFORE any subprocess runs, which is the no-shell guarantee for a \
                 parameterized verb. Allow-list (curated, evil-hunting): \
                 windows.cmdline/dlllist/ldrmodules/handles/getsids/privileges/sessions/envars \
                 (process+execution context), windows.svcscan/netscan/netstat (services+network), \
                 windows.consoles/cmdscan (attacker shell history), \
                 windows.registry.{hashdump,lsadump,cachedump} (credentials), \
                 windows.hollowprocesses/suspicious_threads/vadinfo (injection depth), \
                 windows.modules/modscan/driverscan/ssdt/callbacks (kernel rootkit surface), \
                 windows.filescan/mftscan.MFTScan, windows.registry.hivelist/userassist, \
                 linux.pslist/psscan/pstree/bash/malfind/lsmod/check_modules/check_syscall/hidden_modules, \
                 mac.pslist/psaux/lsmod/malfind/check_syscall. \
                 Use AFTER case_open. memory_path is the image; optional pid scopes per-process \
                 plugins (a u32, never a shell fragment). Default limit 10000. \
                 Returns plugin + rows[] (raw per-plugin JSON columns — output shape varies by \
                 plugin, so the agent gets the plugin's own schema) + rows_seen + stderr_tail. \
                 Linux/macOS images also need their ISF symbol table on the Vol3 symbol path. \
                 Same Volatility binary discovery as vol_pslist ($VOLATILITY_BIN first, then \
                 PATH for vol/vol.py/volatility3/volatility). \
                 ERRORS: PluginNotAllowed (use a canonical allow-listed name, or the bespoke \
                 vol_* tools), MemoryNotFound / MemoryNotRegular (verify path), BinaryNotFound \
                 (install via `pip install volatility3` or use the SIFT VM), SubprocessFailed \
                 (check stderr_tail — common causes: missing ISF symbols, unsupported profile), \
                 OutputParse (rare; Vol3 version mismatch).",
            annotations: ToolAnnotations {
                title: "Run Allow-listed Memory Plugin (Volatility)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<VolRunInput>(),
            handler: |args| dispatch_vol_run(args),
        },
        ToolEntry {
            name: "ez_parse",
            description: "Run ONE allow-listed Eric Zimmerman tool against a carved Windows \
                 artifact and return the decoded rows. This is the decoded-execution / \
                 persistence / anti-forensic verb: where registry_query and the raw parsers \
                 hand back bytes, ez_parse decodes them. ONE verb instead of seven bespoke \
                 wrappers. \
                 tool MUST be one of: lecmd (LNK target+MAC+volserial+args), jlecmd (JumpList \
                 recent-file MRU), amcacheparser (Amcache.hve program presence+SHA1 — \
                 NOTE Amcache LastModified != execution, it is catalog-registration time, so \
                 it is a >=2-artifact corroborator for Prefetch, never proof alone), \
                 appcompatcacheparser (ShimCache path+$SI; pre-Win8 exec flag), rbcmd \
                 (Recycle Bin $I: original path, deletion UTC, deleting SID), sbecmd \
                 (shellbags: folders browsed incl. deleted/external/UNC), wxtcmd (Win10 \
                 Timeline). Any other value is rejected with ToolNotAllowed BEFORE a \
                 subprocess runs — the no-shell guarantee for a parameterized verb. \
                 Use AFTER disk_extract_artifacts has carved the artifact. artifact_path is \
                 the carved file (for sbecmd, the directory of hives). Default limit 10000. \
                 Returns tool + rows[] (raw per-tool CSV columns — schema varies by tool) + \
                 rows_seen + csv_files[] (provenance) + stderr_tail. \
                 Binary discovery: $EZTOOLS_DIR first, then PATH (the tools ship on the SIFT \
                 VM and run native on Linux since the .NET port). \
                 ERRORS: ToolNotAllowed (use an allow-listed key), ArtifactNotFound (verify \
                 the carved path), BinaryNotFound (install the EZ tools or use the SIFT VM), \
                 SubprocessFailed (check stderr_tail), NoCsvProduced (tool ran but wrote no \
                 CSV — usually an unsupported/empty artifact), OutputRead (rare IO error).",
            annotations: ToolAnnotations {
                title: "Decode Windows Artifact (Eric Zimmerman Tools)",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<EzParseInput>(),
            handler: |args| dispatch_ez_parse(args),
        },
        ToolEntry {
            name: "vel_collect",
            description: "Run a Velociraptor artifact via `velociraptor artifacts collect` and \
                 stream the resulting rows. Generic trampoline over Velociraptor's 200+ \
                 built-in DFIR artifacts (Windows.Forensics.Prefetch, \
                 Windows.Persistence.Services, Generic.Forensic.LocalHashes, etc.) — the \
                 agent picks the artifact name and supplies any required parameters via \
                 `args` (e.g. {\"device\":\"C:\"}). Apache-2.0; subprocess-only per Spec #2. \
                 Use AFTER case_open. artifact must be a dotted-path name like \
                 `Windows.Forensics.Prefetch` (validated up-front to keep injection out of \
                 argv). args is an optional `key=value` map; keys must be \
                 `[A-Za-z_][A-Za-z0-9_]*`. Default limit 10000 rows. \
                 Velociraptor binary discovery: $VELOCIRAPTOR_BIN env var first, then PATH \
                 lookup for `velociraptor` (single-binary release; install from \
                 https://github.com/Velocidex/velociraptor/releases). \
                 Returns rows[] {artifact, fields: free-form column map} + rows_seen + \
                 stderr_tail. The fields map is intentionally unstructured — every artifact \
                 has its own column set, and pinning a typed shape would be hostile to the \
                 agent's flexibility. \
                 PAIR WITH yara_scan and registry_query for live-response corroboration: \
                 Velociraptor artifacts often surface persistence and execution evidence in \
                 a single row whose source artifacts also exist as standalone tools — \
                 cross-checking those tools confirms the Velociraptor row is not a parsing \
                 artefact. \
                 ERRORS: BinaryNotFound (install Velociraptor or set $VELOCIRAPTOR_BIN), \
                 InvalidArtifactName (artifact name failed dotted-path validation; check \
                 spelling against `velociraptor artifacts list`), InvalidArgName (an arg \
                 key contained shell-meaningful characters), SubprocessFailed (Velociraptor \
                 returned non-zero; check stderr_tail), OutputParse (stdout was neither \
                 JSONL nor a JSON array — usually a Velociraptor version mismatch).",
            annotations: ToolAnnotations {
                title: "Collect Velociraptor Artifact",
                read_only: true,
                destructive: false,
                idempotent: true,
                // Some Velociraptor artifacts (e.g. uploads, network probes)
                // do touch external systems. Conservative: mark openWorld
                // so the agent UI can prompt before auto-approving.
                open_world: true,
            },
            schema: || schema_for::<VelCollectInput>(),
            handler: |args| dispatch_vel_collect(args),
        },
        ToolEntry {
            name: "browser_history",
            description: "Read visited URLs from an offline browser-history SQLite database — \
                 Chrome/Edge `History` (…/User Data/Default/History) or Firefox \
                 `places.sqlite`. POOL B exfil + triage surface: a downloaded-payload URL, a \
                 credential-phishing visit, or a C2 panel opened in a browser lands here. \
                 Use AFTER case_open with history_path pointing at the file extracted from the \
                 mounted image (pass the extracted copy, not a live profile). Opened READ-ONLY \
                 + immutable, so it never writes a -wal/-journal next to the evidence. \
                 Auto-detects the browser by schema (Chrome urls/visits vs Firefox moz_places) \
                 and normalizes timestamps to UTC ISO-8601Z from each native epoch (Chrome \
                 WebKit µs-since-1601, Firefox µs-since-1970). Default limit 10000, newest \
                 last-visit first. Returns browser_family, rows[] {url, title, \
                 last_visit_time_iso, visit_count}, rows_seen. \
                 HONEST SCOPE: a row CONFIRMS a URL was RECORDED AS VISITED at time T (a \
                 browser-artifact fact) — it does NOT assert execution, so a single \
                 browser_history Finding is a legitimate CONFIRMED browser fact and never \
                 trips the ≥2-artifact-class execution rule; intent is a separate \
                 'hypothesis:' layer. \
                 ERRORS: NotFound (verify path), Unreadable (not openable), ParseFailed \
                 (corrupt DB / unexpected column shape), UnknownSchema (a valid SQLite file \
                 that is neither a Chrome nor a Firefox history DB).",
            annotations: ToolAnnotations {
                title: "Read Browser History",
                read_only: true,
                destructive: false,
                idempotent: true,
                open_world: false,
            },
            schema: || schema_for::<BrowserHistoryInput>(),
            handler: |args| dispatch_browser_history(args),
        },
    ]
}

fn schema_for<T: schemars::JsonSchema>() -> Value {
    let schema = schemars::schema_for!(T);
    serde_json::to_value(schema).expect("schemars output is JSON")
}

/// Parse one inbound line and produce the response line (or None for
/// notifications, which the spec says are not replied to).
fn dispatch(line: &str, registry: &[ToolEntry]) -> Option<String> {
    // Parse the message envelope. Malformed JSON is itself an error
    // response with a null id (we have no id to echo).
    let msg: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(err) => {
            return Some(make_error_response(
                &Value::Null,
                ERR_INVALID_PARAMS,
                &format!("malformed JSON: {err}"),
            ));
        }
    };

    let method = msg.get("method").and_then(|v| v.as_str()).unwrap_or("");
    let id = msg.get("id").cloned();
    let params = msg.get("params").cloned().unwrap_or(Value::Null);

    // Notifications have no id and expect no response.
    let is_notification = id.is_none();

    let result = match method {
        "initialize" => Ok(handle_initialize(&params)),
        "notifications/initialized" | "initialized" => {
            // Spec: notifications/initialized is fire-and-forget.
            return None;
        }
        "tools/list" => Ok(handle_tools_list(registry)),
        "tools/call" => handle_tools_call(&params, registry),
        "ping" => Ok(json!({})),
        other => Err(ToolError::InvalidParams(format!(
            "unknown method: {other:?}"
        ))),
    };

    if is_notification {
        // Method-call-without-id is a notification; even errors get swallowed.
        return None;
    }

    let id = id.unwrap_or(Value::Null);
    Some(match result {
        Ok(value) => make_success_response(&id, &value),
        Err(ToolError::InvalidParams(msg)) => make_error_response(&id, ERR_INVALID_PARAMS, &msg),
        Err(ToolError::Internal(msg)) => make_error_response(&id, ERR_INTERNAL, &msg),
    })
}

fn handle_initialize(_params: &Value) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": CRATE_VERSION,
        },
    })
}

fn handle_tools_list(registry: &[ToolEntry]) -> Value {
    let tools: Vec<Value> = registry
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": (t.schema)(),
                "annotations": t.annotations.to_json(),
            })
        })
        .collect();
    json!({ "tools": tools })
}

fn handle_tools_call(params: &Value, registry: &[ToolEntry]) -> Result<Value, ToolError> {
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::InvalidParams("tools/call missing 'name'".to_string()))?;
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let entry = registry
        .iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ToolError::InvalidParams(format!("unknown tool: {name}")))?;

    // Guard against a panicking tool handler (e.g. a third-party hive/image
    // parser hitting an unimplemented code path on an unusual artifact) taking
    // down the whole stdio server mid-investigation. Convert the panic into a
    // clean per-call ToolError so the run continues with the remaining tools.
    let payload =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (entry.handler)(arguments)))
            .map_err(|panic| {
                let detail = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "tool handler panicked".to_string());
                ToolError::Internal(format!("tool '{name}' panicked: {detail}"))
            })??;
    let payload_text = serde_json::to_string(&payload)
        .map_err(|e| ToolError::Internal(format!("serialize tool output: {e}")))?;
    let sha = sha256_hex(payload_text.as_bytes());

    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": payload_text,
            }
        ],
        "_meta": {
            "tool": name,
            "output_sha256": sha,
        },
    }))
}

// ---------------------------------------------------------------------------
// Per-tool dispatchers — validate input, call the typed handler,
// serialize the typed output back to JSON.
// ---------------------------------------------------------------------------

fn dispatch_case_open(args: Value) -> Result<Value, ToolError> {
    let input: CaseOpenInput = parse_args(args)?;
    let handle =
        case_open::case_open(&input).map_err(|e| ToolError::Internal(format!("case_open: {e}")))?;
    serde_json::to_value(handle).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
}

fn dispatch_disk_mount(args: Value) -> Result<Value, ToolError> {
    let input: DiskMountInput = parse_args(args)?;
    match disk_mount(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::DiskError::CaseNotFound(_)
            | crate::tools::DiskError::ImageNotFound(_)
            | crate::tools::DiskError::UnsupportedPlatform),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("disk_mount: {e}"))),
    }
}

fn dispatch_disk_extract_artifacts(args: Value) -> Result<Value, ToolError> {
    let input: DiskExtractArtifactsInput = parse_args(args)?;
    match disk_extract_artifacts(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::DiskError::CaseNotFound(_)
            | crate::tools::DiskError::MountNotFound(_)
            | crate::tools::DiskError::MountNotMounted(_)
            | crate::tools::DiskError::MountRootNotFound(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("disk_extract_artifacts: {e}"))),
    }
}

fn dispatch_disk_unmount(args: Value) -> Result<Value, ToolError> {
    let input: DiskUnmountInput = parse_args(args)?;
    match disk_unmount(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::DiskError::CaseNotFound(_)
            | crate::tools::DiskError::MountNotFound(_)
            | crate::tools::DiskError::MountNotMounted(_)
            | crate::tools::DiskError::UnsupportedPlatform),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("disk_unmount: {e}"))),
    }
}

fn dispatch_evtx_query(args: Value) -> Result<Value, ToolError> {
    let input: EvtxQueryInput = parse_args(args)?;
    // EvtxNotFound is user-input territory — surface as -32602 so the
    // agent can correct the path instead of treating it as a tool crash.
    match evtx_query(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(e @ crate::tools::EvtxError::EvtxNotFound(_)) => {
            Err(ToolError::InvalidParams(format!("{e}")))
        }
        Err(e) => Err(ToolError::Internal(format!("evtx_query: {e}"))),
    }
}

fn dispatch_prefetch_parse(args: Value) -> Result<Value, ToolError> {
    let input: PrefetchInput = parse_args(args)?;
    // NotFound is user-input territory; surface as -32602.
    match prefetch_parse(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(e @ crate::tools::PrefetchError::NotFound(_)) => {
            Err(ToolError::InvalidParams(format!("{e}")))
        }
        Err(e) => Err(ToolError::Internal(format!("prefetch_parse: {e}"))),
    }
}

fn dispatch_mft_timeline(args: Value) -> Result<Value, ToolError> {
    let input: MftInput = parse_args(args)?;
    // InvalidTimeFilter + MftNotFound are user-facing input; surface as
    // -32602 not -32603 so the agent corrects the input rather than
    // treating the tool as crashed.
    match mft_timeline(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(crate::tools::MftError::InvalidTimeFilter { value, reason }) => Err(
            ToolError::InvalidParams(format!("invalid time filter {value:?}: {reason}")),
        ),
        Err(e @ crate::tools::MftError::MftNotFound(_)) => {
            Err(ToolError::InvalidParams(format!("{e}")))
        }
        Err(e) => Err(ToolError::Internal(format!("mft_timeline: {e}"))),
    }
}

fn dispatch_registry_query(args: Value) -> Result<Value, ToolError> {
    let input: RegistryInput = parse_args(args)?;
    // HiveNotFound is user-input territory; surface as -32602. (HiveOpen/
    // Unreadable stay -32603 since those represent corrupt or permission-denied
    // files — system-state issues the agent can't fix by retrying with a
    // different argument.) An absent key is NOT an error: registry_query returns
    // an empty result with key_present=false.
    match registry_query(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(e @ crate::tools::RegistryError::HiveNotFound(_)) => {
            Err(ToolError::InvalidParams(format!("{e}")))
        }
        Err(e) => Err(ToolError::Internal(format!("registry_query: {e}"))),
    }
}

fn dispatch_yara_scan(args: Value) -> Result<Value, ToolError> {
    let input: YaraInput = parse_args(args)?;
    // TargetNotFound, RulesNotFound, RulesCompileFailed, NoRulesFiles
    // are all user-input issues; surface as -32602.
    match yara_scan(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::YaraError::RulesCompileFailed { .. }
            | crate::tools::YaraError::NoRulesFiles(_)
            | crate::tools::YaraError::TargetNotFound(_)
            | crate::tools::YaraError::RulesNotFound(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("yara_scan: {e}"))),
    }
}

fn dispatch_usnjrnl_query(args: Value) -> Result<Value, ToolError> {
    let input: UsnJrnlInput = parse_args(args)?;
    // UsnJrnlNotFound, InvalidTimeFilter, InvalidReason are user-input
    // issues; surface as -32602.
    match usnjrnl_query(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::UsnJrnlError::UsnJrnlNotFound(_)
            | crate::tools::UsnJrnlError::InvalidTimeFilter { .. }
            | crate::tools::UsnJrnlError::InvalidReason(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("usnjrnl_query: {e}"))),
    }
}

fn dispatch_hayabusa_scan(args: Value) -> Result<Value, ToolError> {
    let input: HayabusaInput = parse_args(args)?;
    // EvtxDirNotFound/NotDirectory, RuleSetNotFound, InvalidMinLevel
    // are user-input; surface as -32602.
    match hayabusa_scan(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::HayabusaError::InvalidMinLevel(_)
            | crate::tools::HayabusaError::EvtxDirNotFound(_)
            | crate::tools::HayabusaError::EvtxDirNotDirectory(_)
            | crate::tools::HayabusaError::RuleSetNotFound(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("hayabusa_scan: {e}"))),
    }
}

fn dispatch_sysmon_network_query(args: Value) -> Result<Value, ToolError> {
    let input: SysmonNetworkInput = parse_args(args)?;
    match sysmon_network_query(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::SysmonNetworkError::EvtxNotFound(_)
            | crate::tools::SysmonNetworkError::EvtxNotRegular(_)
            | crate::tools::SysmonNetworkError::InvalidTimeFilter { .. }),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("sysmon_network_query: {e}"))),
    }
}

fn dispatch_zeek_summary(args: Value) -> Result<Value, ToolError> {
    let input: ZeekSummaryInput = parse_args(args)?;
    match zeek_summary(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(e @ crate::tools::ZeekSummaryError::NotFound(_)) => {
            Err(ToolError::InvalidParams(format!("{e}")))
        }
        Err(e) => Err(ToolError::Internal(format!("zeek_summary: {e}"))),
    }
}

fn dispatch_pcap_triage(args: Value) -> Result<Value, ToolError> {
    let input: PcapTriageInput = parse_args(args)?;
    match pcap_triage(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::PcapTriageError::PcapNotFound(_)
            | crate::tools::PcapTriageError::PcapNotRegular(_)
            | crate::tools::PcapTriageError::InvalidAnalyzer(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("pcap_triage: {e}"))),
    }
}

fn dispatch_vol_pslist(args: Value) -> Result<Value, ToolError> {
    let input: VolPslistInput = parse_args(args)?;
    // MemoryNotFound / MemoryNotRegular are user-input errors; surface
    // as -32602 so the agent corrects the path rather than treating
    // the tool as crashed.
    match vol_pslist(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VolError::MemoryNotFound(_)
            | crate::tools::VolError::MemoryNotRegular(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vol_pslist: {e}"))),
    }
}

fn dispatch_vol_psscan(args: Value) -> Result<Value, ToolError> {
    let input: VolPsscanInput = parse_args(args)?;
    match vol_psscan(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VolPsscanError::MemoryNotFound(_)
            | crate::tools::VolPsscanError::MemoryNotRegular(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vol_psscan: {e}"))),
    }
}

fn dispatch_vol_psxview(args: Value) -> Result<Value, ToolError> {
    let input: VolPsxviewInput = parse_args(args)?;
    match vol_psxview(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VolPsxviewError::MemoryNotFound(_)
            | crate::tools::VolPsxviewError::MemoryNotRegular(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vol_psxview: {e}"))),
    }
}

fn dispatch_vol_malfind(args: Value) -> Result<Value, ToolError> {
    let input: VolMalfindInput = parse_args(args)?;
    // Same: MemoryNotFound / MemoryNotRegular are user-input.
    match vol_malfind(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VolMalfindError::MemoryNotFound(_)
            | crate::tools::VolMalfindError::MemoryNotRegular(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vol_malfind: {e}"))),
    }
}

fn dispatch_vol_run(args: Value) -> Result<Value, ToolError> {
    let input: VolRunInput = parse_args(args)?;
    // PluginNotAllowed / MemoryNotFound / MemoryNotRegular are user-input
    // errors; surface as -32602 so the agent fixes the call rather than
    // treating the tool as crashed.
    match vol_run(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VolRunError::PluginNotAllowed(_)
            | crate::tools::VolRunError::MemoryNotFound(_)
            | crate::tools::VolRunError::MemoryNotRegular(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vol_run: {e}"))),
    }
}

fn dispatch_ez_parse(args: Value) -> Result<Value, ToolError> {
    let input: EzParseInput = parse_args(args)?;
    // ToolNotAllowed / ArtifactNotFound are user-input errors; surface as
    // -32602 so the agent fixes the call rather than treating it as crashed.
    match ez_parse(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::EzParseError::ToolNotAllowed(_)
            | crate::tools::EzParseError::ArtifactNotFound(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("ez_parse: {e}"))),
    }
}

fn dispatch_vel_collect(args: Value) -> Result<Value, ToolError> {
    let input: VelCollectInput = parse_args(args)?;
    // InvalidArtifactName / InvalidArgName are user-input issues; surface as -32602.
    match vel_collect(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::VelCollectError::InvalidArtifactName(_)
            | crate::tools::VelCollectError::InvalidArgName(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("vel_collect: {e}"))),
    }
}

fn dispatch_browser_history(args: Value) -> Result<Value, ToolError> {
    let input: BrowserHistoryInput = parse_args(args)?;
    // NotFound / UnknownSchema are user-input territory (wrong path, or a file
    // that isn't a browser history DB); surface as -32602. Unreadable/ParseFailed
    // are corrupt-or-permission system issues → -32603.
    match browser_history(&input) {
        Ok(output) => {
            serde_json::to_value(output).map_err(|e| ToolError::Internal(format!("serialize: {e}")))
        }
        Err(
            e @ (crate::tools::BrowserHistoryError::NotFound(_)
            | crate::tools::BrowserHistoryError::UnknownSchema(_)),
        ) => Err(ToolError::InvalidParams(format!("{e}"))),
        Err(e) => Err(ToolError::Internal(format!("browser_history: {e}"))),
    }
}

fn parse_args<T: DeserializeOwned>(args: Value) -> Result<T, ToolError> {
    serde_json::from_value(args).map_err(|e| ToolError::InvalidParams(format!("invalid args: {e}")))
}

// ---------------------------------------------------------------------------
// JSON-RPC envelope helpers.
// ---------------------------------------------------------------------------

fn make_success_response(id: &Value, result: &Value) -> String {
    serialize_envelope(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    }))
}

fn make_error_response(id: &Value, code: i64, message: &str) -> String {
    serialize_envelope(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        },
    }))
}

fn serialize_envelope(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| {
        // Pathological — should never happen; fall back to a valid
        // hand-crafted JSON-RPC parse-error.
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"could not serialize response"}}"#
            .to_string()
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// Hand-rolled hex encoder removed — `hex` is already a dev-dep,
// promote to runtime.
//
// Note: the `hex` crate is in `[dev-dependencies]` for tests today;
// `Cargo.toml` should add it under `[dependencies]` for production
// use. Until that change lands the `hex::encode` call uses the
// `dev-dependencies` symbol via `cargo test`, so the server fails
// to link in `--release`. The Cargo.toml edit accompanies this file.

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn drive(input: &str) -> String {
        let mut output: Vec<u8> = Vec::new();
        run_stdio_server_with_streams(Cursor::new(input.as_bytes()), &mut output)
            .expect("server loop");
        String::from_utf8(output).expect("utf-8 output")
    }

    #[test]
    fn initialize_returns_protocol_version() {
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
        assert!(resp["result"]["capabilities"]["tools"].is_object());
    }

    #[test]
    fn tools_list_advertises_all_tools() {
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        let expected = [
            "case_open",
            "disk_mount",
            "disk_extract_artifacts",
            "disk_unmount",
            "evtx_query",
            "prefetch_parse",
            "mft_timeline",
            "registry_query",
            "yara_scan",
            "usnjrnl_query",
            "hayabusa_scan",
            "sysmon_network_query",
            "zeek_summary",
            "pcap_triage",
            "vol_pslist",
            "vol_malfind",
            "vol_psscan",
            "vol_psxview",
            "vol_run",
            "ez_parse",
            "vel_collect",
            "browser_history",
        ];
        assert_eq!(names.len(), expected.len());
        for want in expected {
            assert!(names.contains(&want), "missing {want}: {names:?}");
        }
        // Each must have an inputSchema dict + annotations object.
        for tool in tools {
            assert!(tool["inputSchema"].is_object(), "schema missing for {tool}");
            let ann = &tool["annotations"];
            assert!(ann.is_object(), "annotations missing for {tool}");
            assert!(ann["title"].is_string(), "title missing on {tool}");
            for hint in [
                "readOnlyHint",
                "destructiveHint",
                "idempotentHint",
                "openWorldHint",
            ] {
                assert!(ann[hint].is_boolean(), "{hint} missing on {tool}");
            }
        }
    }

    #[test]
    fn case_open_is_marked_non_idempotent() {
        // case_open mints a fresh UUID4 per call; idempotentHint must be false.
        let req = r#"{"jsonrpc":"2.0","id":99,"method":"tools/list"}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let case_open = tools.iter().find(|t| t["name"] == "case_open").unwrap();
        assert_eq!(case_open["annotations"]["readOnlyHint"], false);
        assert_eq!(case_open["annotations"]["idempotentHint"], false);
        assert_eq!(case_open["annotations"]["openWorldHint"], false);
    }

    #[test]
    fn vel_collect_is_marked_open_world() {
        // Velociraptor artifacts can touch external systems — UI should prompt.
        let req = r#"{"jsonrpc":"2.0","id":100,"method":"tools/list"}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        let tools = resp["result"]["tools"].as_array().unwrap();
        let vel = tools.iter().find(|t| t["name"] == "vel_collect").unwrap();
        assert_eq!(vel["annotations"]["openWorldHint"], true);
        assert_eq!(vel["annotations"]["readOnlyHint"], true);
    }

    #[test]
    fn unknown_tool_returns_invalid_params() {
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"no_such","arguments":{}}}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(resp["error"]["code"], ERR_INVALID_PARAMS);
        assert!(
            resp["error"]["message"]
                .as_str()
                .unwrap()
                .contains("no_such"),
            "{resp}"
        );
    }

    #[test]
    fn unknown_method_errors() {
        let req = r#"{"jsonrpc":"2.0","id":4,"method":"some/bogus"}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(resp["error"]["code"], ERR_INVALID_PARAMS);
    }

    #[test]
    fn malformed_json_error_keeps_loop_alive() {
        let lines = "not json\n{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"ping\"}\n";
        let out = drive(lines);
        let mut iter = out.lines();
        let first: Value = serde_json::from_str(iter.next().unwrap()).unwrap();
        assert_eq!(first["error"]["code"], ERR_INVALID_PARAMS);
        let second: Value = serde_json::from_str(iter.next().unwrap()).unwrap();
        assert_eq!(second["id"], 5);
        assert!(second["result"].is_object());
    }

    #[test]
    fn notifications_initialized_produces_no_response() {
        let req = r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let out = drive(&format!("{req}\n"));
        assert!(
            out.is_empty(),
            "notification must not produce a response: {out:?}"
        );
    }

    #[test]
    fn tool_call_invalid_args_returns_invalid_params() {
        let req = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"case_open","arguments":{"image_path":42}}}"#;
        let out = drive(&format!("{req}\n"));
        let resp: Value = serde_json::from_str(out.trim()).unwrap();
        assert_eq!(resp["error"]["code"], ERR_INVALID_PARAMS);
    }

    #[test]
    fn case_open_against_real_file_succeeds() {
        let _env_guard = crate::ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");
        let img = tmp.path().join("evidence.E01");
        std::fs::write(&img, b"fake evidence bytes for hashing").unwrap();
        let home = tmp.path().join("home");
        let prev_findevil = std::env::var("FINDEVIL_HOME").ok();
        std::env::set_var("FINDEVIL_HOME", &home);

        let req = format!(
            r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"case_open","arguments":{{"image_path":{img:?}}}}}}}"#,
            img = img.to_string_lossy().replace('\\', "\\\\"),
        );
        let out = drive(&format!("{req}\n"));
        match prev_findevil {
            Some(v) => std::env::set_var("FINDEVIL_HOME", v),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }

        let resp: Value = serde_json::from_str(out.trim()).expect(&out);
        assert!(resp["result"].is_object(), "expected success: {resp}");
        let body_text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let body: Value = serde_json::from_str(body_text).unwrap();
        assert!(body["id"].is_string(), "case handle has id");
        assert_eq!(
            body["image_hash"].as_str().unwrap().len(),
            64,
            "image_hash is sha256-length: {body}"
        );
        // _meta.output_sha256 is sha256 of the serialized typed output.
        assert_eq!(
            resp["result"]["_meta"]["output_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
    }
}
