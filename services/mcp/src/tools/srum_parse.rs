//! `srum_parse` — two-stage decoder for the Windows System Resource Usage
//! Monitor database (`C:\Windows\System32\sru\SRUDB.dat`).
//!
//! SRUM logs per-application and per-network-interface resource usage. The
//! forensically richest table is the **network data usage provider**
//! `{973F5D5C-1D90-4944-BE8E-24B94231A174}` — `BytesSent` / `BytesRecvd`
//! per application per hour. That is the closest thing Windows keeps to a
//! built-in record of data-transfer volume, plus application-execution
//! provenance (an app that moved bytes was running).
//!
//! DFIR HONESTY: SRUM byte counts are a **lead** for exfiltration volume,
//! never proof. High egress on a host is consistent with a backup, a sync
//! client, a browser, or exfil alike. This tool is a faithful reporter of
//! the table — it decodes and aggregates the recorded bytes and asserts
//! nothing about intent, exfiltration, or attribution. Corroborate every
//! byte total with finding-specific collection/staging plus network or
//! data-movement evidence before any exfil claim.
//!
//! TWO STAGES, DEGRADE-SAFE:
//! 1. `SRUDB.dat` is an ESE (Extensible Storage Engine) database, so it is
//!    first dumped to text with `esedbexport` (libesedb — ships on SIFT and
//!    in the DFIR container). We invoke a fixed argv
//!    `esedbexport -t <staging_prefix> <SRUDB.dat>` which writes one
//!    tab-delimited text file per table under
//!    `<staging_prefix>.export/`. The export is staged UNDER THE CASE DIR
//!    (`$FINDEVIL_HOME/cases/<case_id>/…`), never beside the read-only
//!    evidence.
//! 2. The exported network-usage table text is decoded in pure Rust by
//!    [`parse_srum_network_export`].
//!
//! When `esedbexport` is absent (the common case on a bare host without
//! libesedb) the tool returns a typed [`SrumParseOutput`] with
//! `esedbexport_available: false` and empty rows — it does NOT error, so
//! every other tool keeps working. Binary discovery: `$FINDEVIL_ESEDBEXPORT_BIN`
//! first, then PATH (default binary name `esedbexport`).
//!
//! ESEDBEXPORT DUMP COLUMN LAYOUT (what [`parse_srum_network_export`] parses):
//! `esedbexport` writes each table as a **tab (`\t`) delimited** text file.
//! The first non-empty line is a header of column names; every subsequent
//! line is one record whose fields align by position with the header. We
//! locate the columns we need by case-insensitive NAME (not fixed index, so
//! a schema/column-order change surfaces cleanly rather than silently
//! mis-reading): `AppId`, `InterfaceLuid`, `BytesSent`, `BytesRecvd`,
//! `TimeStamp`. `BytesSent`/`BytesRecvd` parse as `u64` (non-numeric → 0);
//! `InterfaceLuid` parses as `Option<u64>`; `TimeStamp` is carried through
//! as an `Option<String>` verbatim. If NEITHER a `BytesSent` nor a
//! `BytesRecvd` column is present the text is not a network-usage table and
//! zero rows are returned.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard cap on surfaced rows. The true parsed count is reported separately
/// in [`SrumParseOutput::row_count`], so a cap never hides how much the
/// table actually held.
const MAX_ROWS: usize = 5_000;

/// How many top egress applications to surface in `top_talkers`.
const MAX_TOP_TALKERS: usize = 20;

/// Distinctive prefix of the SRUM network data usage provider GUID
/// `{973F5D5C-1D90-4944-BE8E-24B94231A174}`. `esedbexport` names each output
/// file after its ESE table name; we match the exported file whose name
/// contains this GUID prefix (case-insensitive). This is a fixed Windows
/// provider identifier — a general SRUM signature, not an evidence-specific
/// literal.
const SRUM_NETWORK_GUID_PREFIX: &str = "973F5D5C";

/// Column names we look up (case-insensitive) in the esedbexport header.
const COL_APP_ID: &str = "appid";
const COL_INTERFACE_LUID: &str = "interfaceluid";
const COL_BYTES_SENT: &str = "bytessent";
const COL_BYTES_RECVD: &str = "bytesrecvd";
const COL_TIMESTAMP: &str = "timestamp";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SrumParseInput {
    /// Case ID from a prior `case_open` call. Used to locate the per-case
    /// staging directory under `$FINDEVIL_HOME/cases/<case_id>` and for
    /// audit correlation.
    pub case_id: String,

    /// Path to the SRUM ESE database to decode — a `SRUDB.dat` extracted
    /// from the evidence image (read-only; never modified).
    pub artifact_path: PathBuf,
}

/// One decoded network-usage record from the SRUM network provider table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SrumNetworkRow {
    /// Application identifier as recorded in the table's `AppId` column.
    /// In raw SRUM this is an id into the `SruDbIdMap`; `esedbexport` emits it
    /// verbatim, so it is carried through as an opaque string.
    pub app_id: String,

    /// Network interface LUID (`InterfaceLuid`), when the column is present
    /// and numeric.
    pub interface_luid: Option<u64>,

    /// Bytes sent by the application during the recorded interval.
    pub bytes_sent: u64,

    /// Bytes received by the application during the recorded interval.
    pub bytes_recvd: u64,

    /// Interval timestamp (`TimeStamp`) carried through verbatim, when present.
    pub timestamp: Option<String>,
}

/// An application aggregated by total bytes sent — the egress-volume lead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SrumTopTalker {
    /// Application identifier (matches [`SrumNetworkRow::app_id`]).
    pub app_id: String,

    /// Summed `BytesSent` across every recorded interval for this app.
    pub bytes_sent: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SrumParseOutput {
    /// Whether the `esedbexport` binary was found and runnable. `false` is
    /// the graceful degraded path (no libesedb on the host) — rows are then
    /// empty and this is NOT an error.
    pub esedbexport_available: bool,

    /// Whether the SRUM network data usage provider table was located in the
    /// export and decoded.
    pub table_found: bool,

    /// True number of network-usage records parsed (before the `MAX_ROWS`
    /// cap on `rows`).
    pub row_count: usize,

    /// Decoded rows, sorted by a stable key and capped at `MAX_ROWS`.
    pub rows: Vec<SrumNetworkRow>,

    /// Sum of `BytesSent` across every parsed row — an aggregate egress
    /// lead, not proof of exfiltration.
    pub total_bytes_sent: u64,

    /// Sum of `BytesRecvd` across every parsed row.
    pub total_bytes_recvd: u64,

    /// Highest-egress applications by summed `BytesSent`, capped at
    /// `MAX_TOP_TALKERS`.
    pub top_talkers: Vec<SrumTopTalker>,
}

#[derive(Debug, Error)]
pub enum SrumError {
    #[error("SRUM database not found: {0}")]
    NotFound(PathBuf),

    #[error("SRUM path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error("case {0} not found under FINDEVIL_HOME/cases (run case_open first)")]
    CaseNotFound(String),

    #[error("invalid case_id (must match [A-Za-z0-9_-]+, no path separators or '.'/'..'): {0}")]
    InvalidCaseId(String),

    #[error("could not prepare SRUM staging directory {path}: {source}")]
    Staging {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("esedbexport exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not read esedbexport output under {path}: {source}")]
    OutputRead {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Decode the SRUM network data usage table from a `SRUDB.dat` ESE database.
///
/// Runs `esedbexport` to dump the ESE tables, then decodes the network
/// provider table in pure Rust. When `esedbexport` is not installed the
/// result degrades to `esedbexport_available: false` with empty rows — it
/// does not error.
///
/// # Errors
/// * [`SrumError::NotFound`] / [`SrumError::NotRegular`] — the input path is
///   missing or not a regular file.
/// * [`SrumError::CaseNotFound`] — no case directory for `case_id`.
/// * [`SrumError::Staging`] — the per-case staging directory could not be
///   created.
/// * [`SrumError::SubprocessFailed`] — `esedbexport` ran but returned
///   non-zero.
/// * [`SrumError::OutputRead`] — the export directory could not be read.
pub fn srum_parse(input: &SrumParseInput) -> Result<SrumParseOutput, SrumError> {
    if !input.artifact_path.exists() {
        return Err(SrumError::NotFound(input.artifact_path.clone()));
    }
    if !input.artifact_path.is_file() {
        return Err(SrumError::NotRegular(input.artifact_path.clone()));
    }

    // Binary-missing is the primary degraded path: return a typed empty
    // result rather than erroring, exactly like indx_parse signals its
    // missing-binary case (here surfaced as a boolean field so the caller
    // can branch without matching an error).
    let Some(binary) = resolve_binary() else {
        return Ok(degraded_output(false));
    };

    let staging = prepare_staging_dir(&input.case_id)?;
    let target_prefix = staging.join("srum");
    let export_dir = export_dir_for(&target_prefix);

    let args = build_esedbexport_args(&target_prefix, &input.artifact_path);

    // Defense-in-depth pre-spawn gate: refuse a poisoned
    // $FINDEVIL_ESEDBEXPORT_BIN that resolves to a denied binary and reject
    // NUL bytes in the artifact path.
    if let Err(e) = crate::tools::argsafe::guard_spawn(&binary, &args) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(SrumError::SubprocessFailed {
            exit_code: -1,
            stderr: e.to_string(),
        });
    }

    let spawned = Command::new(&binary).args(&args).output();
    let proc = match spawned {
        Ok(proc) => proc,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            // Resolver found a path that vanished between check and spawn:
            // still the degraded (no-binary) path, not a failure.
            let _ = std::fs::remove_dir_all(&staging);
            return Ok(degraded_output(false));
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(SrumError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            });
        }
    };

    if !proc.status.success() {
        let stderr = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);
        let _ = std::fs::remove_dir_all(&staging);
        return Err(SrumError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr,
        });
    }

    let result = decode_export(&export_dir);
    let _ = std::fs::remove_dir_all(&staging);
    result
}

/// Build the fixed argv `-t <target_prefix> <artifact>`. Pure + unit-tested
/// so the invocation contract cannot silently regress.
fn build_esedbexport_args(target_prefix: &Path, artifact: &Path) -> Vec<OsString> {
    vec![
        "-t".into(),
        target_prefix.as_os_str().to_os_string(),
        artifact.as_os_str().to_os_string(),
    ]
}

/// `esedbexport -t <prefix>` writes its tables under `<prefix>.export/`.
fn export_dir_for(target_prefix: &Path) -> PathBuf {
    let mut name = target_prefix.as_os_str().to_os_string();
    name.push(".export");
    PathBuf::from(name)
}

/// Read the export directory, locate the SRUM network provider table file,
/// decode it, and assemble the aggregated output.
fn decode_export(export_dir: &Path) -> Result<SrumParseOutput, SrumError> {
    let table_path = match find_network_table_file(export_dir) {
        Ok(Some(path)) => path,
        Ok(None) => return Ok(degraded_output(true)),
        Err(source) => {
            return Err(SrumError::OutputRead {
                path: export_dir.to_path_buf(),
                source,
            });
        }
    };

    let text = std::fs::read_to_string(&table_path).map_err(|source| SrumError::OutputRead {
        path: table_path.clone(),
        source,
    })?;

    let rows = parse_srum_network_export(&text);
    Ok(assemble_output(rows))
}

/// Locate the exported table file for the SRUM network provider. `esedbexport`
/// names each file after its ESE table name, so we match the file whose name
/// contains the network provider GUID prefix (case-insensitive).
fn find_network_table_file(export_dir: &Path) -> std::io::Result<Option<PathBuf>> {
    if !export_dir.is_dir() {
        return Ok(None);
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(export_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            if name.to_ascii_uppercase().contains(SRUM_NETWORK_GUID_PREFIX) {
                candidates.push(path);
            }
        }
    }
    // Deterministic pick when esedbexport split a table across `.0`, `.1`, …
    candidates.sort();
    Ok(candidates.into_iter().next())
}

/// Turn parsed rows into the sorted, capped, aggregated output.
fn assemble_output(mut rows: Vec<SrumNetworkRow>) -> SrumParseOutput {
    rows.sort_by(|a, b| {
        a.app_id
            .cmp(&b.app_id)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
            .then_with(|| a.bytes_sent.cmp(&b.bytes_sent))
            .then_with(|| a.bytes_recvd.cmp(&b.bytes_recvd))
    });

    let row_count = rows.len();
    let (total_bytes_sent, total_bytes_recvd, top_talkers) = aggregate(&rows);
    rows.truncate(MAX_ROWS);

    SrumParseOutput {
        esedbexport_available: true,
        table_found: true,
        row_count,
        rows,
        total_bytes_sent,
        total_bytes_recvd,
        top_talkers,
    }
}

/// A typed empty result. `available` distinguishes the no-binary degraded
/// path (`false`) from a present binary whose export held no network table
/// (`true`, `table_found: false`).
const fn degraded_output(available: bool) -> SrumParseOutput {
    SrumParseOutput {
        esedbexport_available: available,
        table_found: false,
        row_count: 0,
        rows: Vec::new(),
        total_bytes_sent: 0,
        total_bytes_recvd: 0,
        top_talkers: Vec::new(),
    }
}

/// Sum egress/ingress and rank applications by total bytes sent. Saturating
/// addition keeps a corrupt oversized field from wrapping the totals.
fn aggregate(rows: &[SrumNetworkRow]) -> (u64, u64, Vec<SrumTopTalker>) {
    let mut total_sent: u64 = 0;
    let mut total_recvd: u64 = 0;
    let mut per_app: BTreeMap<String, u64> = BTreeMap::new();
    for row in rows {
        total_sent = total_sent.saturating_add(row.bytes_sent);
        total_recvd = total_recvd.saturating_add(row.bytes_recvd);
        let entry = per_app.entry(row.app_id.clone()).or_insert(0);
        *entry = entry.saturating_add(row.bytes_sent);
    }

    let mut talkers: Vec<SrumTopTalker> = per_app
        .into_iter()
        .map(|(app_id, bytes_sent)| SrumTopTalker { app_id, bytes_sent })
        .collect();
    // Highest egress first; app_id ascending as a stable tie-break.
    talkers.sort_by(|a, b| {
        b.bytes_sent
            .cmp(&a.bytes_sent)
            .then_with(|| a.app_id.cmp(&b.app_id))
    });
    talkers.truncate(MAX_TOP_TALKERS);

    (total_sent, total_recvd, talkers)
}

/// Parse an `esedbexport` tab-delimited table dump into typed network rows.
///
/// See the module doc for the exact column layout. Columns are located by
/// case-insensitive name in the header; rows are aligned by position. If the
/// text has no `BytesSent`/`BytesRecvd` column it is not a network-usage
/// table and an empty vec is returned. A short or malformed row never
/// panics — absent fields default (`bytes_* = 0`, `interface_luid`/
/// `timestamp = None`).
fn parse_srum_network_export(text: &str) -> Vec<SrumNetworkRow> {
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let Some(header_line) = lines.next() else {
        return Vec::new();
    };

    let headers: Vec<String> = header_line
        .split('\t')
        .map(|h| h.trim().to_ascii_lowercase())
        .collect();

    let find = |name: &str| headers.iter().position(|h| h == name);
    let idx_sent = find(COL_BYTES_SENT);
    let idx_recvd = find(COL_BYTES_RECVD);
    // Neither byte column → not the network table.
    if idx_sent.is_none() && idx_recvd.is_none() {
        return Vec::new();
    }
    let idx_app = find(COL_APP_ID);
    let idx_luid = find(COL_INTERFACE_LUID);
    let idx_ts = find(COL_TIMESTAMP);

    let mut rows = Vec::new();
    for line in lines {
        let fields: Vec<&str> = line.split('\t').collect();
        let field_at = |idx: Option<usize>| idx.and_then(|i| fields.get(i)).map(|s| s.trim());

        let app_id = field_at(idx_app).unwrap_or("").to_string();
        let bytes_sent = field_at(idx_sent)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let bytes_recvd = field_at(idx_recvd)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        let interface_luid = field_at(idx_luid).and_then(|s| s.parse::<u64>().ok());
        let timestamp = field_at(idx_ts)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        rows.push(SrumNetworkRow {
            app_id,
            interface_luid,
            bytes_sent,
            bytes_recvd,
            timestamp,
        });
    }
    rows
}

/// Create a fresh per-case staging directory under
/// `$FINDEVIL_HOME/cases/<case_id>/_xartifact/srum-<pid>-<nanos>`. Derived
/// entirely at runtime; never beside the read-only evidence.
fn prepare_staging_dir(case_id: &str) -> Result<PathBuf, SrumError> {
    let case = case_dir(case_id)?;
    let staging =
        case.join("_xartifact")
            .join(format!("srum-{}-{}", std::process::id(), nanosecond_tag()));
    std::fs::create_dir_all(&staging).map_err(|source| SrumError::Staging {
        path: staging.clone(),
        source,
    })?;
    Ok(staging)
}

/// Locate the case directory, mirroring the canonical
/// `$FINDEVIL_HOME/cases/<case_id>` layout used across the tool surface.
fn case_dir(case_id: &str) -> Result<PathBuf, SrumError> {
    if !super::case_id::is_valid_case_id(case_id) {
        return Err(SrumError::InvalidCaseId(case_id.to_string()));
    }
    let dir = findevil_home()?.join("cases").join(case_id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(SrumError::CaseNotFound(case_id.to_string()))
    }
}

fn findevil_home() -> Result<PathBuf, SrumError> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h).join(".findevil"));
        }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p).join(".findevil"));
        }
    }
    Err(SrumError::CaseNotFound("FINDEVIL_HOME".to_string()))
}

/// Resolve the exporter binary from `$FINDEVIL_ESEDBEXPORT_BIN` (default
/// `esedbexport`), then PATH — exactly the env-var-with-default discovery
/// used by `ez_parse`/`indx_parse`. Returns `None` when absent (the graceful
/// degraded path).
fn resolve_binary() -> Option<PathBuf> {
    let name =
        std::env::var("FINDEVIL_ESEDBEXPORT_BIN").unwrap_or_else(|_| "esedbexport".to_string());
    if name.is_empty() {
        return None;
    }

    // An explicit, existing path is used directly.
    let direct = PathBuf::from(&name);
    if direct.is_file() {
        return Some(direct);
    }

    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name
    };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(&exe);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn nanosecond_tag() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("…[truncated]");
    }
    s
}

// ---------------------------------------------------------------------------
// Unit tests: the pure decode + aggregation. The real esedbexport invocation
// stays opt-in via $FINDEVIL_ESEDBEXPORT_BIN (install-first tool), so it is
// not exercised here — exactly as indx_parse unit-tests only its pure parser.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic esedbexport-style dump of the SRUM network provider table,
    /// matching the tab-delimited layout documented in the module doc.
    fn sample_dump() -> String {
        // header then four rows; columns are intentionally NOT in id order to
        // prove the parser keys on name, not position.
        let mut s = String::new();
        s.push_str("AutoIncId\tTimeStamp\tAppId\tInterfaceLuid\tBytesSent\tBytesRecvd\n");
        s.push_str("1\t2026-04-25 10:00:00\tapp-a\t1001\t500\t100\n");
        s.push_str("2\t2026-04-25 11:00:00\tapp-a\t1001\t1500\t200\n");
        s.push_str("3\t2026-04-25 10:00:00\tapp-b\t1002\t9000\t50\n");
        s.push_str("4\t2026-04-25 12:00:00\tapp-c\t1003\t10\t3000\n");
        s
    }

    #[test]
    fn build_args_are_dash_t_prefix_then_artifact() {
        let args = build_esedbexport_args(
            Path::new("/case/_xartifact/srum-1-2/srum"),
            Path::new("/evidence/SRUDB.dat"),
        );
        let s: Vec<String> = args
            .iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            s,
            vec![
                "-t",
                "/case/_xartifact/srum-1-2/srum",
                "/evidence/SRUDB.dat"
            ]
        );
    }

    #[test]
    fn export_dir_appends_dot_export() {
        let dir = export_dir_for(Path::new("/case/stage/srum"));
        assert_eq!(dir, PathBuf::from("/case/stage/srum.export"));
    }

    #[test]
    fn parse_decodes_rows_by_column_name() {
        let rows = parse_srum_network_export(&sample_dump());
        assert_eq!(rows.len(), 4);
        // Values keyed by NAME regardless of the extra AutoIncId column first.
        let first = rows.iter().find(|r| r.app_id == "app-b").unwrap();
        assert_eq!(first.bytes_sent, 9000);
        assert_eq!(first.bytes_recvd, 50);
        assert_eq!(first.interface_luid, Some(1002));
        assert_eq!(first.timestamp.as_deref(), Some("2026-04-25 10:00:00"));
    }

    #[test]
    fn assemble_sorts_by_stable_key() {
        let rows = parse_srum_network_export(&sample_dump());
        let out = assemble_output(rows);
        // Stable key: app_id, then timestamp, then byte counts.
        let ordered: Vec<(&str, u64)> = out
            .rows
            .iter()
            .map(|r| (r.app_id.as_str(), r.bytes_sent))
            .collect();
        assert_eq!(
            ordered,
            vec![
                ("app-a", 500), // 10:00 before 11:00
                ("app-a", 1500),
                ("app-b", 9000),
                ("app-c", 10),
            ]
        );
    }

    #[test]
    fn aggregate_totals_are_summed() {
        let rows = parse_srum_network_export(&sample_dump());
        let out = assemble_output(rows);
        // sent: 500 + 1500 + 9000 + 10 = 11010
        assert_eq!(out.total_bytes_sent, 11_010);
        // recvd: 100 + 200 + 50 + 3000 = 3350
        assert_eq!(out.total_bytes_recvd, 3_350);
        assert_eq!(out.row_count, 4);
    }

    #[test]
    fn top_talkers_ranked_by_summed_bytes_sent() {
        let rows = parse_srum_network_export(&sample_dump());
        let out = assemble_output(rows);
        // app-a totals 2000, app-b 9000, app-c 10 → b, a, c.
        let ranked: Vec<(&str, u64)> = out
            .top_talkers
            .iter()
            .map(|t| (t.app_id.as_str(), t.bytes_sent))
            .collect();
        assert_eq!(
            ranked,
            vec![("app-b", 9000), ("app-a", 2000), ("app-c", 10)]
        );
    }

    #[test]
    fn empty_dump_yields_zero_rows_without_panic() {
        assert!(parse_srum_network_export("").is_empty());
        assert!(parse_srum_network_export("   \n  \n").is_empty());
    }

    #[test]
    fn header_without_byte_columns_is_not_a_network_table() {
        // A different SRUM provider (e.g. energy usage) — no BytesSent/Recvd.
        let text = "AutoIncId\tTimeStamp\tAppId\tChargeLevel\n1\tt\tapp\t80\n";
        assert!(parse_srum_network_export(text).is_empty());
    }

    #[test]
    fn short_and_nonnumeric_rows_default_without_panic() {
        // Row 2 is truncated (missing trailing columns); row 3 has a
        // non-numeric BytesSent. Neither must panic.
        let text = "TimeStamp\tAppId\tInterfaceLuid\tBytesSent\tBytesRecvd\n\
                    t1\tapp-a\t7\t123\t9\n\
                    t2\tapp-b\n\
                    t3\tapp-c\tNaN\tNaN\tNaN\n";
        let rows = parse_srum_network_export(text);
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].bytes_sent, 123);
        // truncated row: fields absent → defaults
        assert_eq!(rows[1].app_id, "app-b");
        assert_eq!(rows[1].bytes_sent, 0);
        assert_eq!(rows[1].interface_luid, None);
        assert_eq!(rows[1].timestamp.as_deref(), Some("t2"));
        // non-numeric bytes → 0, non-numeric luid → None
        assert_eq!(rows[2].bytes_sent, 0);
        assert_eq!(rows[2].bytes_recvd, 0);
        assert_eq!(rows[2].interface_luid, None);
    }

    #[test]
    fn only_one_byte_column_still_parses() {
        // BytesRecvd present but BytesSent absent — still a network table.
        let text = "AppId\tBytesRecvd\napp-a\t4096\n";
        let rows = parse_srum_network_export(text);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].bytes_recvd, 4096);
        assert_eq!(rows[0].bytes_sent, 0);
    }

    #[test]
    fn degraded_output_no_binary_is_empty_and_flagged() {
        let out = degraded_output(false);
        assert!(!out.esedbexport_available);
        assert!(!out.table_found);
        assert_eq!(out.row_count, 0);
        assert!(out.rows.is_empty());
        assert!(out.top_talkers.is_empty());
        assert_eq!(out.total_bytes_sent, 0);
        assert_eq!(out.total_bytes_recvd, 0);
    }

    #[test]
    fn find_network_table_matches_guid_prefix() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("MSysObjects.0"), "x").unwrap();
        std::fs::write(
            dir.path().join("{973F5D5C-1D90-4944-BE8E-24B94231A174}.0"),
            "x",
        )
        .unwrap();
        let found = find_network_table_file(dir.path()).unwrap();
        let name = found
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap();
        assert!(name.to_ascii_uppercase().contains(SRUM_NETWORK_GUID_PREFIX));
    }

    #[test]
    fn find_network_table_none_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("MSysObjects.0"), "x").unwrap();
        assert!(find_network_table_file(dir.path()).unwrap().is_none());
    }

    #[test]
    fn truncate_to_passthrough_and_multibyte_safe() {
        assert_eq!(truncate_to("short".to_string(), 100), "short");
        let s: String = "\u{FFFD}".repeat(1000);
        let out = truncate_to(s, 100);
        assert!(out.ends_with("…[truncated]"));
    }
}
