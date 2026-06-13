//! `nfdump_query` — subprocess wrapper for `nfdump` (`NetFlow` / IPFIX flow reader).
//!
//! Spec #2 §6 + the network-flow leg of the DFIR tool surface. `nfdump`
//! (BSD-3-Clause; safe to invoke as a subprocess) reads captured `NetFlow`
//! v5/v9, IPFIX, and `sFlow` records and renders them as rows. Pool B exfil
//! triage: large outbound byte counts, beaconing to a single destination, or
//! connections to a known-bad IP all surface in flow data without needing the
//! full packet capture.
//!
//! `nfdump` invocation (deliberately minimal, FIXED argv):
//!   `nfdump -r <flow_path> -o json`
//!
//! `-o json` makes `nfdump` emit a JSON array of flow records to stdout. There
//! is deliberately NO free-text filter field — `nfdump`'s filter language is a
//! second argv element that would be an injection sink, so the agent narrows
//! results with the typed `limit` instead and does its own row filtering.
//!
//! Binary discovery mirrors `vol_pslist` / `vel_collect`: `$NFDUMP_BIN` env var
//! first, then PATH lookup for `nfdump` (and `.exe` on Windows). `nfdump` is an
//! INSTALL-FIRST tool — absent on the stock SIFT VM — so the spawn path degrades
//! to a typed `BinaryNotFound` rather than crashing the lane.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NfdumpQueryInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the captured flow file (an `nfcapd`-style `NetFlow` / IPFIX
    /// dump). Passed verbatim to `nfdump -r`; read-only.
    pub flow_path: PathBuf,

    /// Hard cap on rows returned. Default `10_000`. A busy collector can
    /// emit millions of flow records, so the cap keeps responses bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NfdumpQueryOutput {
    /// Flow records, one generic column map per row exactly as `nfdump`
    /// emitted them. Deliberately unstructured — `nfdump`'s JSON column set
    /// varies with the source flow version and aggregation flags.
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,

    /// Total rows `nfdump` emitted before our limit was applied.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). `nfdump` prints read summaries
    /// and format warnings here; useful when `rows` is empty.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum NfdumpQueryError {
    #[error("flow file not found: {0}")]
    FlowNotFound(PathBuf),

    #[error("flow path is not a regular file: {0}")]
    FlowNotRegular(PathBuf),

    #[error(
        "nfdump binary not on PATH (set $NFDUMP_BIN to override). \
         Install: `sudo apt-get install -y nfdump`."
    )]
    BinaryNotFound,

    #[error("nfdump exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not parse nfdump JSON output: {0}")]
    OutputParse(String),
}

/// Build the FIXED `nfdump` argument vector: `-r <flow_path> -o json`.
///
/// Extracted as a pure function so the argv contract is unit-tested and the
/// "no free-text filter" invariant is visible at a glance.
fn build_nfdump_args(flow_path: &Path) -> Vec<OsString> {
    vec![
        "-r".into(),
        flow_path.as_os_str().to_os_string(),
        "-o".into(),
        "json".into(),
    ]
}

/// Run `nfdump -r <flow_path> -o json` and parse the flow records.
///
/// # Errors
/// * [`NfdumpQueryError::FlowNotFound`] / [`NfdumpQueryError::FlowNotRegular`] —
///   the supplied `flow_path` is missing or not a regular file.
/// * [`NfdumpQueryError::BinaryNotFound`] — `nfdump` not on PATH and
///   `$NFDUMP_BIN` unset.
/// * [`NfdumpQueryError::SubprocessFailed`] — `nfdump` returned non-zero;
///   check `stderr_tail` in the error.
/// * [`NfdumpQueryError::OutputParse`] — stdout was not the expected JSON;
///   usually an `nfdump` version mismatch.
pub fn nfdump_query(input: &NfdumpQueryInput) -> Result<NfdumpQueryOutput, NfdumpQueryError> {
    if !input.flow_path.exists() {
        return Err(NfdumpQueryError::FlowNotFound(input.flow_path.clone()));
    }
    if !input.flow_path.is_file() {
        return Err(NfdumpQueryError::FlowNotRegular(input.flow_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(build_nfdump_args(&input.flow_path));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            NfdumpQueryError::BinaryNotFound
        } else {
            NfdumpQueryError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(NfdumpQueryError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_rows(stdout.as_ref(), limit, stderr_tail)
}

fn resolve_binary() -> Result<PathBuf, NfdumpQueryError> {
    if let Ok(env_path) = std::env::var("NFDUMP_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let candidates: &[&str] = if cfg!(windows) {
            &["nfdump.exe", "nfdump"]
        } else {
            &["nfdump"]
        };
        for dir in std::env::split_paths(&path_var) {
            for name in candidates {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(NfdumpQueryError::BinaryNotFound)
}

fn parse_rows(
    stdout: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<NfdumpQueryOutput, NfdumpQueryError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(NfdumpQueryOutput {
            rows: Vec::new(),
            rows_seen: 0,
            stderr_tail,
        });
    }

    // `nfdump -o json` emits a single JSON array. We parse defensively for any
    // whitespace-separated sequence of JSON values (an array flattened to its
    // elements, single-line JSONL, or concatenated objects) so a future format
    // drift can't silently kill the lane the way a strict array parser would.
    let mut all_rows: Vec<serde_json::Value> = Vec::new();
    let stream = serde_json::Deserializer::from_str(trimmed).into_iter::<serde_json::Value>();
    for item in stream {
        match item {
            Ok(serde_json::Value::Array(items)) => all_rows.extend(items),
            Ok(value) => all_rows.push(value),
            Err(e) => return Err(NfdumpQueryError::OutputParse(e.to_string())),
        }
    }

    let rows_seen = all_rows.len();
    let mut out = Vec::with_capacity(rows_seen.min(limit));
    for value in all_rows.into_iter().take(limit) {
        if let serde_json::Value::Object(fields) = value {
            out.push(fields);
        }
    }

    Ok(NfdumpQueryOutput {
        rows: out,
        rows_seen,
        stderr_tail,
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk to the nearest char boundary so a multi-byte UTF-8 codepoint
        // (nfdump warnings can carry non-ASCII hostnames) doesn't panic
        // `String::truncate`. The walk is bounded at 4 bytes per codepoint.
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("…[truncated]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn build_nfdump_args_is_fixed_read_json() {
        let args = build_nfdump_args(Path::new("/flows/nfcapd.0001"));
        let s = as_strings(&args);
        assert_eq!(s, vec!["-r", "/flows/nfcapd.0001", "-o", "json"]);
    }

    #[test]
    fn build_nfdump_args_has_no_filter_field() {
        // The injection guard: argv carries no free-text filter element, so a
        // hostile flow_path can never smuggle in an nfdump filter expression.
        let args = build_nfdump_args(Path::new("/flows/x"));
        let s = as_strings(&args);
        assert_eq!(s.len(), 4, "exactly -r PATH -o json, nothing else: {s:?}");
        assert!(!s.iter().any(|a| a == "-f" || a == "-O"));
    }

    #[test]
    fn parse_rows_handles_json_array() {
        let stdout =
            r#"[{"sa":"10.0.0.1","da":"10.0.0.2","ibyt":1200},{"sa":"10.0.0.3","ibyt":4}]"#;
        let out = parse_rows(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(
            out.rows[0].get("sa").and_then(serde_json::Value::as_str),
            Some("10.0.0.1")
        );
    }

    #[test]
    fn parse_rows_handles_jsonl_fallback() {
        let stdout = "{\"sa\":\"10.0.0.1\"}\n{\"sa\":\"10.0.0.2\"}\n";
        let out = parse_rows(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_respects_limit() {
        let stdout = r#"[{"a":1},{"a":2},{"a":3},{"a":4}]"#;
        let out = parse_rows(stdout, 2, String::new()).unwrap();
        assert_eq!(out.rows_seen, 4);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_skips_non_object_rows() {
        let stdout = "{\"a\":1}\n\"stray scalar\"\n{\"a\":2}\n";
        let out = parse_rows(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_empty_stdout_is_no_rows() {
        let out = parse_rows("   \n", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn parse_rows_rejects_garbage() {
        let err = parse_rows("not json at all\n", 100, String::new()).unwrap_err();
        assert!(matches!(err, NfdumpQueryError::OutputParse(_)));
    }

    #[test]
    fn missing_flow_file_is_typed_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.nfcapd");
        let err = nfdump_query(&NfdumpQueryInput {
            case_id: "c".to_string(),
            flow_path: missing,
            limit: None,
        })
        .unwrap_err();
        assert!(matches!(err, NfdumpQueryError::FlowNotFound(_)));
    }

    #[test]
    fn directory_flow_path_is_not_regular() {
        let tmp = tempfile::tempdir().unwrap();
        let err = nfdump_query(&NfdumpQueryInput {
            case_id: "c".to_string(),
            flow_path: tmp.path().to_path_buf(),
            limit: None,
        })
        .unwrap_err();
        assert!(matches!(err, NfdumpQueryError::FlowNotRegular(_)));
    }

    #[test]
    fn truncate_to_does_not_panic_on_multibyte_boundary() {
        let s: String = "\u{FFFD}".repeat(1000);
        assert_eq!(s.len(), 3000);
        let out = truncate_to(s, 100);
        assert!(out.ends_with("…[truncated]"));
        let body_len = out.len() - "…[truncated]".len();
        assert!(body_len <= 100);
        assert!(out.is_char_boundary(body_len));
    }
}
