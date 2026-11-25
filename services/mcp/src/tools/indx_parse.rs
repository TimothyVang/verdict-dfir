//! `indx_parse` — subprocess wrapper for Willi Ballenthin's `INDXParse.py`.
//!
//! `INDXParse.py` parses NTFS directory-index (`$I30` / `INDX`) records,
//! including entries recovered from index slack space. The `$I30`
//! stream is the canonical "a file used to live in this directory"
//! artifact: even after a file is deleted and its `$MFT` record reused,
//! its `INDX` entry can survive in slack, carrying the `$FN` MAC times.
//! That makes it a Pool A / Pool B corroboration surface for
//! anti-forensic deletion.
//!
//! INSTALL-FIRST: `INDXParse.py` is NOT on stock SIFT. Install via
//! `pip install INDXParse` (or `pipx install INDXParse`), which exposes
//! the `INDXParse.py` console script. When absent the tool returns a
//! graceful [`IndxError::BinaryNotFound`] — every other tool keeps
//! working.
//!
//! Invocation (deliberately minimal, fixed argv):
//!   `INDXParse.py <indx_path>`
//!
//! With no mode flag, `INDXParse.py` defaults to CSV output of the
//! `dir` index type. The format is NOT RFC-4180 CSV — it is a
//! `,\t` (comma-then-tab) delimited table with NO field quoting,
//! emitted by the tool's own `entry_dir_csv` formatter. The first
//! line is a header; each subsequent line is one index entry. We parse
//! that literal delimiter into generic `rows` (`BTreeMap<String,
//! String>`, header column to value) so a future column change in the
//! tool surfaces as new keys rather than a silent mismatch.
//!
//! Binary discovery: `$INDXPARSE_BIN` env var first, then PATH lookup
//! for `INDXParse.py`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// The literal field delimiter `INDXParse.py` writes between columns
/// in both its header line and its data rows (`entry_dir_csv`):
/// a comma immediately followed by a tab.
const INDX_DELIMITER: &str = ",\t";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IndxParseInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the NTFS directory-index stream to parse — a carved
    /// `$I30` / `INDX` file extracted from the evidence image.
    pub indx_path: PathBuf,

    /// Hard cap on rows returned. Default `10_000`. A single directory
    /// index rarely holds more, but slack-space recovery on a large
    /// directory can inflate the count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IndxParseOutput {
    /// Parsed index entries. Each row maps a header column
    /// (`FILENAME`, `PHYSICAL SIZE`, `LOGICAL SIZE`, `MODIFIED TIME`,
    /// `ACCESSED TIME`, `CHANGED TIME`, `CREATED TIME`) to its value,
    /// exactly as `INDXParse.py` emitted it. Kept unstructured so a
    /// column change in the tool is visible rather than silently
    /// dropped.
    pub rows: Vec<BTreeMap<String, String>>,

    /// Total entries `INDXParse.py` emitted before our limit.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). `INDXParse.py` prints
    /// debug / parse warnings here.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum IndxError {
    #[error("INDX file not found: {0}")]
    NotFound(PathBuf),

    #[error("INDX path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error(
        "INDXParse.py not on PATH (set $INDXPARSE_BIN to override). \
         Install: `pip install INDXParse` (or `pipx install INDXParse`)."
    )]
    BinaryNotFound,

    #[error("INDXParse.py exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not parse INDXParse.py output: {0}")]
    OutputParse(String),
}

/// Run `INDXParse.py` against a carved NTFS `$I30` / `INDX` stream and
/// return its directory-index entries.
///
/// # Errors
/// * [`IndxError::NotFound`] / [`IndxError::NotRegular`] — the input
///   path is missing or is not a regular file.
/// * [`IndxError::BinaryNotFound`] — `INDXParse.py` not on PATH and
///   `$INDXPARSE_BIN` unset.
/// * [`IndxError::SubprocessFailed`] — `INDXParse.py` returned
///   non-zero; check `stderr_tail` in the error.
/// * [`IndxError::OutputParse`] — stdout had no parseable header line.
pub fn indx_parse(input: &IndxParseInput) -> Result<IndxParseOutput, IndxError> {
    if !input.indx_path.exists() {
        return Err(IndxError::NotFound(input.indx_path.clone()));
    }
    if !input.indx_path.is_file() {
        return Err(IndxError::NotRegular(input.indx_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let args = build_indx_args(&input.indx_path);
    let proc = Command::new(&binary).args(&args).output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            IndxError::BinaryNotFound
        } else {
            IndxError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(IndxError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_indx_csv(stdout.as_ref(), limit, stderr_tail)
}

/// Build the fixed argv for `INDXParse.py`. The default (no mode flag)
/// is CSV output of the `dir` index type — exactly what `parse_indx_csv`
/// consumes — so we pass only the input path.
fn build_indx_args(indx_path: &std::path::Path) -> Vec<std::ffi::OsString> {
    vec![indx_path.as_os_str().to_os_string()]
}

fn resolve_binary() -> Result<PathBuf, IndxError> {
    if let Ok(env_path) = std::env::var("INDXPARSE_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        // The pip/pipx console script is named `INDXParse.py` on every
        // platform. On Windows the launcher may also be `INDXParse.py.exe`.
        let candidates: &[&str] = if cfg!(windows) {
            &["INDXParse.py.exe", "INDXParse.py"]
        } else {
            &["INDXParse.py"]
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
    Err(IndxError::BinaryNotFound)
}

/// Parse `INDXParse.py`'s default `dir`/CSV output.
///
/// The format is the tool's own `,\t`-delimited table (NOT RFC CSV,
/// no quoting): the first non-empty line is a header, each subsequent
/// line is one index entry. We zip each row against the header. A row
/// with MORE fields than the header (a filename literally containing
/// `,\t`, which the tool does not escape) has its overflow re-joined
/// into the final header column so no bytes are lost; a row with FEWER
/// fields leaves the trailing header columns absent from its map.
fn parse_indx_csv(
    stdout: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<IndxParseOutput, IndxError> {
    let mut lines = stdout.lines().filter(|l| !l.trim().is_empty());

    let Some(header_line) = lines.next() else {
        // No header at all: an empty INDX yields no output. Treat as a
        // clean zero-row result rather than a parse failure.
        return Ok(IndxParseOutput {
            rows: Vec::new(),
            rows_seen: 0,
            stderr_tail,
        });
    };

    let headers: Vec<String> = header_line
        .split(INDX_DELIMITER)
        .map(|h| h.trim().to_string())
        .collect();
    if headers.is_empty() {
        return Err(IndxError::OutputParse(
            "header line had no columns".to_string(),
        ));
    }

    let mut rows_seen = 0usize;
    let mut rows = Vec::new();
    for line in lines {
        rows_seen += 1;
        if rows.len() < limit {
            rows.push(row_to_map(line, &headers));
        }
    }

    Ok(IndxParseOutput {
        rows,
        rows_seen,
        stderr_tail,
    })
}

/// Zip one data line against the header columns. Overflow fields (the
/// unescaped-delimiter-in-filename case) are re-joined into the last
/// column so the row is preserved verbatim.
fn row_to_map(line: &str, headers: &[String]) -> BTreeMap<String, String> {
    let fields: Vec<&str> = line.split(INDX_DELIMITER).collect();
    let last_idx = headers.len() - 1;
    let mut map = BTreeMap::new();
    for (i, header) in headers.iter().enumerate() {
        let value = if i == last_idx && fields.len() > headers.len() {
            // Re-join overflow into the final column.
            fields[i..].join(INDX_DELIMITER)
        } else if let Some(v) = fields.get(i) {
            (*v).to_string()
        } else {
            // Row shorter than the header — column absent.
            continue;
        };
        map.insert(header.clone(), value.trim().to_string());
    }
    map
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk down to the nearest char boundary so multi-byte UTF-8
        // (INDXParse.py can emit Unicode filenames in warnings) doesn't
        // panic `String::truncate`. Bounded at 4 bytes per codepoint.
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
// Unit tests for the argv builder + parser. The actual INDXParse.py
// invocation stays opt-in via $INDXPARSE_BIN (install-first tool).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_indx_args_passes_only_the_path() {
        let args = build_indx_args(std::path::Path::new("/case/extracted/I30"));
        assert_eq!(args, vec![std::ffi::OsString::from("/case/extracted/I30")]);
    }

    #[test]
    fn parse_indx_csv_parses_header_and_rows() {
        // The literal default `dir`/CSV shape INDXParse.py emits:
        // a `,\t`-delimited header followed by `,\t`-delimited rows.
        let stdout = "FILENAME,\tPHYSICAL SIZE,\tLOGICAL SIZE,\tMODIFIED TIME,\t\
                      ACCESSED TIME,\tCHANGED TIME,\tCREATED TIME\n\
                      evil.exe,\t1024,\t900,\t2026-04-25 10:00:00,\t\
                      2026-04-25 10:00:00,\t2026-04-25 10:00:00,\t2026-04-25 09:00:00\n\
                      report.docx,\t2048,\t2000,\t2026-04-26 08:00:00,\t\
                      2026-04-26 08:00:00,\t2026-04-26 08:00:00,\t2026-04-26 07:00:00\n";
        let out = parse_indx_csv(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(
            out.rows[0].get("FILENAME").map(String::as_str),
            Some("evil.exe")
        );
        assert_eq!(
            out.rows[0].get("PHYSICAL SIZE").map(String::as_str),
            Some("1024")
        );
        assert_eq!(
            out.rows[0].get("CREATED TIME").map(String::as_str),
            Some("2026-04-25 09:00:00")
        );
        assert_eq!(
            out.rows[1].get("FILENAME").map(String::as_str),
            Some("report.docx")
        );
    }

    #[test]
    fn parse_indx_csv_empty_output_is_zero_rows() {
        let out = parse_indx_csv("", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn parse_indx_csv_header_only_is_zero_rows() {
        let stdout = "FILENAME,\tPHYSICAL SIZE,\tLOGICAL SIZE,\tMODIFIED TIME,\t\
                      ACCESSED TIME,\tCHANGED TIME,\tCREATED TIME\n";
        let out = parse_indx_csv(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn parse_indx_csv_respects_limit() {
        let stdout = "A,\tB\n1,\t2\n3,\t4\n5,\t6\n";
        let out = parse_indx_csv(stdout, 2, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3, "rows_seen counts every data line");
        assert_eq!(out.rows.len(), 2, "rows[] is capped at the limit");
    }

    #[test]
    fn row_to_map_rejoins_overflow_into_last_column() {
        // A slack-recovered filename containing the unescaped `,\t`
        // delimiter must not corrupt the columns to its right; the
        // overflow re-joins into the final header column.
        let headers: Vec<String> = vec!["FILENAME".into(), "SIZE".into()];
        let map = row_to_map("weird,\tname,\t512", &headers);
        // 3 fields, 2 headers → overflow re-joined into the LAST header.
        assert_eq!(map.get("FILENAME").map(String::as_str), Some("weird"));
        assert_eq!(map.get("SIZE").map(String::as_str), Some("name,\t512"));
    }

    #[test]
    fn row_to_map_shorter_row_leaves_trailing_columns_absent() {
        let headers: Vec<String> = vec!["A".into(), "B".into(), "C".into()];
        let map = row_to_map("1,\t2", &headers);
        assert_eq!(map.get("A").map(String::as_str), Some("1"));
        assert_eq!(map.get("B").map(String::as_str), Some("2"));
        assert!(!map.contains_key("C"), "missing trailing column is absent");
    }

    #[test]
    fn truncate_to_passthrough_when_short_enough() {
        let s = "short".to_string();
        assert_eq!(truncate_to(s, 100), "short");
    }

    #[test]
    fn truncate_to_does_not_panic_on_multibyte_boundary() {
        let s: String = "\u{FFFD}".repeat(1000);
        assert_eq!(s.len(), 3000);
        let out = truncate_to(s, 100);
        assert!(out.ends_with("…[truncated]"));
        let body_len = out.len() - "…[truncated]".len();
        assert!(out.is_char_boundary(body_len));
    }
}
