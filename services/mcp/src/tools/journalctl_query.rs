//! `journalctl_query` — subprocess wrapper for `journalctl` over a binary
//! systemd journal file.
//!
//! Spec #2 §6 + the Linux-host leg of the DFIR tool surface. systemd
//! journals (`/var/log/journal/<machine-id>/*.journal`) are an opaque
//! binary format; `journalctl` is the only first-party reader. Per
//! CLAUDE.md "AGPL/GPL tools are subprocess-only", we shell out to the
//! `journalctl` binary and parse its JSON-line (`-o json`) output — we
//! never link `libsystemd`.
//!
//! `journalctl` invocation (deliberately minimal, FIXED argv):
//!   `journalctl --file <journal_path> -o json [--since <iso>]
//!     [--until <iso>]`
//!
//! `-o json` makes `journalctl` emit one JSON object per line on stdout.
//! Fields are systemd journal entry fields (`MESSAGE`, `_PID`,
//! `_SYSTEMD_UNIT`, `__REALTIME_TIMESTAMP`, etc.). We keep them generic
//! (a `Map<String, Value>` per row) rather than imposing a typed shape:
//! the field set varies per unit and per systemd version, and pinning a
//! schema here would be hostile to the agent's flexibility.
//!
//! Binary discovery mirrors `vol_pslist` / `vel_collect`:
//! `$JOURNALCTL_BIN` env var first, then PATH lookup for `journalctl`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// One parsed journal entry. Generic on purpose — the systemd field set
/// varies per unit and per version, so a typed shape would drop fields.
pub type JournalRow = serde_json::Map<String, serde_json::Value>;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalctlQueryInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to a binary systemd journal file (a `*.journal` file under
    /// `/var/log/journal/<machine-id>/` in the mounted image). Passed
    /// verbatim to `journalctl --file`.
    pub journal_path: PathBuf,

    /// Optional lower time bound passed to `journalctl --since`. systemd
    /// accepts ISO-8601 (`2026-04-25 00:00:00`) among other formats; the
    /// agent should supply a UTC ISO-8601 timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,

    /// Optional upper time bound passed to `journalctl --until`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,

    /// Hard cap on rows emitted. Default `10_000`. A busy host's journal
    /// can hold millions of entries; the cap keeps responses bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JournalctlQueryOutput {
    pub rows: Vec<JournalRow>,

    /// Total rows `journalctl` emitted before our limit was applied.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). `journalctl` prints
    /// "no journal files were found" and similar diagnostics here.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum JournalctlQueryError {
    #[error("journal file not found: {0}")]
    NotFound(PathBuf),

    #[error("journal path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error(
        "journalctl binary not on PATH (set $JOURNALCTL_BIN to override). \
         Install: `sudo apt-get install -y systemd` (Linux host or SIFT VM)."
    )]
    BinaryNotFound,

    #[error("journalctl exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not parse journalctl JSON output: {0}")]
    OutputParse(String),
}

/// Build the FIXED `journalctl` argument vector.
///
/// Extracted as a pure function so the arg contract is unit-tested. Each
/// path / time bound becomes a single argv element — never a shell
/// fragment — so a `journal_path` or `since` value that looks like a flag
/// is still a single inert argument.
fn build_journalctl_args(
    journal_path: &Path,
    since: Option<&str>,
    until: Option<&str>,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "--file".into(),
        journal_path.as_os_str().to_os_string(),
        "-o".into(),
        "json".into(),
    ];
    if let Some(s) = since {
        args.push("--since".into());
        args.push(s.into());
    }
    if let Some(u) = until {
        args.push("--until".into());
        args.push(u.into());
    }
    args
}

/// Run `journalctl` against a binary journal file and parse its rows.
///
/// # Errors
/// * [`JournalctlQueryError::NotFound`] / [`JournalctlQueryError::NotRegular`] —
///   the `journal_path` is missing or not a regular file.
/// * [`JournalctlQueryError::BinaryNotFound`] — `journalctl` not on PATH and
///   `$JOURNALCTL_BIN` unset.
/// * [`JournalctlQueryError::SubprocessFailed`] — `journalctl` returned
///   non-zero; check `stderr_tail`.
/// * [`JournalctlQueryError::OutputParse`] — a stdout line was not valid JSON
///   (rare; indicates a `journalctl` version or output-format mismatch).
pub fn journalctl_query(
    input: &JournalctlQueryInput,
) -> Result<JournalctlQueryOutput, JournalctlQueryError> {
    if !input.journal_path.exists() {
        return Err(JournalctlQueryError::NotFound(input.journal_path.clone()));
    }
    if !input.journal_path.is_file() {
        return Err(JournalctlQueryError::NotRegular(input.journal_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(build_journalctl_args(
        &input.journal_path,
        input.since.as_deref(),
        input.until.as_deref(),
    ));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            JournalctlQueryError::BinaryNotFound
        } else {
            JournalctlQueryError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(JournalctlQueryError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_rows(stdout.as_ref(), limit, stderr_tail)
}

fn resolve_binary() -> Result<PathBuf, JournalctlQueryError> {
    if let Ok(env_path) = std::env::var("JOURNALCTL_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let bin_name = if cfg!(windows) {
            "journalctl.exe"
        } else {
            "journalctl"
        };
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(JournalctlQueryError::BinaryNotFound)
}

/// Parse `journalctl -o json` output: one JSON object per line.
fn parse_rows(
    stdout: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<JournalctlQueryOutput, JournalctlQueryError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(JournalctlQueryOutput {
            rows: Vec::new(),
            rows_seen: 0,
            stderr_tail,
        });
    }

    // `-o json` is strictly line-delimited (one object per line). We still
    // parse defensively with a streaming `Deserializer` so a future
    // whitespace/pretty drift can't silently kill the lane — and an array
    // wrapper is flattened to its elements.
    let mut values: Vec<serde_json::Value> = Vec::new();
    let stream = serde_json::Deserializer::from_str(trimmed).into_iter::<serde_json::Value>();
    for item in stream {
        match item {
            Ok(serde_json::Value::Array(items)) => values.extend(items),
            Ok(value) => values.push(value),
            Err(e) => return Err(JournalctlQueryError::OutputParse(e.to_string())),
        }
    }

    let rows_seen = values.len();
    let mut rows = Vec::with_capacity(rows_seen.min(limit));
    for value in values.into_iter().take(limit) {
        if let serde_json::Value::Object(map) = value {
            rows.push(map);
        }
    }

    Ok(JournalctlQueryOutput {
        rows,
        rows_seen,
        stderr_tail,
    })
}

/// Cheap pre-flight: a path that looks like a binary systemd journal.
#[must_use]
pub fn path_looks_like_journal(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("journal"))
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk to the nearest char boundary so a multi-byte UTF-8 codepoint
        // straddling `max` (journalctl diagnostics can carry non-ASCII unit
        // names) doesn't panic `String::truncate`. Bounded at 4 bytes.
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
    fn build_args_carries_file_and_json_format() {
        let args = build_journalctl_args(Path::new("/var/log/journal/x.journal"), None, None);
        let s = as_strings(&args);
        for expected in ["--file", "/var/log/journal/x.journal", "-o", "json"] {
            assert!(
                s.contains(&expected.to_string()),
                "missing {expected} in {s:?}"
            );
        }
        // `-o json` must be a flag/value pair, in order.
        let o = s.iter().position(|a| a == "-o").unwrap();
        assert_eq!(s[o + 1], "json");
    }

    #[test]
    fn build_args_appends_since_and_until_when_present() {
        let args = build_journalctl_args(
            Path::new("/j.journal"),
            Some("2026-04-25 00:00:00"),
            Some("2026-04-26 00:00:00"),
        );
        let s = as_strings(&args);
        let since = s.iter().position(|a| a == "--since").unwrap();
        assert_eq!(s[since + 1], "2026-04-25 00:00:00");
        let until = s.iter().position(|a| a == "--until").unwrap();
        assert_eq!(s[until + 1], "2026-04-26 00:00:00");
    }

    #[test]
    fn build_args_omits_time_bounds_when_absent() {
        let args = build_journalctl_args(Path::new("/j.journal"), None, None);
        let s = as_strings(&args);
        assert!(!s.contains(&"--since".to_string()));
        assert!(!s.contains(&"--until".to_string()));
    }

    #[test]
    fn parse_rows_handles_jsonl() {
        let stdout = "{\"MESSAGE\":\"started\",\"_PID\":\"1\"}\n{\"MESSAGE\":\"stopped\"}\n";
        let out = parse_rows(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
        assert_eq!(
            out.rows[0]
                .get("MESSAGE")
                .and_then(serde_json::Value::as_str),
            Some("started")
        );
    }

    #[test]
    fn parse_rows_respects_limit() {
        let stdout = "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n";
        let out = parse_rows(stdout, 2, String::new()).unwrap();
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
    fn parse_rows_skips_non_object_rows() {
        let stdout = "{\"a\":1}\n\"scalar\"\n{\"a\":2}\n";
        let out = parse_rows(stdout, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_rejects_garbage() {
        let err = parse_rows("not json at all\n", 100, String::new()).unwrap_err();
        assert!(matches!(err, JournalctlQueryError::OutputParse(_)));
    }

    #[test]
    fn path_looks_like_journal_matches_extension() {
        assert!(path_looks_like_journal(Path::new("/x/system.journal")));
        assert!(path_looks_like_journal(Path::new("user-1000.JOURNAL")));
        assert!(!path_looks_like_journal(Path::new("/x/syslog")));
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
