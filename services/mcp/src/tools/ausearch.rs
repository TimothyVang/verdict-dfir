//! `ausearch` — subprocess wrapper for the Linux audit framework's
//! `ausearch` reader over an `audit.log`.
//!
//! Spec #2 §6 + the Linux-host leg of the DFIR tool surface. The Linux
//! audit daemon (`auditd`) writes `/var/log/audit/audit.log`: the
//! authoritative record of `execve`, `connect`, file-access, and other
//! syscall-level events on a hardened host. `ausearch` (from the
//! `audit` / `audit-libs` package) is the canonical reader; its `-i`
//! flag interprets numeric uids/gids/syscalls into names. Per CLAUDE.md
//! the convention is to invoke external readers as a SUBPROCESS.
//!
//! NB: `ausearch` is an INSTALL-FIRST tool — it is NOT present on the
//! stock SANS SIFT VM, so a missing binary is an honest limitation
//! ([`AusearchError::BinaryNotFound`]) rather than a crash.
//!
//! `ausearch` invocation (deliberately minimal, FIXED argv):
//!   `ausearch -i -if <audit_log_path>`
//!     -i   interpret numeric fields (uid -> name, syscall -> name)
//!     -if  read this input file instead of the live audit log
//!
//! `ausearch` groups related records into events separated by a blank
//! line and a leading `----` rule. Each line is `key=value key=value …`
//! plus a `type=…` tag; we parse each `type=…` line into a generic row
//! (a `Map<String, Value>`) so the variable field set per record type
//! is preserved.
//!
//! Binary discovery mirrors `vol_pslist` / `vel_collect`:
//! `$AUSEARCH_BIN` env var first, then PATH lookup for `ausearch`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// One parsed audit record. Generic on purpose — the audit field set
/// varies per record `type` (`SYSCALL` / `EXECVE` / `PATH` / `USER_LOGIN` …),
/// so a typed shape would drop fields.
pub type AuditRow = serde_json::Map<String, serde_json::Value>;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AusearchInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to a Linux audit log (`/var/log/audit/audit.log` or a
    /// rotated `audit.log.N`) from the mounted image. Passed verbatim
    /// to `ausearch -if`.
    pub audit_log_path: PathBuf,

    /// Hard cap on rows emitted. Default `10_000`. A busy hardened host's
    /// audit log can hold millions of records; the cap keeps responses
    /// bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AusearchOutput {
    pub rows: Vec<AuditRow>,

    /// Total `type=…` records parsed before our limit was applied.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). `ausearch` prints
    /// "<not interpreted>" warnings and parse diagnostics here.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum AusearchError {
    #[error("audit log not found: {0}")]
    NotFound(PathBuf),

    #[error("audit log path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error(
        "ausearch binary not on PATH (set $AUSEARCH_BIN to override). \
         Install: `sudo apt-get install -y auditd` — ausearch is NOT on the stock SIFT VM."
    )]
    BinaryNotFound,

    #[error("ausearch exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },
}

/// Build the FIXED `ausearch` argument vector.
///
/// Extracted as a pure function so the arg contract is unit-tested. The
/// `audit_log_path` becomes a single argv element after `-if` — never a
/// shell fragment — so a path that looks like a flag is still inert.
fn build_ausearch_args(audit_log_path: &Path) -> Vec<OsString> {
    vec![
        // Interpret numeric uid/gid/syscall fields into names.
        "-i".into(),
        // Read this input file rather than the live audit log.
        "-if".into(),
        audit_log_path.as_os_str().to_os_string(),
    ]
}

/// `ausearch` exits 1 with no error when a search yields zero matches.
/// Distinguish that benign "no results" case from a real failure so an
/// empty audit log reads as an empty row set, not a [`AusearchError::SubprocessFailed`].
const NO_MATCHES_EXIT_CODE: i32 = 1;

fn stderr_signals_no_matches(stderr: &str) -> bool {
    stderr.contains("<no matches>")
}

/// Run `ausearch` against an `audit.log` and parse its records.
///
/// # Errors
/// * [`AusearchError::NotFound`] / [`AusearchError::NotRegular`] — the
///   `audit_log_path` is missing or not a regular file.
/// * [`AusearchError::BinaryNotFound`] — `ausearch` not on PATH and
///   `$AUSEARCH_BIN` unset (it is INSTALL-FIRST: absent on the SIFT VM).
/// * [`AusearchError::SubprocessFailed`] — `ausearch` returned a real
///   error (a zero-match exit is treated as an empty result, not a failure);
///   check `stderr_tail`.
pub fn ausearch(input: &AusearchInput) -> Result<AusearchOutput, AusearchError> {
    if !input.audit_log_path.exists() {
        return Err(AusearchError::NotFound(input.audit_log_path.clone()));
    }
    if !input.audit_log_path.is_file() {
        return Err(AusearchError::NotRegular(input.audit_log_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(build_ausearch_args(&input.audit_log_path));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            AusearchError::BinaryNotFound
        } else {
            AusearchError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);
    let exit_code = proc.status.code().unwrap_or(-1);

    // A zero-match search exits 1 with "<no matches>" on stderr — benign.
    let is_no_matches =
        exit_code == NO_MATCHES_EXIT_CODE && stderr_signals_no_matches(&stderr_tail);
    if !proc.status.success() && !is_no_matches {
        return Err(AusearchError::SubprocessFailed {
            exit_code,
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    Ok(parse_records(stdout.as_ref(), limit, stderr_tail))
}

fn resolve_binary() -> Result<PathBuf, AusearchError> {
    if let Ok(env_path) = std::env::var("AUSEARCH_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let bin_name = if cfg!(windows) {
            "ausearch.exe"
        } else {
            "ausearch"
        };
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(AusearchError::BinaryNotFound)
}

/// True for an event separator line (`----`) or a blank line — neither
/// is a `type=…` record.
fn is_separator_line(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with("----")
}

/// Parse `ausearch -i` output. Each non-separator line is one record
/// beginning with a `type=…` tag, followed by `key=value` pairs.
fn parse_records(stdout: &str, limit: usize, stderr_tail: String) -> AusearchOutput {
    let records: Vec<&str> = stdout
        .lines()
        .filter(|line| !is_separator_line(line) && line.contains("type="))
        .collect();

    let rows_seen = records.len();
    let rows = records
        .into_iter()
        .take(limit)
        .map(parse_record_line)
        .collect();

    AusearchOutput {
        rows,
        rows_seen,
        stderr_tail,
    }
}

/// Parse one `ausearch` record line into a `key=value` map.
///
/// The line is whitespace-separated `key=value` tokens. `ausearch -i`
/// can emit a value containing spaces only inside quotes (`msg='op=PAM:
/// …'`); we keep the parse simple and split on whitespace, attaching the
/// full original line under `raw` so nothing is lost. The leading
/// `type=…` tag is captured like any other field.
fn parse_record_line(line: &str) -> AuditRow {
    let mut map = serde_json::Map::new();
    for token in line.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            if !key.is_empty() {
                map.insert(
                    key.to_string(),
                    serde_json::Value::String(value.to_string()),
                );
            }
        }
    }
    map.insert(
        "raw".to_string(),
        serde_json::Value::String(line.to_string()),
    );
    map
}

/// Cheap pre-flight: a path whose name looks like a Linux audit log.
#[must_use]
pub fn path_looks_like_audit_log(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.to_ascii_lowercase().contains("audit.log"))
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk to the nearest char boundary so a multi-byte UTF-8 codepoint
        // straddling `max` doesn't panic `String::truncate`. Bounded at 4 bytes.
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
    fn build_args_uses_interpret_and_input_file() {
        let args = build_ausearch_args(Path::new("/var/log/audit/audit.log"));
        let s = as_strings(&args);
        assert_eq!(s, vec!["-i", "-if", "/var/log/audit/audit.log"]);
        // `-if` must be immediately followed by the path.
        let f = s.iter().position(|a| a == "-if").unwrap();
        assert_eq!(s[f + 1], "/var/log/audit/audit.log");
    }

    #[test]
    fn parse_record_captures_type_and_fields() {
        let line = "type=EXECVE msg=audit(1714032843.123:456): argc=2 a0=\"/bin/sh\" a1=\"-c\"";
        let rec = parse_record_line(line);
        assert_eq!(
            rec.get("type").and_then(serde_json::Value::as_str),
            Some("EXECVE")
        );
        assert_eq!(
            rec.get("argc").and_then(serde_json::Value::as_str),
            Some("2")
        );
        // raw keeps the full original line.
        assert_eq!(
            rec.get("raw").and_then(serde_json::Value::as_str),
            Some(line)
        );
    }

    #[test]
    fn parse_records_counts_type_lines_and_skips_separators() {
        let stdout = "\
----
type=SYSCALL msg=audit(1714032843.123:456): arch=c000003e syscall=59 success=yes uid=0
type=EXECVE msg=audit(1714032843.123:456): argc=1 a0=\"id\"

----
type=USER_LOGIN msg=audit(1714032900.000:789): acct=\"root\" res=success
";
        let out = parse_records(stdout, 100, String::new());
        assert_eq!(out.rows_seen, 3, "3 type= lines, separators excluded");
        assert_eq!(out.rows.len(), 3);
        assert_eq!(
            out.rows[0]
                .get("syscall")
                .and_then(serde_json::Value::as_str),
            Some("59")
        );
    }

    #[test]
    fn parse_records_respects_limit() {
        let stdout = "\
type=SYSCALL a=1
type=SYSCALL a=2
type=SYSCALL a=3
";
        let out = parse_records(stdout, 2, String::new());
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_records_empty_is_no_rows() {
        let out = parse_records("----\n\n", 100, String::new());
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn no_matches_stderr_is_detected() {
        assert!(stderr_signals_no_matches("<no matches>\n"));
        assert!(!stderr_signals_no_matches("some other error"));
    }

    #[test]
    fn path_looks_like_audit_log_matches_known_names() {
        assert!(path_looks_like_audit_log(Path::new(
            "/var/log/audit/audit.log"
        )));
        assert!(path_looks_like_audit_log(Path::new("audit.log.1")));
        assert!(!path_looks_like_audit_log(Path::new("/var/log/syslog")));
    }

    #[test]
    fn truncate_to_does_not_panic_on_multibyte_boundary() {
        let s: String = "\u{FFFD}".repeat(1000);
        let out = truncate_to(s, 100);
        assert!(out.ends_with("…[truncated]"));
        let body_len = out.len() - "…[truncated]".len();
        assert!(out.is_char_boundary(body_len));
    }
}
