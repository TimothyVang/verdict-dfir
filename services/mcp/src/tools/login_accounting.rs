//! `login_accounting` — subprocess wrapper for `last` over a binary
//! `wtmp` / `btmp` login-accounting database.
//!
//! Spec #2 §6 + the Linux-host leg of the DFIR tool surface. `wtmp`
//! (successful logins / logouts / reboots) and `btmp` (failed login
//! attempts) are opaque binary `utmp`-format files; `last` (from the
//! `util-linux` package) is the canonical reader. Per CLAUDE.md the
//! convention is to invoke external readers as a SUBPROCESS — `last`
//! is GPL-2.0, so a subprocess boundary keeps it out of our Apache-2.0
//! binary entirely.
//!
//! `last` invocation (deliberately minimal, FIXED argv):
//!   `last -f <wtmp_path> -F -w`
//!     -f  read this accounting file instead of /var/log/wtmp
//!     -F  full login/logout times (so we get a parseable absolute date)
//!     -w  wide — never truncate the user / host columns
//!
//! We deliberately do NOT pass `-R` (`--nohostname`): that flag suppresses the
//! host field entirely, which would discard the remote SSH/RDP source host that
//! is the whole point of this tool (an interactive login from an unexpected
//! host is the lateral-movement signal). `last` displays the host string AS
//! RECORDED in `wtmp` and does no live DNS lookup by default (that is opt-in via
//! `-d`), so keeping the host column is both useful and network-safe.
//!
//! Pool A / B triage: an interactive login from an unexpected host, an
//! off-hours `root` session, or a burst of `btmp` failures are all
//! classic lateral-movement / brute-force signals.
//!
//! Binary discovery mirrors `vol_pslist` / `vel_collect`:
//! `$LAST_BIN` env var first, then PATH lookup for `last`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LoginAccountingInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to a binary login-accounting database — a `wtmp` (successful
    /// sessions) or `btmp` (failed attempts) file from the mounted
    /// image. Passed verbatim to `last -f`.
    pub accounting_path: PathBuf,

    /// Hard cap on rows emitted. Default `10_000`. A long-lived host's
    /// `wtmp` can hold tens of thousands of sessions; the cap keeps
    /// responses bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginRecord {
    /// Account name (e.g. `root`, `alice`). For `btmp` this is the
    /// account a failed attempt targeted.
    pub user: String,

    /// TTY / line the session used (e.g. `pts/0`, `tty1`, `system boot`).
    pub line: String,

    /// Remote host the session came from, when present. Empty for local
    /// console logins and pseudo-records (boot / shutdown).
    pub host: String,

    /// Login time as the absolute string `last -F` printed, when parsed.
    /// `None` for malformed or pseudo rows.
    pub login_iso: Option<String>,

    /// Logout time as the absolute string `last -F` printed, when
    /// parsed. `None` for still-logged-in / crashed / pseudo rows.
    pub logout_iso: Option<String>,

    /// The full original `last` line, kept verbatim so nothing the
    /// positional parse dropped is lost to the agent.
    pub raw: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct LoginAccountingOutput {
    pub rows: Vec<LoginRecord>,

    /// Total data rows `last` emitted before our limit was applied
    /// (excludes blank lines and the trailing `wtmp begins …` footer).
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). `last` prints
    /// "last: <file>: No such file or directory" and similar here.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum LoginAccountingError {
    #[error("accounting file not found: {0}")]
    NotFound(PathBuf),

    #[error("accounting path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error(
        "last binary not on PATH (set $LAST_BIN to override). \
         Install: `sudo apt-get install -y util-linux` (Linux host or SIFT VM)."
    )]
    BinaryNotFound,

    #[error("last exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },
}

/// Build the FIXED `last` argument vector.
///
/// Extracted as a pure function so the arg contract is unit-tested. The
/// `accounting_path` becomes a single argv element after `-f` — never a
/// shell fragment — so a path that looks like a flag is still inert.
fn build_last_args(accounting_path: &Path) -> Vec<OsString> {
    vec![
        "-f".into(),
        accounting_path.as_os_str().to_os_string(),
        // Full absolute login/logout times (parseable date, not "Mon 09:14").
        "-F".into(),
        // Wide: never truncate the user / host columns.
        "-w".into(),
    ]
}

/// Run `last` against a `wtmp` / `btmp` file and parse its rows.
///
/// # Errors
/// * [`LoginAccountingError::NotFound`] / [`LoginAccountingError::NotRegular`] —
///   the `accounting_path` is missing or not a regular file.
/// * [`LoginAccountingError::BinaryNotFound`] — `last` not on PATH and
///   `$LAST_BIN` unset.
/// * [`LoginAccountingError::SubprocessFailed`] — `last` returned non-zero;
///   check `stderr_tail`.
pub fn login_accounting(
    input: &LoginAccountingInput,
) -> Result<LoginAccountingOutput, LoginAccountingError> {
    if !input.accounting_path.exists() {
        return Err(LoginAccountingError::NotFound(
            input.accounting_path.clone(),
        ));
    }
    if !input.accounting_path.is_file() {
        return Err(LoginAccountingError::NotRegular(
            input.accounting_path.clone(),
        ));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(build_last_args(&input.accounting_path));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            LoginAccountingError::BinaryNotFound
        } else {
            LoginAccountingError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(LoginAccountingError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    Ok(parse_last_table(stdout.as_ref(), limit, stderr_tail))
}

fn resolve_binary() -> Result<PathBuf, LoginAccountingError> {
    if let Ok(env_path) = std::env::var("LAST_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let bin_name = if cfg!(windows) { "last.exe" } else { "last" };
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(LoginAccountingError::BinaryNotFound)
}

/// True for a line that is not a session record: blank lines and the
/// trailing `wtmp begins Sat Apr 25 …` (or `btmp begins …`) footer.
fn is_non_record_line(line: &str) -> bool {
    let t = line.trim();
    t.is_empty() || t.starts_with("wtmp begins") || t.starts_with("btmp begins")
}

/// Parse the `last -F -w -R` text table into typed rows.
///
/// `-F -R` output is positional: `user line host login_ts - logout_ts
/// (duration)`. With `-R` the host column is suppressed for local
/// logins, so we locate the login timestamp by its weekday token rather
/// than a fixed column index — robust to the variable host field.
fn parse_last_table(stdout: &str, limit: usize, stderr_tail: String) -> LoginAccountingOutput {
    let records: Vec<&str> = stdout
        .lines()
        .filter(|line| !is_non_record_line(line))
        .collect();

    let rows_seen = records.len();
    let rows = records
        .into_iter()
        .take(limit)
        .map(parse_last_line)
        .collect();

    LoginAccountingOutput {
        rows,
        rows_seen,
        stderr_tail,
    }
}

/// A weekday abbreviation marks the start of a `last -F` timestamp
/// (`Sat Apr 25 09:14:03 2026`). Used to split the variable leading
/// columns (user / line / optional host) from the time columns.
const WEEKDAYS: &[&str] = &["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

fn parse_last_line(line: &str) -> LoginRecord {
    let raw = line.to_string();
    let tokens: Vec<&str> = line.split_whitespace().collect();

    // Leading positional columns: user, line, then an optional host.
    let user = tokens.first().copied().unwrap_or_default().to_string();
    let line_col = tokens.get(1).copied().unwrap_or_default().to_string();

    // First weekday token marks the login timestamp start. Everything
    // between `line` and there is the host column (empty for local logins).
    let first_ts = tokens.iter().position(|t| WEEKDAYS.contains(t));
    let host = match first_ts {
        Some(idx) if idx > 2 => tokens[2..idx].join(" "),
        _ => String::new(),
    };

    let (login_iso, logout_iso) = first_ts.map_or((None, None), |idx| extract_times(&tokens, idx));

    LoginRecord {
        user,
        line: line_col,
        host,
        login_iso,
        logout_iso,
        raw,
    }
}

/// A `last -F` absolute timestamp is exactly 5 tokens: weekday, month,
/// day, `HH:MM:SS`, year. The logout side may instead be a status word
/// (`still`, `gone`, `crash`, `down`) which we treat as "no logout time".
fn extract_times(tokens: &[&str], login_start: usize) -> (Option<String>, Option<String>) {
    let login = join_timestamp(tokens, login_start);

    // After the login timestamp comes a `-` separator, then the logout
    // timestamp (or a status word). Find the second weekday token, if any.
    let logout = tokens
        .iter()
        .enumerate()
        .skip(login_start + 5)
        .find(|(_, t)| WEEKDAYS.contains(t))
        .and_then(|(idx, _)| join_timestamp(tokens, idx));

    (login, logout)
}

/// Join the 5-token absolute timestamp starting at `start`, if all 5
/// tokens are present. Returns `None` for a truncated tail.
fn join_timestamp(tokens: &[&str], start: usize) -> Option<String> {
    tokens.get(start..start + 5).map(|slice| slice.join(" "))
}

/// Cheap pre-flight: a path whose name looks like a login-accounting DB.
#[must_use]
pub fn path_looks_like_accounting(path: &Path) -> bool {
    path.file_name().and_then(|n| n.to_str()).is_some_and(|n| {
        let lower = n.to_ascii_lowercase();
        lower.contains("wtmp") || lower.contains("btmp") || lower.contains("utmp")
    })
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
    fn build_args_keeps_host_column_without_dns_lookup() {
        let args = build_last_args(Path::new("/var/log/wtmp"));
        let s = as_strings(&args);
        for expected in ["-f", "/var/log/wtmp", "-F", "-w"] {
            assert!(
                s.contains(&expected.to_string()),
                "missing {expected} in {s:?}"
            );
        }
        assert!(
            !s.contains(&"-R".to_string()),
            "`last -R` suppresses the remote host column"
        );
        // `-f` must be immediately followed by the path.
        let f = s.iter().position(|a| a == "-f").unwrap();
        assert_eq!(s[f + 1], "/var/log/wtmp");
    }

    #[test]
    fn parse_remote_login_with_host_and_logout() {
        // user line host  login(5 toks)  -  logout(5 toks)  (duration)
        let line = "alice    pts/0    10.0.0.5    Sat Apr 25 09:14:03 2026 - Sat Apr 25 17:02:11 2026 (07:48)";
        let rec = parse_last_line(line);
        assert_eq!(rec.user, "alice");
        assert_eq!(rec.line, "pts/0");
        assert_eq!(rec.host, "10.0.0.5");
        assert_eq!(rec.login_iso.as_deref(), Some("Sat Apr 25 09:14:03 2026"));
        assert_eq!(rec.logout_iso.as_deref(), Some("Sat Apr 25 17:02:11 2026"));
        assert_eq!(rec.raw, line);
    }

    #[test]
    fn parse_local_login_without_host_still_logged_in() {
        // No host column (local console); logout side is `still logged in`.
        let line = "root     tty1                  Sat Apr 25 08:00:00 2026   still logged in";
        let rec = parse_last_line(line);
        assert_eq!(rec.user, "root");
        assert_eq!(rec.line, "tty1");
        assert_eq!(rec.host, "", "no host column for a local login");
        assert_eq!(rec.login_iso.as_deref(), Some("Sat Apr 25 08:00:00 2026"));
        assert_eq!(rec.logout_iso, None, "no second timestamp -> no logout");
    }

    #[test]
    fn parse_reboot_pseudo_record() {
        let line = "reboot   system boot  5.15.0-generic Sat Apr 25 07:59:00 2026 - Sat Apr 25 18:00:00 2026 (10:01)";
        let rec = parse_last_line(line);
        assert_eq!(rec.user, "reboot");
        assert_eq!(rec.line, "system");
        assert_eq!(rec.login_iso.as_deref(), Some("Sat Apr 25 07:59:00 2026"));
        assert_eq!(rec.logout_iso.as_deref(), Some("Sat Apr 25 18:00:00 2026"));
    }

    #[test]
    fn parse_table_counts_records_and_skips_footer() {
        let stdout = "\
alice    pts/0    10.0.0.5    Sat Apr 25 09:14:03 2026 - Sat Apr 25 17:02:11 2026 (07:48)
root     tty1                  Sat Apr 25 08:00:00 2026   still logged in

wtmp begins Sat Apr 25 07:59:00 2026
";
        let out = parse_last_table(stdout, 100, String::new());
        assert_eq!(out.rows_seen, 2, "footer + blank line excluded");
        assert_eq!(out.rows.len(), 2);
        assert_eq!(out.rows[0].user, "alice");
    }

    #[test]
    fn parse_table_respects_limit() {
        let stdout = "\
a pts/0 h Sat Apr 25 09:14:03 2026 - Sat Apr 25 10:00:00 2026 (00:45)
b pts/1 h Sat Apr 25 09:15:03 2026 - Sat Apr 25 10:00:00 2026 (00:44)
c pts/2 h Sat Apr 25 09:16:03 2026 - Sat Apr 25 10:00:00 2026 (00:43)
";
        let out = parse_last_table(stdout, 2, String::new());
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_table_empty_is_no_rows() {
        let out = parse_last_table(
            "\n\nwtmp begins Sat Apr 25 07:59:00 2026\n",
            100,
            String::new(),
        );
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn parse_btmp_failed_attempt_row() {
        // btmp rows have the same positional shape; status word `gone - no logout`.
        let line = "baduser  ssh:notty 203.0.113.7 Sat Apr 25 03:00:00 2026 - Sat Apr 25 03:00:00 2026 (00:00)";
        let rec = parse_last_line(line);
        assert_eq!(rec.user, "baduser");
        assert_eq!(rec.host, "203.0.113.7");
        assert_eq!(rec.login_iso.as_deref(), Some("Sat Apr 25 03:00:00 2026"));
    }

    #[test]
    fn path_looks_like_accounting_matches_known_names() {
        assert!(path_looks_like_accounting(Path::new("/var/log/wtmp")));
        assert!(path_looks_like_accounting(Path::new("/var/log/btmp.1")));
        assert!(path_looks_like_accounting(Path::new("/run/utmp")));
        assert!(!path_looks_like_accounting(Path::new("/var/log/syslog")));
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
