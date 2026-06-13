//! `plaso_parse` — one allow-listed log2timeline/plaso parser verb.
//!
//! plaso is itself a normalizer across dozens of log formats. Rather than wrap
//! each format as its own tool, `plaso_parse` exposes plaso through ONE verb:
//! the agent names a plaso parser from an **allow-list** and an artifact path,
//! and gets back the normalized timeline rows. This covers a wide cross-OS swath
//! of text/binary logs — Linux `syslog`/`auth.log`, `bash`/`zsh` history,
//! `utmp`/`wtmp`, `dpkg`, legacy Windows `.evt`, scheduled-task jobs, Recycle
//! Bin, `viminfo`, macOS `asl` — in a single audited verb.
//!
//! The allow-list is the security boundary: a parameterized verb is only safe if
//! the parameter can never become an arbitrary command, so any parser name not
//! on the list is rejected before argv is built.
//!
//! Two-stage invocation (plaso's design):
//!   `log2timeline.py --status-view none --parsers <p> --storage-file <tmp.plaso> <artifact>`
//!   `psort.py --status-view none -o json_line -w <tmp.jsonl> <tmp.plaso>`
//! We then parse the JSON-line events. Binary discovery: `$PLASO_DIR` first,
//! then PATH for `log2timeline.py` / `psort.py`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// Allow-listed plaso parser names. Curated from the parser-coverage roadmap's
/// log section — the cross-OS text/binary logs plaso normalizes well. These are
/// canonical plaso parser identifiers; an unknown one is rejected here before
/// argv, and a real-but-unsupported one degrades to an honest `SubprocessFailed`.
const ALLOWED_PARSERS: &[&str] = &[
    // Linux / Unix text + binary logs
    "syslog",
    "bash_history",
    "zsh_extended_history",
    "utmp",
    "dpkg",
    "selinux",
    // Windows (legacy / supplementary to the typed evtx_query path)
    "winevt",
    "winjob",
    "recycle_bin",
    "recycle_bin_info2",
    "winfirewall",
    // Editor / app MRU
    "viminfo",
    // macOS
    "asl_log",
    "mac_appfirewall_log",
    "macwifi",
];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlasoParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,

    /// plaso parser to run. MUST be one of the allow-listed names (see the tool
    /// description); any other value is rejected with `ParserNotAllowed` before
    /// a subprocess runs.
    pub parser: String,

    /// Path to the artifact (a log file, a directory, or a mounted image root).
    pub artifact_path: PathBuf,

    /// Hard cap on events emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlasoParseOutput {
    /// The parser that was run (echoed for audit correlation).
    pub parser: String,

    /// Normalized timeline events as JSON objects (psort `json_line` rows).
    /// Columns vary by parser — the agent gets plaso's own event schema.
    pub events: Vec<serde_json::Map<String, serde_json::Value>>,

    /// Total events plaso emitted before the limit was applied.
    pub events_seen: usize,

    /// Stderr tail (capped at 4096 bytes) from the two stages.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum PlasoParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),

    #[error(
        "parser {0:?} is not on the plaso_parse allow-list; see the tool description \
         for the supported parser names"
    )]
    ParserNotAllowed(String),

    #[error(
        "{binary:?} not found (set $PLASO_DIR or put plaso on PATH). \
         Install plaso (log2timeline) — it ships on the SIFT VM."
    )]
    BinaryNotFound { binary: String },

    #[error("{stage} exited {exit_code}: {stderr}")]
    SubprocessFailed {
        stage: String,
        exit_code: i32,
        stderr: String,
    },

    #[error("could not read plaso output: {0}")]
    OutputRead(String),
}

/// True if `parser` is on the allow-list.
#[must_use]
pub fn is_allowed_parser(parser: &str) -> bool {
    ALLOWED_PARSERS.contains(&parser)
}

/// Build the `log2timeline.py` argv. Pure + unit-tested.
fn build_l2t_args(parser: &str, storage_file: &Path, artifact: &Path) -> Vec<OsString> {
    vec![
        "--status-view".into(),
        "none".into(),
        "--parsers".into(),
        parser.into(),
        "--storage-file".into(),
        storage_file.as_os_str().to_os_string(),
        artifact.as_os_str().to_os_string(),
    ]
}

/// Build the `psort.py` argv (JSON-line export). Pure + unit-tested.
fn build_psort_args(storage_file: &Path, out_file: &Path) -> Vec<OsString> {
    vec![
        "--status-view".into(),
        "none".into(),
        "-o".into(),
        "json_line".into(),
        "-w".into(),
        out_file.as_os_str().to_os_string(),
        storage_file.as_os_str().to_os_string(),
    ]
}

/// Run an allow-listed plaso parser against an artifact and return the events.
///
/// # Errors
/// * [`PlasoParseError::ParserNotAllowed`] — `parser` not on the allow-list
///   (checked BEFORE any IO or subprocess).
/// * [`PlasoParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`PlasoParseError::BinaryNotFound`] — plaso not installed.
/// * [`PlasoParseError::SubprocessFailed`] — a stage returned non-zero.
/// * [`PlasoParseError::OutputRead`] — output missing or unreadable.
pub fn plaso_parse(input: &PlasoParseInput) -> Result<PlasoParseOutput, PlasoParseError> {
    // Allow-list FIRST — the security boundary.
    if !is_allowed_parser(&input.parser) {
        return Err(PlasoParseError::ParserNotAllowed(input.parser.clone()));
    }
    if !input.artifact_path.exists() {
        return Err(PlasoParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }

    let l2t = resolve_binary("log2timeline.py")?;
    let psort = resolve_binary("psort.py")?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let tag = format!("{}-{}", std::process::id(), nanosecond_tag());
    let storage = std::env::temp_dir().join(format!("plaso-{}-{tag}.plaso", input.parser));
    let out_file = std::env::temp_dir().join(format!("plaso-{}-{tag}.jsonl", input.parser));

    let l2t_stderr = run_stage(
        &l2t,
        &build_l2t_args(&input.parser, &storage, &input.artifact_path),
        "log2timeline.py",
    );
    let l2t_stderr = match l2t_stderr {
        Ok(s) => s,
        Err(e) => {
            cleanup(&[&storage, &out_file]);
            return Err(e);
        }
    };

    let psort_stderr = run_stage(&psort, &build_psort_args(&storage, &out_file), "psort.py");
    let psort_stderr = match psort_stderr {
        Ok(s) => s,
        Err(e) => {
            cleanup(&[&storage, &out_file]);
            return Err(e);
        }
    };

    let stderr_tail = truncate_to(format!("{l2t_stderr}{psort_stderr}"), 4096);
    let result = read_json_lines(&out_file, &input.parser, limit, stderr_tail);
    cleanup(&[&storage, &out_file]);
    result
}

/// Run one plaso stage with fixed argv; return its stderr tail or a typed error.
fn run_stage(binary: &Path, args: &[OsString], stage: &str) -> Result<String, PlasoParseError> {
    let proc = Command::new(binary).args(args).output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PlasoParseError::BinaryNotFound {
                binary: stage.to_string(),
            }
        } else {
            PlasoParseError::SubprocessFailed {
                stage: stage.to_string(),
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;
    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 2048);
    if !proc.status.success() {
        return Err(PlasoParseError::SubprocessFailed {
            stage: stage.to_string(),
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }
    Ok(stderr_tail)
}

fn read_json_lines(
    out_file: &Path,
    parser: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<PlasoParseOutput, PlasoParseError> {
    let content = match std::fs::read_to_string(out_file) {
        Ok(c) => c,
        // No output file but both stages succeeded => zero events.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(PlasoParseError::OutputRead(format!(
                "read {}: {e}",
                out_file.display()
            )));
        }
    };
    Ok(parse_json_lines(parser, &content, limit, stderr_tail))
}

/// Parse psort `json_line` output: one JSON object per non-empty line.
fn parse_json_lines(
    parser: &str,
    content: &str,
    limit: usize,
    stderr_tail: String,
) -> PlasoParseOutput {
    let mut events: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
    let mut events_seen = 0usize;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Tolerate a stray non-JSON status line rather than failing the whole run.
        let Ok(serde_json::Value::Object(map)) = serde_json::from_str(trimmed) else {
            continue;
        };
        events_seen += 1;
        if events.len() < limit {
            events.push(map);
        }
    }
    PlasoParseOutput {
        parser: parser.to_string(),
        events,
        events_seen,
        stderr_tail,
    }
}

fn resolve_binary(binary: &str) -> Result<PathBuf, PlasoParseError> {
    if let Ok(dir) = std::env::var("PLASO_DIR") {
        if !dir.is_empty() {
            let candidate = PathBuf::from(dir).join(binary);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(binary);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(PlasoParseError::BinaryNotFound {
        binary: binary.to_string(),
    })
}

fn cleanup(paths: &[&Path]) {
    for p in paths {
        let _ = std::fs::remove_file(p);
    }
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

fn nanosecond_tag() -> u128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos())
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
    fn allow_list_accepts_known_parsers_and_rejects_injection() {
        assert!(is_allowed_parser("syslog"));
        assert!(is_allowed_parser("bash_history"));
        assert!(is_allowed_parser("utmp"));
        assert!(!is_allowed_parser("not_a_parser"));
        assert!(!is_allowed_parser("syslog; rm -rf /"));
        assert!(!is_allowed_parser("$(reboot)"));
    }

    #[test]
    fn plaso_parse_rejects_off_list_parser_before_any_io() {
        let input = PlasoParseInput {
            case_id: "c".into(),
            parser: "syslog && curl evil".into(),
            artifact_path: PathBuf::from("/nonexistent/auth.log"),
            limit: None,
        };
        match plaso_parse(&input) {
            Err(PlasoParseError::ParserNotAllowed(p)) => assert_eq!(p, "syslog && curl evil"),
            other => panic!("expected ParserNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn build_l2t_args_carries_parser_storage_and_artifact() {
        let args = build_l2t_args(
            "syslog",
            Path::new("/t/s.plaso"),
            Path::new("/var/log/syslog"),
        );
        let s = as_strings(&args);
        assert_eq!(
            s,
            vec![
                "--status-view",
                "none",
                "--parsers",
                "syslog",
                "--storage-file",
                "/t/s.plaso",
                "/var/log/syslog",
            ]
        );
    }

    #[test]
    fn build_psort_args_exports_json_line() {
        let args = build_psort_args(Path::new("/t/s.plaso"), Path::new("/t/o.jsonl"));
        let s = as_strings(&args);
        assert!(s.contains(&"json_line".to_string()), "{s:?}");
        let w = s.iter().position(|a| a == "-w").unwrap();
        assert_eq!(s[w + 1], "/t/o.jsonl");
        // storage file is the trailing positional.
        assert_eq!(s.last().unwrap(), "/t/s.plaso");
    }

    #[test]
    fn parse_json_lines_reads_objects_and_skips_noise() {
        let body = "{\"timestamp\":1,\"message\":\"sshd login\"}\n\
                    not-json-status-line\n\
                    {\"timestamp\":2,\"message\":\"sudo\"}\n";
        let out = parse_json_lines("syslog", body, 100, String::new());
        assert_eq!(out.events_seen, 2, "the non-JSON status line is skipped");
        assert_eq!(out.parser, "syslog");
        assert_eq!(
            out.events[1]
                .get("message")
                .and_then(serde_json::Value::as_str),
            Some("sudo")
        );
    }

    #[test]
    fn parse_json_lines_respects_limit() {
        let body = "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n";
        let out = parse_json_lines("syslog", body, 2, String::new());
        assert_eq!(out.events_seen, 3);
        assert_eq!(out.events.len(), 2);
    }
}
