//! `plaso_parse` — one allow-listed log2timeline/plaso parser verb.
//!
//! plaso is itself a normalizer across dozens of log formats. Rather than wrap
//! each format as its own tool, `plaso_parse` exposes plaso through ONE verb:
//! the agent names a plaso parser from an **allow-list** and an artifact path,
//! and gets back the normalized timeline rows. This covers a wide cross-OS swath
//! of text/binary logs — Linux `syslog`/`auth.log`, `bash`/`zsh` history,
//! `utmp`/`wtmp`, `dpkg`, legacy Windows `.evt`, IE index.dat, scheduled-task
//! jobs, Recycle Bin, `viminfo`, macOS `asl` — in a single audited verb.
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

use std::collections::BTreeSet;
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
    "msiecf",
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
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    if input.parser == "recycle_bin_info2" {
        return native_recycle_bin_info2_parse(&input.artifact_path, limit);
    }

    let l2t = resolve_binary("log2timeline.py")?;
    let psort = resolve_binary("psort.py")?;

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
    let result = read_json_lines(&out_file, &input.parser, limit, stderr_tail).map(|mut out| {
        // Make events reproducible (and /home-free): plaso embeds the absolute
        // source path in display_name/filename/pathspec, which carries a per-run
        // case + disk-extract UUID and the operator's /home prefix. Verbatim, it
        // makes output_sha256 non-reproducible across runs (verify_finding replay
        // drift) and leaks /home into the hashed output. Canonicalizing to the
        // artifact basename makes the events evidence-determined, not run-determined.
        canonicalize_event_paths(&mut out.events, &input.artifact_path);
        out
    });
    cleanup(&[&storage, &out_file]);
    result
}

fn native_recycle_bin_info2_parse(
    artifact: &Path,
    limit: usize,
) -> Result<PlasoParseOutput, PlasoParseError> {
    let raw = std::fs::read(artifact)
        .map_err(|e| PlasoParseError::OutputRead(format!("read {}: {e}", artifact.display())))?;
    let paths = extract_windows_paths(&raw);
    let events_seen = paths.len();
    let events = paths
        .into_iter()
        .take(limit)
        .map(|path| {
            let mut event = serde_json::Map::new();
            event.insert(
                "data_type".to_string(),
                serde_json::Value::String("windows:metadata:deleted_item".to_string()),
            );
            event.insert(
                "parser".to_string(),
                serde_json::Value::String("recycle_bin_info2".to_string()),
            );
            event.insert("filename".to_string(), serde_json::Value::String(path));
            event.insert(
                "fallback_basis".to_string(),
                serde_json::Value::String("info2_path_string".to_string()),
            );
            event
        })
        .collect();
    Ok(PlasoParseOutput {
        parser: "recycle_bin_info2".to_string(),
        events,
        events_seen,
        stderr_tail: "native INFO2 path-string fallback; deletion timestamps unavailable"
            .to_string(),
    })
}

fn extract_windows_paths(raw: &[u8]) -> Vec<String> {
    let mut paths = BTreeSet::new();
    collect_path_strings(&printable_ascii_runs(raw), &mut paths);

    let utf16ish: Vec<u8> = raw
        .chunks_exact(2)
        .map(|pair| if pair[1] == 0 { pair[0] } else { 0 })
        .collect();
    collect_path_strings(&printable_ascii_runs(&utf16ish), &mut paths);
    paths.into_iter().collect()
}

fn printable_ascii_runs(raw: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut cur = Vec::new();
    for &byte in raw {
        if (32..=126).contains(&byte) {
            cur.push(byte);
        } else {
            if cur.len() >= 4 {
                runs.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        runs.push(String::from_utf8_lossy(&cur).into_owned());
    }
    runs
}

fn collect_path_strings(runs: &[String], paths: &mut BTreeSet<String>) {
    for run in runs {
        let candidate = run.trim();
        if !candidate.contains(":\\") {
            continue;
        }
        let has_relevant_extension = Path::new(candidate)
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| {
                ["exe", "dll", "zip", "txt", "doc", "jpg", "gif"]
                    .iter()
                    .any(|wanted| ext.eq_ignore_ascii_case(wanted))
            });
        if !has_relevant_extension {
            continue;
        }
        paths.insert(candidate.to_string());
    }
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
    // Normalize plaso's run-varying log tokens (timestamp + PID) at the point of
    // capture so BOTH the success `stderr_tail` and the `SubprocessFailed` error
    // are reproducible — a `verify_finding` replay must recompute the same
    // `output_sha256` (see `normalize_plaso_stderr`).
    let stderr_tail = truncate_to(
        normalize_plaso_stderr(&String::from_utf8_lossy(&proc.stderr)),
        2048,
    );
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

/// Width of a plaso log timestamp `YYYY-MM-DD HH:MM:SS,mmm`.
const LOG_TS_LEN: usize = 23;

/// Byte offsets within a [`LOG_TS_LEN`]-wide stamp that must be ASCII digits.
const LOG_TS_DIGIT_OFFSETS: [usize; 17] =
    [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22];

/// Collapse the two run-varying tokens in plaso's stderr so the captured output
/// is byte-identical across runs.
///
/// plaso logs to stderr with Python `logging` lines whose leading timestamp and
/// PID change on every invocation, e.g.
/// `2026-06-20 19:18:13,552 [INFO] (MainProcess) PID:412041 <mod> message`.
/// The parsed events are deterministic; this diagnostic prefix is the only
/// volatile part. Left raw in [`PlasoParseOutput::stderr_tail`], it makes the
/// whole tool output non-reproducible, so a `verify_finding` replay computes a
/// different `output_sha256` and the audit chain (fail-closed) drops the
/// Finding. Replace the timestamp and `PID:<n>` with fixed placeholders — stable
/// across runs and still human-readable. Hand-rolled (no regex dependency),
/// matching the dependency-light style of `sanitize.rs`.
fn normalize_plaso_stderr(stderr: &str) -> String {
    replace_pid_tokens(&replace_log_timestamps(stderr))
}

/// Replace every `PID:<digits>` with `PID:<pid>`. UTF-8 safe: all matched tokens
/// are ASCII, so slice boundaries stay char-aligned.
fn replace_pid_tokens(s: &str) -> String {
    const MARKER: &str = "PID:";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find(MARKER) {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + MARKER.len()..];
        let digits = after
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(after.len());
        if digits > 0 {
            out.push_str("PID:<pid>");
            rest = &after[digits..];
        } else {
            // `PID:` not followed by a digit: leave it literal, advance past it.
            out.push_str(MARKER);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// Replace every plaso log timestamp `YYYY-MM-DD HH:MM:SS,mmm` with `<ts>`.
fn replace_log_timestamps(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let bytes = rest.as_bytes();
        let mut hit = None;
        let mut i = 0;
        while i + LOG_TS_LEN <= bytes.len() {
            if is_log_timestamp(&bytes[i..i + LOG_TS_LEN]) {
                hit = Some(i);
                break;
            }
            i += 1;
        }
        // No stamp left: copy the remainder and stop.
        let Some(pos) = hit else {
            out.push_str(rest);
            break;
        };
        // A stamp is all-ASCII, so `pos` and `pos + LOG_TS_LEN` are char boundaries.
        out.push_str(&rest[..pos]);
        out.push_str("<ts>");
        rest = &rest[pos + LOG_TS_LEN..];
    }
    out
}

/// True if `s` (exactly 23 bytes) is `YYYY-MM-DD HH:MM:SS,mmm`.
fn is_log_timestamp(s: &[u8]) -> bool {
    if s.len() != LOG_TS_LEN {
        return false;
    }
    LOG_TS_DIGIT_OFFSETS.iter().all(|&k| s[k].is_ascii_digit())
        && s[4] == b'-'
        && s[7] == b'-'
        && s[10] == b' '
        && s[13] == b':'
        && s[16] == b':'
        && s[19] == b','
}

/// Replace the absolute source path that plaso embeds in event fields
/// (`display_name`, `filename`, the nested `pathspec` location, ...) with the
/// artifact basename. The extracted-artifact path carries a per-run case +
/// disk-extract UUID and the operator's `/home` prefix; embedded verbatim it
/// makes `output_sha256` non-reproducible across runs (`verify_finding` replay
/// drift) and leaks the operator path into the hashed output. The verifier
/// replays by re-running the tool against the artifact at its (new) extract path,
/// so a path-independent basename is what makes the replay reproduce.
fn canonicalize_event_paths(
    events: &mut [serde_json::Map<String, serde_json::Value>],
    artifact: &Path,
) {
    let abs = artifact.to_string_lossy().into_owned();
    if abs.is_empty() {
        return;
    }
    let basename = artifact
        .file_name()
        .map_or_else(|| abs.clone(), |n| n.to_string_lossy().into_owned());
    for event in events.iter_mut() {
        for value in event.values_mut() {
            replace_substring_in_value(value, &abs, &basename);
        }
    }
}

/// Recursively replace every occurrence of `needle` with `repl` in every string
/// value of a JSON value (objects, arrays, and leaf strings).
fn replace_substring_in_value(value: &mut serde_json::Value, needle: &str, repl: &str) {
    match value {
        serde_json::Value::String(s) => {
            if s.contains(needle) {
                *s = s.replace(needle, repl);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                replace_substring_in_value(item, needle, repl);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                replace_substring_in_value(v, needle, repl);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_event_paths_strips_volatile_source_path() {
        let artifact = Path::new(
            "/home/op/.findevil/cases/abc/extracted/disk/disk-extract-XYZ/ie/u/index.dat",
        );
        let mut events = vec![{
            let mut m = serde_json::Map::new();
            m.insert(
                "display_name".into(),
                serde_json::Value::String(format!("OS:{}", artifact.display())),
            );
            m.insert(
                "filename".into(),
                serde_json::Value::String(artifact.display().to_string()),
            );
            m.insert(
                "message".into(),
                serde_json::Value::String("Visited http://example.test/".into()),
            );
            m
        }];
        canonicalize_event_paths(&mut events, artifact);
        let e = &events[0];
        assert_eq!(e["display_name"], serde_json::json!("OS:index.dat"));
        assert_eq!(e["filename"], serde_json::json!("index.dat"));
        // Forensic (non-path) content is untouched, and no /home leaks.
        assert_eq!(
            e["message"],
            serde_json::json!("Visited http://example.test/")
        );
        assert!(!serde_json::to_string(e).unwrap().contains("/home/"));
    }

    #[test]
    fn canonicalize_event_paths_is_replay_stable_across_extract_uuids() {
        // The same evidence file, extracted to two different per-run UUID dirs
        // (and even a different operator home), must canonicalize to identical
        // events so a verify_finding replay reproduces the same output_sha256.
        let a =
            Path::new("/home/op/.findevil/cases/c1/extracted/disk/disk-extract-AAA/ie/index.dat");
        let b = Path::new(
            "/home/other/.findevil/cases/c1/extracted/disk/disk-extract-BBB/ie/index.dat",
        );
        let mk = |p: &Path| {
            let mut m = serde_json::Map::new();
            m.insert(
                "display_name".into(),
                serde_json::Value::String(format!("OS:{}", p.display())),
            );
            m
        };
        let mut ea = vec![mk(a)];
        let mut eb = vec![mk(b)];
        canonicalize_event_paths(&mut ea, a);
        canonicalize_event_paths(&mut eb, b);
        assert_eq!(ea, eb);
    }

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
        assert!(is_allowed_parser("msiecf"));
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

    #[test]
    fn native_info2_path_fallback_extracts_deleted_paths() {
        let raw =
            b"\0\0C:\\Documents and Settings\\Suspect User\\Desktop\\ethereal-setup.exe\0junk";
        let paths = extract_windows_paths(raw);
        assert_eq!(
            paths,
            vec!["C:\\Documents and Settings\\Suspect User\\Desktop\\ethereal-setup.exe"]
        );
    }

    #[test]
    fn normalize_plaso_stderr_collapses_timestamp_and_pid_for_stable_replay() {
        // Two real plaso stderr lines from running the SAME parser on the SAME
        // artifact twice: they differ ONLY in the log timestamp and PID (observed
        // live — this drift dropped finding f-B-ie-history-illicit on a real case).
        let run_a = "2026-06-20 19:18:13,552 [INFO] (MainProcess) PID:412041 \
                     <artifact_definitions> Determined path: /usr/share/artifacts\n";
        let run_b = "2026-06-20 19:18:16,851 [INFO] (MainProcess) PID:412049 \
                     <artifact_definitions> Determined path: /usr/share/artifacts\n";
        assert_ne!(run_a, run_b, "raw plaso stderr drifts run-to-run");
        assert_eq!(
            normalize_plaso_stderr(run_a),
            normalize_plaso_stderr(run_b),
            "normalized stderr must be byte-identical so a verify_finding replay \
             reproduces output_sha256",
        );
    }

    #[test]
    fn normalize_plaso_stderr_preserves_evidentiary_content() {
        let line = "2026-06-20 19:18:13,552 [INFO] (MainProcess) PID:412041 \
                    <msiecf> parsed 2352 events\n";
        let n = normalize_plaso_stderr(line);
        assert!(n.contains("<ts>"), "{n}");
        assert!(n.contains("PID:<pid>"), "{n}");
        assert!(
            n.contains("parsed 2352 events"),
            "stable message survives: {n}"
        );
        assert!(!n.contains("412041"), "volatile PID removed: {n}");
        assert!(!n.contains("19:18:13"), "volatile timestamp removed: {n}");
    }

    #[test]
    fn normalize_plaso_stderr_leaves_clean_text_untouched() {
        // No volatile tokens: identity — never mangle a plain diagnostic message.
        let s = "native INFO2 path-string fallback; deletion timestamps unavailable";
        assert_eq!(normalize_plaso_stderr(s), s);
    }

    #[test]
    fn replace_pid_tokens_only_touches_pid_followed_by_digits() {
        // A bare "PID:" with no digits, and unrelated text, are left intact.
        assert_eq!(replace_pid_tokens("PID: none here"), "PID: none here");
        assert_eq!(
            replace_pid_tokens("worker PID:7 done"),
            "worker PID:<pid> done"
        );
        assert_eq!(replace_pid_tokens("no token"), "no token");
    }
}
