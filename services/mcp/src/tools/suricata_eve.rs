//! `suricata_eve` — subprocess wrapper for the Suricata network IDS.
//!
//! Spec #2 §6 + the network-IDS leg of the DFIR tool surface. Suricata
//! (GPL-2.0, so per CLAUDE.md "AGPL/GPL tools are subprocess-only — never
//! linked") replays a PCAP through its rule engine and writes a structured
//! `eve.json` event log (one JSON object per line). Pool B exfil + intrusion
//! triage: alert events, flow records, DNS/HTTP/TLS metadata, and file
//! transfers all land in `eve.json` keyed by `event_type`.
//!
//! Suricata invocation (deliberately minimal, FIXED argv):
//!   `suricata -r <pcap_path> -l <outdir>`
//!
//! Suricata writes `eve.json` (plus `stats.log`, `fast.log`, …) into `-l
//! <outdir>`. We point `-l` at a fresh temp directory (mirroring
//! `hayabusa_scan`'s temp-output-file pattern), read+parse `eve.json` line by
//! line, then remove the temp directory.
//!
//! Binary discovery mirrors `vol_pslist` / `hayabusa_scan`: `$SURICATA_BIN`
//! env var first, then PATH lookup for `suricata` (and `.exe` on Windows).
//! Suricata is an INSTALL-FIRST tool — absent on the stock SIFT VM — so the
//! spawn path degrades to a typed `BinaryNotFound` rather than crashing.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SuricataEveInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the PCAP / PCAPNG capture Suricata replays. Passed verbatim
    /// to `suricata -r`; read-only.
    pub pcap_path: PathBuf,

    /// Hard cap on events returned. Default `10_000`. A busy capture can
    /// produce hundreds of thousands of `eve.json` events, so the cap keeps
    /// responses bounded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SuricataEveOutput {
    /// `eve.json` events, one generic column map per row exactly as Suricata
    /// emitted them. Deliberately unstructured — the field set varies with
    /// `event_type` (`alert`, `flow`, `dns`, `http`, `tls`, `fileinfo`, …).
    pub events: Vec<serde_json::Map<String, serde_json::Value>>,

    /// Total events Suricata wrote to `eve.json` before our limit was applied.
    pub events_seen: usize,

    /// Stderr tail (capped at 4096 bytes). Suricata logs rule-load counts and
    /// engine warnings here; useful when `events` is empty.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum SuricataEveError {
    #[error("pcap file not found: {0}")]
    PcapNotFound(PathBuf),

    #[error("pcap path is not a regular file: {0}")]
    PcapNotRegular(PathBuf),

    #[error(
        "suricata binary not on PATH (set $SURICATA_BIN to override). \
         Install: `sudo apt-get install -y suricata`."
    )]
    BinaryNotFound,

    #[error("suricata exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not read or parse eve.json output: {0}")]
    OutputParse(String),

    #[error("suricata produced no eve.json in the output directory")]
    NoOutput,
}

/// Build the FIXED Suricata argument vector: `-r <pcap_path> -l <outdir>`.
///
/// Extracted as a pure function so the argv contract is unit-tested and the
/// "no free-text passthrough" invariant is visible at a glance.
fn build_suricata_args(pcap_path: &Path, outdir: &Path) -> Vec<OsString> {
    vec![
        "-r".into(),
        pcap_path.as_os_str().to_os_string(),
        "-l".into(),
        outdir.as_os_str().to_os_string(),
    ]
}

/// Run `suricata -r <pcap_path> -l <outdir>` and parse the resulting
/// `eve.json` events.
///
/// # Errors
/// * [`SuricataEveError::PcapNotFound`] / [`SuricataEveError::PcapNotRegular`] —
///   the supplied `pcap_path` is missing or not a regular file.
/// * [`SuricataEveError::BinaryNotFound`] — `suricata` not on PATH and
///   `$SURICATA_BIN` unset.
/// * [`SuricataEveError::SubprocessFailed`] — Suricata returned non-zero;
///   check `stderr_tail` in the error.
/// * [`SuricataEveError::NoOutput`] — Suricata exited cleanly but wrote no
///   `eve.json` (an empty or unreadable capture).
/// * [`SuricataEveError::OutputParse`] — an `eve.json` line was not valid JSON;
///   usually a Suricata version mismatch.
pub fn suricata_eve(input: &SuricataEveInput) -> Result<SuricataEveOutput, SuricataEveError> {
    if !input.pcap_path.exists() {
        return Err(SuricataEveError::PcapNotFound(input.pcap_path.clone()));
    }
    if !input.pcap_path.is_file() {
        return Err(SuricataEveError::PcapNotRegular(input.pcap_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    // Suricata writes eve.json (and stats.log, fast.log, …) into -l <outdir>.
    // Use a fresh per-call temp directory so concurrent runs don't collide.
    let outdir = std::env::temp_dir().join(format!(
        "suricata-eve-{}-{}",
        std::process::id(),
        nanosecond_tag()
    ));
    if let Err(err) = std::fs::create_dir_all(&outdir) {
        return Err(SuricataEveError::OutputParse(format!(
            "could not create output dir {}: {err}",
            outdir.display()
        )));
    }

    let mut cmd = Command::new(&binary);
    cmd.args(build_suricata_args(&input.pcap_path, &outdir));

    let spawn = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            SuricataEveError::BinaryNotFound
        } else {
            SuricataEveError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    });
    let proc = match spawn {
        Ok(proc) => proc,
        Err(err) => {
            let _ = std::fs::remove_dir_all(&outdir);
            return Err(err);
        }
    };

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        let _ = std::fs::remove_dir_all(&outdir);
        return Err(SuricataEveError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let result = read_and_parse_eve(&outdir, limit, stderr_tail);
    // Best-effort cleanup; the scan succeeded already if we got this far.
    let _ = std::fs::remove_dir_all(&outdir);
    result
}

/// Read `<outdir>/eve.json` and parse it. Split out so the parse path is
/// reachable from a unit test without spawning Suricata.
fn read_and_parse_eve(
    outdir: &Path,
    limit: usize,
    stderr_tail: String,
) -> Result<SuricataEveOutput, SuricataEveError> {
    let eve_path = outdir.join("eve.json");
    if !eve_path.is_file() {
        return Err(SuricataEveError::NoOutput);
    }
    let body = std::fs::read_to_string(&eve_path).map_err(|err| {
        SuricataEveError::OutputParse(format!("could not read {}: {err}", eve_path.display()))
    })?;
    parse_events(&body, limit, stderr_tail)
}

fn resolve_binary() -> Result<PathBuf, SuricataEveError> {
    if let Ok(env_path) = std::env::var("SURICATA_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let candidates: &[&str] = if cfg!(windows) {
            &["suricata.exe", "suricata"]
        } else {
            &["suricata"]
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
    Err(SuricataEveError::BinaryNotFound)
}

/// Parse an `eve.json` body — one JSON object per line. Blank lines are
/// skipped; an unparseable line aborts with [`SuricataEveError::OutputParse`].
fn parse_events(
    body: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<SuricataEveOutput, SuricataEveError> {
    let mut events: Vec<serde_json::Map<String, serde_json::Value>> = Vec::new();
    let mut events_seen: usize = 0;
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| SuricataEveError::OutputParse(e.to_string()))?;
        events_seen += 1;
        if let serde_json::Value::Object(fields) = value {
            if events.len() < limit {
                events.push(fields);
            }
        }
    }

    Ok(SuricataEveOutput {
        events,
        events_seen,
        stderr_tail,
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk to the nearest char boundary so a multi-byte UTF-8 codepoint
        // (Suricata warnings can carry non-ASCII rule metadata) doesn't panic
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
    fn build_suricata_args_is_fixed_read_log() {
        let args = build_suricata_args(Path::new("/pcap/capture.pcap"), Path::new("/tmp/out"));
        let s = as_strings(&args);
        assert_eq!(s, vec!["-r", "/pcap/capture.pcap", "-l", "/tmp/out"]);
    }

    #[test]
    fn build_suricata_args_has_no_passthrough_field() {
        // The injection guard: argv carries only -r PATH -l OUTDIR, so a hostile
        // pcap_path can never smuggle in extra Suricata flags or a rule path.
        let args = build_suricata_args(Path::new("/pcap/x"), Path::new("/tmp/o"));
        let s = as_strings(&args);
        assert_eq!(s.len(), 4, "exactly -r PATH -l OUTDIR, nothing else: {s:?}");
    }

    #[test]
    fn parse_events_handles_jsonl() {
        let body = "{\"event_type\":\"alert\",\"signature_id\":2001}\n{\"event_type\":\"flow\"}\n";
        let out = parse_events(body, 100, String::new()).unwrap();
        assert_eq!(out.events_seen, 2);
        assert_eq!(out.events.len(), 2);
        assert_eq!(
            out.events[0]
                .get("event_type")
                .and_then(serde_json::Value::as_str),
            Some("alert")
        );
    }

    #[test]
    fn parse_events_skips_blank_lines() {
        let body = "{\"event_type\":\"dns\"}\n\n   \n{\"event_type\":\"http\"}\n";
        let out = parse_events(body, 100, String::new()).unwrap();
        assert_eq!(out.events_seen, 2);
        assert_eq!(out.events.len(), 2);
    }

    #[test]
    fn parse_events_respects_limit() {
        let body = "{\"a\":1}\n{\"a\":2}\n{\"a\":3}\n{\"a\":4}\n";
        let out = parse_events(body, 2, String::new()).unwrap();
        assert_eq!(out.events_seen, 4, "events_seen counts all rows pre-limit");
        assert_eq!(out.events.len(), 2);
    }

    #[test]
    fn parse_events_empty_body_is_no_events() {
        let out = parse_events("   \n\n", 100, String::new()).unwrap();
        assert_eq!(out.events_seen, 0);
        assert!(out.events.is_empty());
    }

    #[test]
    fn parse_events_rejects_garbage_line() {
        let err = parse_events("{\"a\":1}\nnot json\n", 100, String::new()).unwrap_err();
        assert!(matches!(err, SuricataEveError::OutputParse(_)));
    }

    #[test]
    fn read_and_parse_eve_missing_file_is_no_output() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_and_parse_eve(tmp.path(), 100, String::new()).unwrap_err();
        assert!(matches!(err, SuricataEveError::NoOutput));
    }

    #[test]
    fn read_and_parse_eve_reads_written_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("eve.json"),
            "{\"event_type\":\"alert\"}\n{\"event_type\":\"flow\"}\n",
        )
        .unwrap();
        let out = read_and_parse_eve(tmp.path(), 100, String::new()).unwrap();
        assert_eq!(out.events_seen, 2);
        assert_eq!(out.events.len(), 2);
    }

    #[test]
    fn missing_pcap_file_is_typed_not_found() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("does-not-exist.pcap");
        let err = suricata_eve(&SuricataEveInput {
            case_id: "c".to_string(),
            pcap_path: missing,
            limit: None,
        })
        .unwrap_err();
        assert!(matches!(err, SuricataEveError::PcapNotFound(_)));
    }

    #[test]
    fn directory_pcap_path_is_not_regular() {
        let tmp = tempfile::tempdir().unwrap();
        let err = suricata_eve(&SuricataEveInput {
            case_id: "c".to_string(),
            pcap_path: tmp.path().to_path_buf(),
            limit: None,
        })
        .unwrap_err();
        assert!(matches!(err, SuricataEveError::PcapNotRegular(_)));
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
