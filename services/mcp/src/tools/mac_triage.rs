//! `mac_triage` — one allow-listed `mac_apt` module verb.
//!
//! `mac_apt` is the macOS supertool: its modules parse Unified Logs, `FSEvents`,
//! launchd, `KnowledgeC`, Quarantine, TCC, Safari, Spotlight, install history,
//! and shell sessions internally. Wrapping it once is the macOS analogue of
//! `disk_extract_artifacts` — ONE verb covers most of the macOS roadmap.
//!
//! The agent names a module from an **allow-list** (the security boundary — a
//! parameterized verb is only safe if the parameter can never become an
//! arbitrary command) and a mounted-image path; `mac_triage` runs the fixed-argv
//! invocation, reads the CSV(s) `mac_apt` writes, and returns the rows.
//!
//! Invocation: `mac_apt.py -o <outdir> MOUNTED <image> <MODULE>`. `mac_apt` is a
//! Python tool present on the SIFT VM; on a host without it the verb degrades to
//! a typed `BinaryNotFound`. Binary discovery: `$MAC_APT` (full path to
//! `mac_apt.py`) first, then PATH.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::tools::ez_parse::parse_csv_records;

const DEFAULT_LIMIT: usize = 10_000;

/// Allow-listed `mac_apt` plugin names (canonical `mac_apt` module identifiers).
/// Curated from the parser-coverage roadmap's macOS section.
const ALLOWED_MODULES: &[&str] = &[
    "UNIFIEDLOGS",
    "FSEVENTS",
    "AUTOSTART",
    "KNOWLEDGEC",
    "QUARANTINE",
    "TCC",
    "SAFARI",
    "SPOTLIGHT",
    "INSTALLHISTORY",
    "BASHSESSIONS",
    "NOTIFICATIONS",
    "USERS",
    "NETWORKING",
    "RECENTITEMS",
    "SUDOLASTRUN",
];

/// True if `module` is on the allow-list.
#[must_use]
pub fn is_allowed_module(module: &str) -> bool {
    ALLOWED_MODULES.contains(&module)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MacTriageInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,

    /// Which `mac_apt` module to run. MUST be one of the allow-listed names (see
    /// the tool description); any other value is rejected with `ModuleNotAllowed`
    /// before a subprocess runs.
    pub module: String,

    /// Path to the mounted macOS image root (a `MOUNTED` input for `mac_apt`).
    pub image_path: PathBuf,

    /// Hard cap on rows emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MacTriageOutput {
    /// The module that was run (echoed for audit correlation).
    pub module: String,

    /// Decoded rows as `column -> value` maps. Columns vary by module — the
    /// agent gets `mac_apt`'s own CSV schema.
    pub rows: Vec<std::collections::BTreeMap<String, String>>,

    /// Total rows parsed before the limit was applied.
    pub rows_seen: usize,

    /// Names of the CSV file(s) `mac_apt` produced (for provenance).
    pub csv_files: Vec<String>,

    /// Stderr tail (capped at 4096 bytes).
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum MacTriageError {
    #[error("image path not found: {0}")]
    ImageNotFound(PathBuf),

    #[error(
        "module {0:?} is not on the mac_triage allow-list; use one of the canonical \
         mac_apt module names in the tool description"
    )]
    ModuleNotAllowed(String),

    #[error(
        "mac_apt not found (set $MAC_APT to mac_apt.py or put it on PATH). \
         mac_apt ships on the SIFT VM."
    )]
    BinaryNotFound,

    #[error("mac_apt exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("mac_apt produced no CSV in the output directory")]
    NoCsvProduced,

    #[error("could not read mac_apt output: {0}")]
    OutputRead(String),
}

/// Build the fixed argv: `-o <outdir> MOUNTED <image> <MODULE>`. Pure +
/// unit-tested. The module is assumed already allow-list-validated.
fn build_mac_apt_args(image: &Path, module: &str, outdir: &Path) -> Vec<OsString> {
    vec![
        "-o".into(),
        outdir.as_os_str().to_os_string(),
        "MOUNTED".into(),
        image.as_os_str().to_os_string(),
        module.into(),
    ]
}

/// Run an allow-listed `mac_apt` module against a mounted macOS image.
///
/// # Errors
/// * [`MacTriageError::ModuleNotAllowed`] — `module` not on the allow-list
///   (checked BEFORE any IO or subprocess).
/// * [`MacTriageError::ImageNotFound`] — `image_path` missing.
/// * [`MacTriageError::BinaryNotFound`] — `mac_apt` not installed.
/// * [`MacTriageError::SubprocessFailed`] — `mac_apt` returned non-zero.
/// * [`MacTriageError::NoCsvProduced`] / [`MacTriageError::OutputRead`] — output
///   missing or unreadable.
pub fn mac_triage(input: &MacTriageInput) -> Result<MacTriageOutput, MacTriageError> {
    // Allow-list FIRST — the security boundary.
    if !is_allowed_module(&input.module) {
        return Err(MacTriageError::ModuleNotAllowed(input.module.clone()));
    }
    if !input.image_path.exists() {
        return Err(MacTriageError::ImageNotFound(input.image_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let outdir = std::env::temp_dir().join(format!(
        "macapt-{}-{}-{}",
        input.module.to_ascii_lowercase(),
        std::process::id(),
        nanosecond_tag()
    ));
    if let Err(e) = std::fs::create_dir_all(&outdir) {
        return Err(MacTriageError::OutputRead(format!(
            "could not create output dir {}: {e}",
            outdir.display()
        )));
    }

    let mut cmd = Command::new(&binary);
    cmd.args(build_mac_apt_args(
        &input.image_path,
        &input.module,
        &outdir,
    ));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            MacTriageError::BinaryNotFound
        } else {
            MacTriageError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        let _ = std::fs::remove_dir_all(&outdir);
        return Err(MacTriageError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let result = collect_csv_rows(&outdir, &input.module, limit, stderr_tail);
    let _ = std::fs::remove_dir_all(&outdir);
    result
}

/// Read every `*.csv` `mac_apt` wrote (it can nest them), parse, merge the rows.
fn collect_csv_rows(
    outdir: &Path,
    module: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<MacTriageOutput, MacTriageError> {
    let mut csv_paths: Vec<PathBuf> = Vec::new();
    collect_csv_paths(outdir, &mut csv_paths);
    if csv_paths.is_empty() {
        return Err(MacTriageError::NoCsvProduced);
    }
    csv_paths.sort();

    let mut rows: Vec<std::collections::BTreeMap<String, String>> = Vec::new();
    let mut csv_files: Vec<String> = Vec::new();
    let mut rows_seen = 0usize;
    for path in &csv_paths {
        if let Some(name) = path.file_name() {
            csv_files.push(name.to_string_lossy().into_owned());
        }
        let content = std::fs::read_to_string(path)
            .map_err(|e| MacTriageError::OutputRead(format!("read {}: {e}", path.display())))?;
        let records = parse_csv_records(&content);
        let mut iter = records.into_iter();
        let Some(header) = iter.next() else { continue };
        for record in iter {
            rows_seen += 1;
            if rows.len() < limit {
                let mut map = std::collections::BTreeMap::new();
                for (i, col) in header.iter().enumerate() {
                    map.insert(col.clone(), record.get(i).cloned().unwrap_or_default());
                }
                rows.push(map);
            }
        }
    }

    Ok(MacTriageOutput {
        module: module.to_string(),
        rows,
        rows_seen,
        csv_files,
        stderr_tail,
    })
}

/// Recursively collect `*.csv` paths under `dir` (`mac_apt` nests output).
fn collect_csv_paths(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_csv_paths(&path, out);
        } else if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("csv"))
        {
            out.push(path);
        }
    }
}

fn resolve_binary() -> Result<PathBuf, MacTriageError> {
    if let Ok(p) = std::env::var("MAC_APT") {
        let candidate = PathBuf::from(p);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in ["mac_apt.py", "mac_apt"] {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(MacTriageError::BinaryNotFound)
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
    fn allow_list_accepts_modules_and_rejects_injection() {
        assert!(is_allowed_module("UNIFIEDLOGS"));
        assert!(is_allowed_module("FSEVENTS"));
        assert!(is_allowed_module("TCC"));
        assert!(!is_allowed_module("NOPE"));
        assert!(!is_allowed_module("UNIFIEDLOGS; rm -rf /"));
        assert!(!is_allowed_module("$(reboot)"));
    }

    #[test]
    fn mac_triage_rejects_off_list_module_before_any_io() {
        let input = MacTriageInput {
            case_id: "c".into(),
            module: "UNIFIEDLOGS && curl evil".into(),
            image_path: PathBuf::from("/nonexistent/mount"),
            limit: None,
        };
        match mac_triage(&input) {
            Err(MacTriageError::ModuleNotAllowed(m)) => assert_eq!(m, "UNIFIEDLOGS && curl evil"),
            other => panic!("expected ModuleNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn build_mac_apt_args_uses_mounted_input_and_module() {
        let args = build_mac_apt_args(Path::new("/mnt/mac"), "UNIFIEDLOGS", Path::new("/out"));
        let s = as_strings(&args);
        assert_eq!(s, vec!["-o", "/out", "MOUNTED", "/mnt/mac", "UNIFIEDLOGS"]);
    }

    #[test]
    fn collect_csv_rows_reads_nested_csv() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("UNIFIEDLOGS");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("out.csv"), "Process,Message\nsshd,login\n").unwrap();
        let out = collect_csv_rows(dir.path(), "UNIFIEDLOGS", 10, String::new()).unwrap();
        assert_eq!(out.rows_seen, 1);
        assert_eq!(out.rows[0].get("Process").map(String::as_str), Some("sshd"));
        assert_eq!(out.csv_files, vec!["out.csv"]);
    }

    #[test]
    fn collect_csv_rows_errors_when_no_csv() {
        let dir = tempfile::tempdir().unwrap();
        match collect_csv_rows(dir.path(), "TCC", 10, String::new()) {
            Err(MacTriageError::NoCsvProduced) => {}
            other => panic!("expected NoCsvProduced, got {other:?}"),
        }
    }
}
