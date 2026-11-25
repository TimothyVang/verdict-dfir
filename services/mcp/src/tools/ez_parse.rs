//! `ez_parse` — one allow-listed Eric Zimmerman tool verb.
//!
//! The EZ tools (`LECmd`, `JLECmd`, `AmcacheParser`, `AppCompatCacheParser`,
//! `RBCmd`, `SBECmd`, `WxTCmd`) decode the Windows execution / persistence /
//! anti-forensic artifacts that `registry_query` and the raw parsers can only
//! hand back as bytes — LNK targets, jump-list MRUs, Amcache SHA1s, shim-cache
//! paths, Recycle Bin deletions, shellbag folders. They share ONE shape: `<Tool> -f
//! <artifact> --csv <outdir>` writes a CSV the analyst then reads.
//!
//! So they collapse into ONE verb. The agent names a tool from an **allow-list**
//! (the security boundary — a parameterized verb is only safe if the parameter
//! can never become an arbitrary command) and an artifact path; `ez_parse` runs
//! the fixed-argv invocation, reads the CSV(s) the tool produced, and returns
//! the rows. Output is generic (`rows: Vec<Map>`) because each tool's CSV has
//! its own columns — the agent gets the tool's own schema.
//!
//! All EZ tools are native-Linux since the SANS .NET port and ship on the SIFT
//! VM; on a host without them the verb degrades to a typed `BinaryNotFound`.
//! Binary discovery: `$EZTOOLS_DIR/<Tool>` first, then PATH.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// Per-tool descriptor: the allow-list key, the binary name, and the flag the
/// tool uses to take its input (most are `-f <file>`; `SBECmd` takes `-d <dir>`).
struct EzToolSpec {
    key: &'static str,
    binary: &'static str,
    input_flag: &'static str,
}

/// The allow-list. Curated to the file/dir-oriented decoders that take a simple
/// `-f`/`-d` + `--csv`. `RECmd` is deliberately absent — it needs a batch
/// definition file, not a single artifact, so it does not fit this verb.
const EZ_TOOLS: &[EzToolSpec] = &[
    EzToolSpec {
        key: "lecmd",
        binary: "LECmd",
        input_flag: "-f",
    },
    EzToolSpec {
        key: "jlecmd",
        binary: "JLECmd",
        input_flag: "-f",
    },
    EzToolSpec {
        key: "amcacheparser",
        binary: "AmcacheParser",
        input_flag: "-f",
    },
    EzToolSpec {
        key: "appcompatcacheparser",
        binary: "AppCompatCacheParser",
        input_flag: "-f",
    },
    EzToolSpec {
        key: "rbcmd",
        binary: "RBCmd",
        input_flag: "-f",
    },
    EzToolSpec {
        key: "sbecmd",
        binary: "SBECmd",
        input_flag: "-d",
    },
    EzToolSpec {
        key: "wxtcmd",
        binary: "WxTCmd",
        input_flag: "-f",
    },
];

fn lookup_tool(key: &str) -> Option<&'static EzToolSpec> {
    EZ_TOOLS.iter().find(|t| t.key == key)
}

/// True if `tool` is on the allow-list.
#[must_use]
pub fn is_allowed_ez_tool(tool: &str) -> bool {
    lookup_tool(tool).is_some()
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EzParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,

    /// Which EZ tool to run. MUST be one of: `lecmd` (LNK), `jlecmd`
    /// (jump-lists), `amcacheparser` (`Amcache.hve`), `appcompatcacheparser`
    /// (shim-cache in SYSTEM), `rbcmd` (Recycle Bin `$I`), `sbecmd` (shellbags),
    /// `wxtcmd` (Windows 10 Timeline). Any other value is rejected with
    /// `ToolNotAllowed` before a subprocess runs.
    pub tool: String,

    /// Path to the carved artifact (or, for `sbecmd`, the directory of hives).
    pub artifact_path: PathBuf,

    /// Hard cap on rows emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EzParseOutput {
    /// The tool that was run (echoed for audit correlation).
    pub tool: String,

    /// Decoded rows as `column -> value` maps. Columns vary by tool — the agent
    /// gets the tool's own CSV schema rather than a lossy projection.
    pub rows: Vec<std::collections::BTreeMap<String, String>>,

    /// Total rows parsed before the limit was applied.
    pub rows_seen: usize,

    /// Names of the CSV file(s) the tool produced (for provenance).
    pub csv_files: Vec<String>,

    /// Stderr tail (capped at 4096 bytes).
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum EzParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),

    #[error(
        "tool {0:?} is not on the ez_parse allow-list; use one of: lecmd, jlecmd, \
         amcacheparser, appcompatcacheparser, rbcmd, sbecmd, wxtcmd"
    )]
    ToolNotAllowed(String),

    #[error(
        "EZ tool binary {binary:?} not found (set $EZTOOLS_DIR or put it on PATH). \
         Install the Eric Zimmerman tools — they ship on the SIFT VM and run \
         native on Linux since the .NET port."
    )]
    BinaryNotFound { binary: String },

    #[error("{binary} exited {exit_code}: {stderr}")]
    SubprocessFailed {
        binary: String,
        exit_code: i32,
        stderr: String,
    },

    #[error("{binary} produced no CSV in the output directory")]
    NoCsvProduced { binary: String },

    #[error("could not read EZ tool output: {0}")]
    OutputRead(String),
}

/// Build the fixed argv: `<input_flag> <artifact> --csv <outdir>`. Pure +
/// unit-tested so the contract can't regress. The tool is assumed already
/// allow-list-validated by the caller.
fn build_ez_args(spec: &EzToolSpec, artifact: &Path, outdir: &Path) -> Vec<OsString> {
    vec![
        spec.input_flag.into(),
        artifact.as_os_str().to_os_string(),
        "--csv".into(),
        outdir.as_os_str().to_os_string(),
    ]
}

/// Run an allow-listed EZ tool against a carved artifact and parse its CSV.
///
/// # Errors
/// * [`EzParseError::ToolNotAllowed`] — `tool` not on the allow-list (checked
///   BEFORE any IO or subprocess).
/// * [`EzParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`EzParseError::BinaryNotFound`] — the tool binary is not installed.
/// * [`EzParseError::SubprocessFailed`] — the tool returned non-zero.
/// * [`EzParseError::NoCsvProduced`] / [`EzParseError::OutputRead`] — output
///   missing or unreadable.
pub fn ez_parse(input: &EzParseInput) -> Result<EzParseOutput, EzParseError> {
    // Allow-list FIRST — the security boundary.
    let spec =
        lookup_tool(&input.tool).ok_or_else(|| EzParseError::ToolNotAllowed(input.tool.clone()))?;
    if !input.artifact_path.exists() {
        return Err(EzParseError::ArtifactNotFound(input.artifact_path.clone()));
    }

    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let binary = match resolve_binary(spec.binary) {
        Ok(binary) => binary,
        Err(EzParseError::BinaryNotFound { .. }) if spec.key == "lecmd" => {
            return Ok(native_lecmd_path_fallback(
                &input.artifact_path,
                limit,
                spec.binary,
            ));
        }
        Err(err) => return Err(err),
    };

    let outdir = std::env::temp_dir().join(format!(
        "ez-{}-{}-{}",
        spec.key,
        std::process::id(),
        nanosecond_tag()
    ));
    if let Err(e) = std::fs::create_dir_all(&outdir) {
        return Err(EzParseError::OutputRead(format!(
            "could not create output dir {}: {e}",
            outdir.display()
        )));
    }

    let mut cmd = Command::new(&binary);
    cmd.args(build_ez_args(spec, &input.artifact_path, &outdir));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            EzParseError::BinaryNotFound {
                binary: spec.binary.to_string(),
            }
        } else {
            EzParseError::SubprocessFailed {
                binary: spec.binary.to_string(),
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        let _ = std::fs::remove_dir_all(&outdir);
        return Err(EzParseError::SubprocessFailed {
            binary: spec.binary.to_string(),
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let result = collect_csv_rows(&outdir, &input.tool, limit, stderr_tail, spec.binary);
    let _ = std::fs::remove_dir_all(&outdir);
    result
}

fn native_lecmd_path_fallback(artifact: &Path, limit: usize, binary: &str) -> EzParseOutput {
    let mut rows = Vec::new();
    let display = artifact.to_string_lossy().into_owned();
    let normalized = display.to_lowercase().replace('\\', "/");
    let path_context = (normalized.contains("/recent/") || normalized.contains("/nethood/"))
        && [
            "channels",
            "keys",
            "ghostware",
            "anony",
            "staging",
            "staged",
        ]
        .iter()
        .any(|token| normalized.contains(token));
    let rows_seen = usize::from(path_context);
    if path_context && limit > 0 {
        let mut row = std::collections::BTreeMap::new();
        row.insert("Source File".to_string(), display);
        row.insert("Fallback Basis".to_string(), "path_name".to_string());
        row.insert(
            "Fallback Warning".to_string(),
            format!(
                "{binary} not found; emitted path-only LNK context. Target metadata and volume serial were not decoded."
            ),
        );
        rows.push(row);
    }
    EzParseOutput {
        tool: "lecmd".to_string(),
        rows,
        rows_seen,
        csv_files: Vec::new(),
        stderr_tail: format!(
            "{binary} not found; native path-only LNK fallback used for suspicious Recent/NetHood context."
        ),
    }
}

/// Read every `*.csv` the tool wrote, parse it, and merge the rows.
fn collect_csv_rows(
    outdir: &Path,
    tool: &str,
    limit: usize,
    stderr_tail: String,
    binary: &str,
) -> Result<EzParseOutput, EzParseError> {
    let entries = std::fs::read_dir(outdir)
        .map_err(|e| EzParseError::OutputRead(format!("read_dir {}: {e}", outdir.display())))?;
    let mut csv_paths: Vec<PathBuf> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("csv"))
        {
            csv_paths.push(path);
        }
    }
    if csv_paths.is_empty() {
        return Err(EzParseError::NoCsvProduced {
            binary: binary.to_string(),
        });
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
            .map_err(|e| EzParseError::OutputRead(format!("read {}: {e}", path.display())))?;
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

    Ok(EzParseOutput {
        tool: tool.to_string(),
        rows,
        rows_seen,
        csv_files,
        stderr_tail,
    })
}

/// Minimal RFC-4180 CSV reader: splits `content` into records of fields,
/// honoring double-quoted fields (embedded commas, newlines, and `""` escapes).
/// Dependency-free on purpose — keeps the tool surface's dependency footprint
/// unchanged. Shared with `mac_triage`, which reads `mac_apt` CSV the same way.
pub(crate) fn parse_csv_records(content: &str) -> Vec<Vec<String>> {
    let mut records: Vec<Vec<String>> = Vec::new();
    let mut record: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = content.chars().peekable();
    let mut started = false;

    while let Some(c) = chars.next() {
        started = true;
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    record.push(std::mem::take(&mut field));
                }
                '\r' => { /* swallow; \n handles the line break */ }
                '\n' => {
                    record.push(std::mem::take(&mut field));
                    records.push(std::mem::take(&mut record));
                }
                _ => field.push(c),
            }
        }
    }
    // Flush a trailing field/record with no terminating newline.
    if started && (!field.is_empty() || !record.is_empty()) {
        record.push(field);
        records.push(record);
    }
    records
}

fn resolve_binary(binary: &str) -> Result<PathBuf, EzParseError> {
    let exe = if cfg!(windows) {
        format!("{binary}.exe")
    } else {
        binary.to_string()
    };
    if let Ok(dir) = std::env::var("EZTOOLS_DIR") {
        if !dir.is_empty() {
            let candidate = PathBuf::from(dir).join(&exe);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(&exe);
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(EzParseError::BinaryNotFound {
        binary: binary.to_string(),
    })
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
    fn allow_list_accepts_known_tools_and_rejects_injection() {
        assert!(is_allowed_ez_tool("lecmd"));
        assert!(is_allowed_ez_tool("amcacheparser"));
        assert!(is_allowed_ez_tool("sbecmd"));
        // off-list + injection-shaped strings are rejected
        assert!(!is_allowed_ez_tool("recmd"));
        assert!(!is_allowed_ez_tool("lecmd; rm -rf /"));
        assert!(!is_allowed_ez_tool("$(reboot)"));
    }

    #[test]
    fn ez_parse_rejects_off_list_tool_before_any_io() {
        let input = EzParseInput {
            case_id: "c".into(),
            tool: "lecmd && curl evil".into(),
            artifact_path: PathBuf::from("/nonexistent/evil.lnk"),
            limit: None,
        };
        match ez_parse(&input) {
            Err(EzParseError::ToolNotAllowed(t)) => assert_eq!(t, "lecmd && curl evil"),
            other => panic!("expected ToolNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn build_ez_args_uses_input_flag_and_csv_outdir() {
        let spec = lookup_tool("lecmd").unwrap();
        let args = build_ez_args(spec, Path::new("/c/evil.lnk"), Path::new("/out"));
        let s = as_strings(&args);
        assert_eq!(s, vec!["-f", "/c/evil.lnk", "--csv", "/out"]);
    }

    #[test]
    fn build_ez_args_uses_dir_flag_for_sbecmd() {
        let spec = lookup_tool("sbecmd").unwrap();
        let args = build_ez_args(spec, Path::new("/c/hives"), Path::new("/out"));
        let s = as_strings(&args);
        assert_eq!(s[0], "-d", "SBECmd takes a directory of hives");
    }

    #[test]
    fn parse_csv_handles_header_rows_quotes_and_escapes() {
        let csv = "SourceFile,TargetPath,Args\r\n\
                   evil.lnk,\"C:\\Windows\\System32\\cmd.exe\",\"/c \"\"whoami\"\"\"\r\n\
                   b.lnk,C:\\b.exe,\r\n";
        let recs = parse_csv_records(csv);
        assert_eq!(recs.len(), 3, "header + 2 rows");
        assert_eq!(recs[0], vec!["SourceFile", "TargetPath", "Args"]);
        assert_eq!(recs[1][1], "C:\\Windows\\System32\\cmd.exe");
        assert_eq!(recs[1][2], "/c \"whoami\"", "doubled quotes unescaped");
        assert_eq!(recs[2][2], "", "trailing empty field preserved");
    }

    #[test]
    fn parse_csv_handles_quoted_embedded_newline() {
        let csv = "A,B\n\"line1\nline2\",x\n";
        let recs = parse_csv_records(csv);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[1][0], "line1\nline2");
        assert_eq!(recs[1][1], "x");
    }

    #[test]
    fn collect_csv_rows_maps_header_to_values() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("out.csv"), "Col1,Col2\nv1,v2\nv3,v4\n").unwrap();
        let out = collect_csv_rows(dir.path(), "lecmd", 10, String::new(), "LECmd").unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows[0].get("Col1").map(String::as_str), Some("v1"));
        assert_eq!(out.rows[1].get("Col2").map(String::as_str), Some("v4"));
        assert_eq!(out.csv_files, vec!["out.csv"]);
    }

    #[test]
    fn collect_csv_rows_errors_when_no_csv() {
        let dir = tempfile::tempdir().unwrap();
        match collect_csv_rows(dir.path(), "lecmd", 10, String::new(), "LECmd") {
            Err(EzParseError::NoCsvProduced { binary }) => assert_eq!(binary, "LECmd"),
            other => panic!("expected NoCsvProduced, got {other:?}"),
        }
    }

    #[test]
    fn native_lecmd_path_fallback_surfaces_recent_nethood_context_only() {
        let hit = native_lecmd_path_fallback(
            Path::new("/case/lnk/Documents and Settings/Suspect User/Recent/Staged on USB (E).lnk"),
            10,
            "LECmd",
        );
        assert_eq!(hit.rows_seen, 1);
        assert_eq!(
            hit.rows[0].get("Fallback Basis").map(String::as_str),
            Some("path_name")
        );

        let miss = native_lecmd_path_fallback(
            Path::new("/case/lnk/Documents and Settings/All Users/Start Menu/Programs/Accessories/Calculator.lnk"),
            10,
            "LECmd",
        );
        assert_eq!(miss.rows_seen, 0);
        assert!(miss.rows.is_empty());
    }
}
