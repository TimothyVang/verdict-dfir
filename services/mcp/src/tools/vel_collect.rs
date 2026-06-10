//! `vel_collect` — subprocess wrapper for Velociraptor artifact collection.
//!
//! Spec #2 §6 + the live-response leg of the DFIR tool surface.
//! Velociraptor (Apache-2.0; safe to invoke as a subprocess) ships
//! 200+ built-in DFIR artifacts (`Windows.Forensics.Prefetch`,
//! `Windows.Persistence.Services`, `Generic.Forensic.LocalHashes`, …).
//! This wrapper is a generic trampoline: the agent supplies the
//! artifact name + its parameters, we invoke the CLI and return the
//! row stream.
//!
//! Velociraptor invocation (deliberately minimal):
//!   `<vel> artifacts collect <ArtifactName> --format jsonl
//!     [--args key=value ...]`
//!
//! `--format jsonl` makes Velociraptor emit one JSON object per line
//! to stdout; we tolerate both JSONL and a single JSON-array fallback
//! since older versions emitted the latter.
//!
//! Binary discovery mirrors `vol_pslist` / `vol_malfind`:
//! `$VELOCIRAPTOR_BIN` env var first, then PATH lookup for
//! `velociraptor` (and `.exe` on Windows). Velociraptor is shipped as
//! a single static binary, so this is the only path that matters.
//!
//! NB: this tool intentionally does NOT bake in artifact knowledge.
//! Velociraptor's catalog evolves; the agent picks the artifact
//! name from a separate context (e.g. `velociraptor artifacts list`)
//! and we just relay rows. That keeps the wrapper future-proof and
//! avoids a 200-arm match statement that drifts every release.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VelCollectInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Velociraptor artifact name (e.g. `Windows.Forensics.Prefetch`,
    /// `Generic.Forensic.LocalHashes`). Must match the dotted-path
    /// pattern Velociraptor uses; rejected up-front to keep injection
    /// out of the subprocess argv.
    pub artifact: String,

    /// Optional `key=value` parameters passed to the artifact via
    /// `--args`. Velociraptor artifacts are heavily parameterized
    /// (target paths, glob patterns, max sizes, etc.) — the schema
    /// for each artifact lives with Velociraptor, not here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args: Option<BTreeMap<String, String>>,

    /// Hard cap on rows returned. Default `10_000`. Some artifacts
    /// (e.g. `Generic.Forensic.LocalHashes`) can emit millions of
    /// rows on a fully-populated host — the cap is a safety net.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VelRow {
    /// Artifact name this row was emitted for. Same as the input
    /// `artifact` for a single-artifact call, but kept per-row so the
    /// shape is forward-compatible if we ever fan out.
    pub artifact: String,

    /// Free-form column map, exactly as Velociraptor emitted it.
    /// Deliberately unstructured — every artifact has its own column
    /// set and pinning a typed shape would be hostile to the agent's
    /// flexibility.
    pub fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VelCollectOutput {
    pub rows: Vec<VelRow>,

    /// Total rows Velociraptor emitted before our limit.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes). Velociraptor logs
    /// VFS-mount info, artifact load warnings, and progress here.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VelCollectError {
    #[error(
        "velociraptor binary not on PATH (set $VELOCIRAPTOR_BIN to override). \
         Install: https://github.com/Velocidex/velociraptor/releases"
    )]
    BinaryNotFound,

    #[error("invalid artifact name {0:?}: must match dotted path like Windows.Forensics.Prefetch")]
    InvalidArtifactName(String),

    #[error(
        "invalid arg name {0:?}: keys must be alphanumeric + underscore, no shell metacharacters"
    )]
    InvalidArgName(String),

    #[error("velociraptor exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not parse velociraptor output: {0}")]
    OutputParse(String),
}

/// Run a Velociraptor artifact via `artifacts collect` and return
/// the row stream.
///
/// # Errors
/// * [`VelCollectError::BinaryNotFound`] — Velociraptor not on PATH
///   and `$VELOCIRAPTOR_BIN` unset.
/// * [`VelCollectError::InvalidArtifactName`] — artifact name failed
///   the dotted-path validator (no shell metacharacters allowed).
/// * [`VelCollectError::InvalidArgName`] — an arg key is not
///   `[A-Za-z_][A-Za-z0-9_]*`.
/// * [`VelCollectError::SubprocessFailed`] — non-zero exit; check
///   `stderr_tail` in the error.
/// * [`VelCollectError::OutputParse`] — stdout was neither JSONL
///   nor a JSON array; usually a Velociraptor version mismatch.
pub fn vel_collect(input: &VelCollectInput) -> Result<VelCollectOutput, VelCollectError> {
    if !is_valid_artifact_name(&input.artifact) {
        return Err(VelCollectError::InvalidArtifactName(input.artifact.clone()));
    }
    if let Some(args) = input.args.as_ref() {
        for key in args.keys() {
            if !is_valid_arg_name(key) {
                return Err(VelCollectError::InvalidArgName(key.clone()));
            }
        }
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.arg("artifacts")
        .arg("collect")
        .arg(&input.artifact)
        .arg("--format")
        .arg("jsonl");

    if let Some(args) = input.args.as_ref() {
        for (key, value) in args {
            cmd.arg("--args").arg(format!("{key}={value}"));
        }
    }

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VelCollectError::BinaryNotFound
        } else {
            VelCollectError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VelCollectError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_rows(stdout.as_ref(), &input.artifact, limit, stderr_tail)
}

fn resolve_binary() -> Result<PathBuf, VelCollectError> {
    if let Ok(env_path) = std::env::var("VELOCIRAPTOR_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let candidates: &[&str] = if cfg!(windows) {
            &["velociraptor.exe", "velociraptor"]
        } else {
            &["velociraptor"]
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
    Err(VelCollectError::BinaryNotFound)
}

/// Velociraptor artifact names are dotted ASCII paths, e.g.
/// `Windows.Forensics.Prefetch`. We accept the dotted-path shape and
/// reject anything with shell metacharacters — the artifact name
/// becomes argv[2], so this is the boundary check.
fn is_valid_artifact_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 256 {
        return false;
    }
    let mut prev_dot = false;
    for (i, ch) in name.chars().enumerate() {
        match ch {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '_' => prev_dot = false,
            '.' => {
                if i == 0 || prev_dot {
                    return false;
                }
                prev_dot = true;
            }
            _ => return false,
        }
    }
    !prev_dot
}

/// Arg keys are restricted to identifier-shape strings. The VALUE
/// side is intentionally NOT sanitized — Velociraptor unquotes its
/// own `--args` values, and arbitrary path/glob content is the whole
/// reason the agent is calling this tool. The key restriction blocks
/// the only injection vector that matters (a `key` that contains
/// `--something-else` would smuggle in flags).
fn is_valid_arg_name(key: &str) -> bool {
    if key.is_empty() || key.len() > 64 {
        return false;
    }
    let mut chars = key.chars();
    if !chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
    {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_rows(
    stdout: &str,
    artifact: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<VelCollectOutput, VelCollectError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VelCollectOutput {
            rows: Vec::new(),
            rows_seen: 0,
            stderr_tail,
        });
    }

    // We invoke Velociraptor with `--format jsonl` (one object per line), but
    // parse defensively for any whitespace-separated sequence of JSON values:
    // a single array `[...]` (flattened to its elements), single-line JSONL, or
    // pretty-printed concatenated objects. A streaming `Deserializer` covers all
    // three, so a future format-flag drift can't silently kill the lane the way
    // a line-by-line parser dies on a pretty-printed object's bare `{`.
    let mut all_rows: Vec<serde_json::Value> = Vec::new();
    let stream = serde_json::Deserializer::from_str(trimmed).into_iter::<serde_json::Value>();
    for item in stream {
        match item {
            Ok(serde_json::Value::Array(items)) => all_rows.extend(items),
            Ok(value) => all_rows.push(value),
            Err(e) => return Err(VelCollectError::OutputParse(e.to_string())),
        }
    }

    let rows_seen = all_rows.len();
    let mut out = Vec::with_capacity(rows_seen.min(limit));
    for value in all_rows.into_iter().take(limit) {
        let serde_json::Value::Object(fields) = value else {
            continue;
        };
        out.push(VelRow {
            artifact: artifact.to_string(),
            fields,
        });
    }

    Ok(VelCollectOutput {
        rows: out,
        rows_seen,
        stderr_tail,
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk down to the nearest char boundary so multi-byte UTF-8
        // codepoints (Velociraptor often emits Unicode log lines) don't
        // panic `String::truncate`. `is_char_boundary` is O(1) and the
        // walk is bounded at 4 bytes (max codepoint length).
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
// Unit tests for the sanitizers + parser. The actual Velociraptor
// invocation is exercised by the integration tests and remains opt-in
// via $VELOCIRAPTOR_BIN.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_artifact_names_accepted() {
        assert!(is_valid_artifact_name("Windows.Forensics.Prefetch"));
        assert!(is_valid_artifact_name("Generic.Forensic.LocalHashes"));
        assert!(is_valid_artifact_name("Custom_Artifact"));
        assert!(is_valid_artifact_name("A1.B2.C3"));
    }

    #[test]
    fn invalid_artifact_names_rejected() {
        assert!(!is_valid_artifact_name(""));
        assert!(!is_valid_artifact_name(".LeadingDot"));
        assert!(!is_valid_artifact_name("TrailingDot."));
        assert!(!is_valid_artifact_name("Double..Dot"));
        assert!(!is_valid_artifact_name("Has Spaces"));
        assert!(!is_valid_artifact_name("Has;Semicolons"));
        assert!(!is_valid_artifact_name("Has--Flag"));
        assert!(!is_valid_artifact_name("Has/Slash"));
    }

    #[test]
    fn valid_arg_names_accepted() {
        assert!(is_valid_arg_name("device"));
        assert!(is_valid_arg_name("max_size"));
        assert!(is_valid_arg_name("_internal"));
        assert!(is_valid_arg_name("Path1"));
    }

    #[test]
    fn invalid_arg_names_rejected() {
        assert!(!is_valid_arg_name(""));
        assert!(!is_valid_arg_name("9bad"));
        assert!(!is_valid_arg_name("has-dash"));
        assert!(!is_valid_arg_name("has space"));
        assert!(!is_valid_arg_name("has=equals"));
    }

    #[test]
    fn parse_rows_handles_jsonl() {
        let stdout = r#"{"a":1,"b":"x"}
{"a":2,"b":"y"}
{"a":3}
"#;
        let out = parse_rows(stdout, "TestArtifact", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 3);
        assert_eq!(out.rows[0].artifact, "TestArtifact");
        assert_eq!(
            out.rows[0]
                .fields
                .get("a")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn parse_rows_handles_array_fallback() {
        let stdout = r#"[{"a":1},{"a":2}]"#;
        let out = parse_rows(stdout, "TestArtifact", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_handles_pretty_printed_concatenated_objects() {
        // Defensive: if Velociraptor's format ever drifts to pretty-printed
        // multi-line objects (the shape that silently killed the hayabusa lane),
        // the streaming parser still reads them instead of dying on a bare `{`.
        let stdout = "{\n  \"a\": 1\n}\n{\n  \"a\": 2\n}\n";
        let out = parse_rows(stdout, "TestArtifact", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_respects_limit() {
        let stdout = r#"{"a":1}
{"a":2}
{"a":3}
{"a":4}
"#;
        let out = parse_rows(stdout, "TestArtifact", 2, String::new()).unwrap();
        assert_eq!(out.rows_seen, 4);
        assert_eq!(out.rows.len(), 2);
    }

    #[test]
    fn parse_rows_empty_stdout() {
        let out = parse_rows("", "TestArtifact", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 0);
        assert!(out.rows.is_empty());
    }

    #[test]
    fn parse_rows_rejects_garbage() {
        let err = parse_rows("not json at all\n", "X", 100, String::new()).unwrap_err();
        assert!(matches!(err, VelCollectError::OutputParse(_)));
    }

    #[test]
    fn truncate_to_does_not_panic_on_multibyte_boundary() {
        // P0 regression: a multi-byte codepoint straddling `max` would
        // panic String::truncate. Hayabusa/Volatility/Velociraptor all
        // emit non-ASCII output, so this needs to be safe.
        // U+FFFD (3 bytes: EF BF BD) is what from_utf8_lossy emits for
        // invalid input; 1000× of it produces a 3000-byte string where
        // truncating at any non-multiple-of-3 is mid-codepoint.
        let s: String = "\u{FFFD}".repeat(1000);
        assert_eq!(s.len(), 3000);
        let out = truncate_to(s, 100);
        // Walked down to byte 99 (the last char boundary <= 100, since
        // codepoints occupy bytes 0,3,6,…). 99 / 3 = 33 codepoints.
        assert!(out.ends_with("…[truncated]"));
        let body_len = out.len() - "…[truncated]".len();
        assert!(body_len <= 100);
        // The kept prefix must itself be valid UTF-8 (i.e., no panic
        // path on construction).
        assert!(out.is_char_boundary(body_len));
    }

    #[test]
    fn truncate_to_passthrough_when_short_enough() {
        let s = "short".to_string();
        assert_eq!(truncate_to(s, 100), "short");
    }

    #[test]
    fn parse_rows_skips_non_object_rows() {
        // JSONL with a stray scalar — we keep the object rows and drop the rest.
        let stdout = r#"{"a":1}
"unexpected scalar"
{"a":2}
"#;
        let out = parse_rows(stdout, "TestArtifact", 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3);
        assert_eq!(out.rows.len(), 2);
    }
}
