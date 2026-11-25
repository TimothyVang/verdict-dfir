//! `yara_scan` — scan files against YARA rules in-process.
//!
//! Spec #2 §6 + Pool B exfil / general malware hunting territory.
//! YARA is the lingua franca of IOC + malware-family signatures
//! (YARA-Forge, Florian Roth's signature-base, `VirusTotal` feeds).
//! This tool compiles a rules file (or directory of `.yar`/`.yara`
//! files) and scans a target file or directory.
//!
//! Backed by `yara-x = "=1.12.0"` (BSD-3-Clause, `VirusTotal`'s pure
//! Rust YARA implementation — 99% rule-compatible with libyara,
//! safer + faster). Pinned to 1.12.0 because 1.13+ requires rustc
//! 1.89; we're at 1.88. The yara-x-{macros,parser,proto} subcrates
//! are also pinned for the same reason.
//!
//! Output is intentionally lean: `file_path`, `rule_name`, namespace,
//! tags, and per-pattern match offset/length/preview. Full matched
//! bytes are not returned (could be huge); the agent gets the first
//! 64 bytes hex-encoded as a sanity-check preview.

use std::fs;
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use yara_x::{Compiler, Rules, Scanner};

const DEFAULT_LIMIT: usize = 1_000;
const PREVIEW_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct YaraInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the scanner.
    pub case_id: String,

    /// Target to scan. May be a single file or a directory. When a
    /// directory, `recursive=true` walks all descendants (capped by
    /// the limit below); `recursive=false` only scans top-level files.
    pub target_path: PathBuf,

    /// Path to a YARA rules file (`.yar` / `.yara`) OR a directory of
    /// rules files. Directories are walked recursively for any file
    /// with `.yar` / `.yara` / `.yarx` extension and all matched files
    /// are merged into one Rules instance before scanning.
    pub rules_path: PathBuf,

    /// When `target_path` is a directory: walk all descendants. Default
    /// false (top-level only). Always false for a single-file target.
    #[serde(default, skip_serializing_if = "is_false")]
    pub recursive: bool,

    /// Hard cap on total matches emitted across all scanned files.
    /// Default 1000. Smaller values keep the response under the
    /// MCP token budget when scanning a noisy ruleset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct YaraPatternMatch {
    /// Pattern identifier from the rule (e.g. `$a`, `$mz`).
    pub identifier: String,

    /// Byte offset within the scanned file where the match starts.
    pub offset: u64,

    /// Length of the matched bytes.
    pub length: usize,

    /// First 64 bytes of the matched data, lowercase hex. Truncated
    /// silently if the match is longer; full bytes are not returned
    /// to keep responses bounded.
    pub preview_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct YaraMatch {
    /// Absolute path to the file that matched.
    pub file_path: String,

    /// Rule identifier (the `rule X { ... }` name).
    pub rule_name: String,

    /// Rule namespace (typically the rules-file basename for our
    /// merged-Rules approach; empty string for the default ns).
    pub namespace: String,

    /// Tags declared on the rule (`rule X : tag1 tag2 { ... }`).
    pub tags: Vec<String>,

    /// One entry per matched pattern. Empty rules with no patterns
    /// (pure condition-only rules) yield an empty list.
    pub pattern_matches: Vec<YaraPatternMatch>,
}

#[derive(Clone, Debug, Serialize)]
pub struct YaraOutput {
    pub matches: Vec<YaraMatch>,
    pub files_scanned: usize,
    pub rules_compiled: usize,
    pub scan_errors: usize,
}

#[derive(Debug, Error)]
pub enum YaraError {
    #[error("YARA target not found: {0}")]
    TargetNotFound(PathBuf),

    #[error("YARA rules path not found: {0}")]
    RulesNotFound(PathBuf),

    #[error("no YARA rules files found under {0} (looking for .yar/.yara/.yarx)")]
    NoRulesFiles(PathBuf),

    #[error("YARA rules unreadable {path}: {source}")]
    RulesUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("YARA rules compile failed in {path}: {message}")]
    RulesCompileFailed { path: PathBuf, message: String },
}

/// Cheap pre-flight: file path looks like a YARA rules file.
#[must_use]
pub fn path_looks_like_yara_rules(path: &Path) -> bool {
    path.extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("yar")
            || e.eq_ignore_ascii_case("yara")
            || e.eq_ignore_ascii_case("yarx")
    })
}

/// Compile YARA rules from a file or directory and scan a target.
///
/// # Errors
/// * [`YaraError::TargetNotFound`] / [`YaraError::RulesNotFound`] —
///   filesystem path missing.
/// * [`YaraError::NoRulesFiles`] — `rules_path` is a directory but
///   contains no `.yar`/`.yara`/`.yarx` files.
/// * [`YaraError::RulesUnreadable`] — I/O error reading rules.
/// * [`YaraError::RulesCompileFailed`] — YARA syntax error or
///   unsupported feature in the supplied rules.
pub fn yara_scan(input: &YaraInput) -> Result<YaraOutput, YaraError> {
    if !input.target_path.exists() {
        return Err(YaraError::TargetNotFound(input.target_path.clone()));
    }
    if !input.rules_path.exists() {
        return Err(YaraError::RulesNotFound(input.rules_path.clone()));
    }

    let rule_files = collect_rule_files(&input.rules_path);
    if rule_files.is_empty() {
        return Err(YaraError::NoRulesFiles(input.rules_path.clone()));
    }

    let rules = compile_rules(&rule_files)?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let target_files = collect_target_files(&input.target_path, input.recursive);

    let mut output = YaraOutput {
        matches: Vec::new(),
        files_scanned: 0,
        rules_compiled: rule_files.len(),
        scan_errors: 0,
    };

    let mut scanner = Scanner::new(&rules);
    'files: for file in target_files {
        if output.matches.len() >= limit {
            break;
        }
        output.files_scanned += 1;

        let Ok(scan_result) = scanner.scan_file(&file) else {
            output.scan_errors += 1;
            continue;
        };

        for matching_rule in scan_result.matching_rules() {
            if output.matches.len() >= limit {
                break 'files;
            }
            output.matches.push(YaraMatch {
                file_path: file.to_string_lossy().into_owned(),
                rule_name: matching_rule.identifier().to_string(),
                namespace: matching_rule.namespace().to_string(),
                tags: matching_rule
                    .tags()
                    .map(|t| t.identifier().to_string())
                    .collect(),
                pattern_matches: collect_pattern_matches(&matching_rule),
            });
        }
    }

    Ok(output)
}

fn collect_rule_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    walk_dir(path, true, &mut |p| {
        if p.is_file() && path_looks_like_yara_rules(p) {
            out.push(p.to_path_buf());
        }
    });
    out
}

fn collect_target_files(path: &Path, recursive: bool) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut out = Vec::new();
    walk_dir(path, recursive, &mut |p| {
        if p.is_file() {
            out.push(p.to_path_buf());
        }
    });
    out
}

fn walk_dir(root: &Path, recursive: bool, visit: &mut dyn FnMut(&Path)) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            visit(&path);
        } else if path.is_dir() && recursive {
            walk_dir(&path, recursive, visit);
        }
    }
}

fn compile_rules(rule_files: &[PathBuf]) -> Result<Rules, YaraError> {
    let mut compiler = Compiler::new();
    for path in rule_files {
        let source = fs::read_to_string(path).map_err(|err| YaraError::RulesUnreadable {
            path: path.clone(),
            source: err,
        })?;
        // Use the file basename as the namespace so matches are
        // attributable to which rules file fired them.
        let namespace = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("default")
            .to_string();
        compiler.new_namespace(&namespace);
        compiler
            .add_source(source.as_str())
            .map_err(|err| YaraError::RulesCompileFailed {
                path: path.clone(),
                message: format!("{err}"),
            })?;
    }
    Ok(compiler.build())
}

fn collect_pattern_matches(rule: &yara_x::Rule<'_, '_>) -> Vec<YaraPatternMatch> {
    let mut out = Vec::new();
    for pattern in rule.patterns() {
        for m in pattern.matches() {
            let range = m.range();
            let data = m.data();
            let preview_len = data.len().min(PREVIEW_BYTES);
            out.push(YaraPatternMatch {
                identifier: pattern.identifier().to_string(),
                offset: u64::try_from(range.start).unwrap_or(u64::MAX),
                length: range.len(),
                preview_hex: hex::encode(&data[..preview_len]),
            });
        }
    }
    out
}
