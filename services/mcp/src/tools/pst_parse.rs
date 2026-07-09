//! `pst_parse` — subprocess wrapper for libpff's `pffexport`.
//!
//! Microsoft Outlook stores mail in Personal Storage Table (`.pst`) and
//! Offline Storage Table (`.ost`) files. No other product tool reads them:
//! `email_parse` handles `.eml`/mbox and `oe_dbx_parse` handles Outlook
//! Express `.dbx`, but the PST/OST container needs `libpff`. `pffexport`
//! (from `libpff` — ships on SIFT and in the DFIR container) walks the
//! folder/message tree and writes it to disk. Run with `-m all` it also
//! RECOVERS deleted and orphaned items from unallocated PST space, which
//! is the high-value DFIR surface: mail a suspect deleted from Outlook can
//! still be reconstructed from the store.
//!
//! This tool wraps that export and summarizes each message's METADATA
//! (sender, recipients, subject, delivery time, folder, recovered flag).
//! Message BODIES are never copied into the tool output — only the export
//! tree on disk holds them, and that lives under the case dir.
//!
//! INSTALL-FIRST / DEGRADE-SAFE: `pffexport` is not on every host (the
//! current dev host has no `libpff`). When it is absent the tool returns
//! [`PstParseOutput`] with `pffexport_available: false` and empty
//! summaries — it never errors, so every other tool keeps working.
//!
//! Invocation (fixed argv):
//!   `pffexport -m all -t <case_staging_prefix> <artifact_path>`
//!
//! `pffexport -t <prefix>` writes an export tree rooted at `<prefix>.export/`
//! holding one directory per message. This tool parses each message's
//! `OutlookHeaders.txt`, which `pffexport` emits as newline-delimited
//! `Label:<whitespace>Value` records. The concrete labels this parser reads
//! (case-insensitive, one record per line, value = remainder trimmed):
//!
//! ```text
//! Client submit time:     Mar 20, 2003 12:00:00.000000000 UTC
//! Delivery time:          Mar 20, 2003 12:00:05.000000000 UTC
//! Sender name:            Alice Example
//! Sender email address:   alice@example.test
//! Subject:                Quarterly numbers
//! Displayed recipients:   Bob Example; Carol Example
//! ```
//!
//! `Sender name` is the sender (falling back to `Sender email address` when
//! the display name is blank); `Delivery time` is the delivery timestamp
//! (falling back to `Client submit time`); recipients are split from
//! `Displayed recipients` (or `Recipients`) on `;`. Recovered/orphaned
//! messages appear under a `Recovered` (or `Orphan…`) path segment in the
//! export tree and are flagged `recovered: true`.
//!
//! Binary discovery: `$FINDEVIL_PFFEXPORT_BIN` (default `pffexport`), then
//! PATH — the same resolution shape as `ez_parse` / `indx_parse`.
//!
//! DFIR honesty: metadata is reported exactly as exported. Presence of a
//! message is not evidence of exfiltration, intent, or who read it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default binary name when `$FINDEVIL_PFFEXPORT_BIN` is unset.
const DEFAULT_BINARY: &str = "pffexport";

/// Hard cap on surfaced messages / aggregate entries. The true total is
/// always reported in `message_count`.
const MAX_MESSAGES: usize = 500;

/// Cap on bytes read from a single `OutlookHeaders.txt` (metadata is tiny;
/// this only bounds a pathological/hostile file).
const MAX_HEADER_BYTES: u64 = 256 * 1024;

/// Cap on directory entries walked in the export tree (defense against a
/// pathologically deep/wide export).
const MAX_WALK_ENTRIES: usize = 500_000;

/// The header file `pffexport` writes per message.
const HEADER_FILENAME: &str = "OutlookHeaders.txt";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PstParseInput {
    /// Case ID from a prior `case_open` call. Used to locate the case dir
    /// the export is staged under, and for audit correlation.
    pub case_id: String,

    /// Path to the Outlook `.pst` / `.ost` store to export.
    pub artifact_path: PathBuf,
}

/// One exported message's metadata. Bodies are intentionally absent.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PstMessage {
    /// Sender display name, or the sender email address when the display
    /// name was blank. `None` if neither was present.
    pub from: Option<String>,

    /// Recipient display names / addresses, split from the recipients line.
    pub to: Vec<String>,

    /// Message subject, if present.
    pub subject: Option<String>,

    /// Delivery time (or client-submit time fallback), verbatim as
    /// `pffexport` formatted it. Not normalized — reported as parsed.
    pub delivery_time: Option<String>,

    /// Enclosing mail folder name (the export dir above the message dir).
    pub folder: Option<String>,

    /// True when this message was found under a recovered/orphan subtree —
    /// i.e. reconstructed by `pffexport -m all` from unallocated PST space.
    pub recovered: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PstParseOutput {
    /// False when `pffexport` was not installed. All other fields are then
    /// empty/zero — this is a graceful degrade, not an error.
    pub pffexport_available: bool,

    /// Total messages found in the export (before the `MAX_MESSAGES` cap on
    /// the `messages` vector).
    pub message_count: usize,

    /// Per-message metadata, sorted by (folder, `delivery_time`, subject,
    /// from) and capped at `MAX_MESSAGES`.
    pub messages: Vec<PstMessage>,

    /// How many messages were flagged `recovered` (deleted/orphaned items
    /// reconstructed from unallocated space).
    pub recovered_deleted_count: usize,

    /// Sorted, de-duplicated sender values across all messages (capped).
    pub unique_senders: Vec<String>,

    /// Sorted, de-duplicated subjects across all messages (capped).
    pub subjects: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PstError {
    #[error("PST/OST artifact not found: {0}")]
    NotFound(PathBuf),

    #[error("PST/OST path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error("case dir not found for case_id {0:?} (call case_open first)")]
    CaseNotFound(String),

    #[error("invalid case_id (must match [A-Za-z0-9_-]+, no path separators or '.'/'..'): {0}")]
    InvalidCaseId(String),

    #[error("could not create export staging dir {path}: {source}")]
    StagingCreate {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("pffexport exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not walk pffexport output: {0}")]
    OutputWalk(String),
}

/// Export an Outlook PST/OST with `pffexport -m all` and summarize the
/// exported messages' metadata.
///
/// # Errors
/// * [`PstError::NotFound`] / [`PstError::NotRegular`] — bad input path.
/// * [`PstError::CaseNotFound`] — no case dir for `case_id` (staging needs it).
/// * [`PstError::StagingCreate`] — the case staging dir could not be made.
/// * [`PstError::SubprocessFailed`] — `pffexport` returned non-zero.
/// * [`PstError::OutputWalk`] — the export tree could not be read.
///
/// A MISSING `pffexport` binary is NOT an error: the returned output has
/// `pffexport_available: false` and empty summaries.
pub fn pst_parse(input: &PstParseInput) -> Result<PstParseOutput, PstError> {
    if !input.artifact_path.exists() {
        return Err(PstError::NotFound(input.artifact_path.clone()));
    }
    if !input.artifact_path.is_file() {
        return Err(PstError::NotRegular(input.artifact_path.clone()));
    }

    // Degrade-safe: no libpff on this host → typed "unavailable", never error.
    let Some(binary) = resolve_pffexport() else {
        return Ok(unavailable_output());
    };

    // Stage the export UNDER THE CASE DIR — never beside the evidence.
    let case_dir = case_dir(&input.case_id)?;
    let staging = case_dir
        .join("extracted")
        .join("pst")
        .join(format!("pst-export-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&staging).map_err(|source| PstError::StagingCreate {
        path: staging.clone(),
        source,
    })?;

    let prefix = staging.join("store");
    let args = build_pffexport_args(&prefix, &input.artifact_path);

    // Defense-in-depth: refuse a poisoned $FINDEVIL_PFFEXPORT_BIN that
    // resolves to a denied binary, and reject NUL bytes in the args.
    if let Err(e) = crate::tools::argsafe::guard_spawn(&binary, &args) {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(PstError::SubprocessFailed {
            exit_code: -1,
            stderr: e.to_string(),
        });
    }

    let proc = Command::new(&binary).args(&args).output();
    let proc = match proc {
        Ok(proc) => proc,
        // Lost the resolve→spawn race (binary vanished, or PATH probe found a
        // stale entry): still degrade, do not error.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = std::fs::remove_dir_all(&staging);
            return Ok(unavailable_output());
        }
        Err(err) => {
            let _ = std::fs::remove_dir_all(&staging);
            return Err(PstError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            });
        }
    };

    if !proc.status.success() {
        let stderr = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);
        let _ = std::fs::remove_dir_all(&staging);
        return Err(PstError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr,
        });
    }

    let messages = summarize_export(&staging).map_err(PstError::OutputWalk)?;
    Ok(build_output(messages, true))
}

/// The output returned when `pffexport` is not installed.
const fn unavailable_output() -> PstParseOutput {
    PstParseOutput {
        pffexport_available: false,
        message_count: 0,
        messages: Vec::new(),
        recovered_deleted_count: 0,
        unique_senders: Vec::new(),
        subjects: Vec::new(),
    }
}

/// Build the fixed argv: `-m all -t <prefix> <artifact>`. Pure + tested.
fn build_pffexport_args(prefix: &Path, artifact: &Path) -> Vec<OsString> {
    vec![
        "-m".into(),
        "all".into(),
        "-t".into(),
        prefix.as_os_str().to_os_string(),
        artifact.as_os_str().to_os_string(),
    ]
}

/// Resolve the `pffexport` binary: `$FINDEVIL_PFFEXPORT_BIN` (a name or an
/// explicit path) then a PATH probe. `None` means "not installed" — the
/// degrade signal. Mirrors `ez_parse`'s env-default-then-PATH shape.
fn resolve_pffexport() -> Option<PathBuf> {
    let name = std::env::var("FINDEVIL_PFFEXPORT_BIN")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BINARY.to_string());

    // An explicit path (contains a separator) is taken as-is when it exists.
    let candidate = PathBuf::from(&name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then_some(candidate);
    }

    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name
    };
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(&exe);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Resolve `$FINDEVIL_HOME/cases/<case_id>` (mirrors the disk tool's helper).
fn case_dir(case_id: &str) -> Result<PathBuf, PstError> {
    if !super::case_id::is_valid_case_id(case_id) {
        return Err(PstError::InvalidCaseId(case_id.to_string()));
    }
    let dir = findevil_home()
        .ok_or_else(|| PstError::CaseNotFound(case_id.to_string()))?
        .join("cases")
        .join(case_id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(PstError::CaseNotFound(case_id.to_string()))
    }
}

fn findevil_home() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h).join(".findevil"));
        }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p).join(".findevil"));
        }
    }
    None
}

/// Walk the export tree under `root`, parsing every `OutlookHeaders.txt`
/// into a fully-populated [`PstMessage`] (folder + recovered flag set from
/// its path). Iterative DFS — no recursion, bounded by `MAX_WALK_ENTRIES`.
///
/// # Errors
/// Returns a message when the root directory cannot be read.
fn summarize_export(root: &Path) -> Result<Vec<PstMessage>, String> {
    let mut messages = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    let mut visited = 0usize;

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            // A single unreadable subdir must not abort the whole walk; the
            // root itself failing is the only hard error.
            Err(e) if dir == root => return Err(format!("read_dir {}: {e}", root.display())),
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_WALK_ENTRIES {
                return Ok(messages);
            }
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().is_some_and(|n| n == HEADER_FILENAME) {
                if let Some(msg) = read_message(&path) {
                    messages.push(msg);
                }
            }
        }
    }
    Ok(messages)
}

/// Read one `OutlookHeaders.txt` and build its message, tagging folder and
/// recovered from the path. `None` only when the file is unreadable.
fn read_message(header_path: &Path) -> Option<PstMessage> {
    let text = read_capped(header_path, MAX_HEADER_BYTES)?;
    let mut msg = parse_pff_message_headers(&text);
    msg.folder = message_folder(header_path);
    msg.recovered = path_is_recovered(header_path);
    Some(msg)
}

/// Read at most `cap` bytes of a file as lossy UTF-8. `None` on IO error.
fn read_capped(path: &Path, cap: u64) -> Option<String> {
    use std::io::Read;
    let file = std::fs::File::open(path).ok()?;
    let mut buf = Vec::new();
    file.take(cap).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Pure parser for `pffexport`'s `OutlookHeaders.txt` records. See the module
/// doc for the exact label shape. Unknown lines are ignored; a text with no
/// recognized label yields an all-empty message and never panics. `folder`
/// and `recovered` are set by the caller from the path, not the text.
fn parse_pff_message_headers(text: &str) -> PstMessage {
    let mut from_name: Option<String> = None;
    let mut from_email: Option<String> = None;
    let mut subject: Option<String> = None;
    let mut delivery: Option<String> = None;
    let mut submit: Option<String> = None;
    let mut to: Vec<String> = Vec::new();

    for line in text.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match label.trim().to_ascii_lowercase().as_str() {
            "sender name" => from_name = Some(value.to_string()),
            "sender email address" => from_email = Some(value.to_string()),
            "subject" => subject = Some(value.to_string()),
            "delivery time" => delivery = Some(value.to_string()),
            "client submit time" => submit = Some(value.to_string()),
            "displayed recipients" | "recipients" | "to" => {
                to = split_recipients(value);
            }
            _ => {}
        }
    }

    PstMessage {
        from: from_name.or(from_email),
        to,
        subject,
        delivery_time: delivery.or(submit),
        folder: None,
        recovered: false,
    }
}

/// Split a recipients field on `;` into trimmed, non-empty entries.
fn split_recipients(value: &str) -> Vec<String> {
    value
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// The enclosing mail-folder name: the directory ABOVE the per-message
/// directory that holds `OutlookHeaders.txt`
/// (`…/<folder>/<MessageNNNN>/OutlookHeaders.txt`).
fn message_folder(header_path: &Path) -> Option<String> {
    let message_dir = header_path.parent()?;
    let folder_dir = message_dir.parent()?;
    folder_dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
}

/// True when any component of `path` marks a recovered/orphan subtree —
/// where `pffexport -m all` places items reconstructed from unallocated
/// space. Matched case-insensitively: exactly `recovered`, or an `orphan…`
/// prefix (`Orphan`, `Orphans`).
fn path_is_recovered(path: &Path) -> bool {
    path.components().any(|c| {
        let name = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        name == "recovered" || name.starts_with("orphan")
    })
}

/// Assemble the output: sort messages by a stable key, cap them, and derive
/// the de-duplicated sender/subject aggregates and recovered count. Pure +
/// tested so the sort/dedup/cap contract can't regress.
fn build_output(mut messages: Vec<PstMessage>, available: bool) -> PstParseOutput {
    messages.sort_by_key(sort_key);

    let message_count = messages.len();
    let recovered_deleted_count = messages.iter().filter(|m| m.recovered).count();

    let unique_senders = dedup_capped(messages.iter().filter_map(|m| m.from.clone()));
    let subjects = dedup_capped(messages.iter().filter_map(|m| m.subject.clone()));

    messages.truncate(MAX_MESSAGES);

    PstParseOutput {
        pffexport_available: available,
        message_count,
        messages,
        recovered_deleted_count,
        unique_senders,
        subjects,
    }
}

/// Stable ordering key: folder, then delivery time, subject, sender. `None`
/// sorts before `Some` via the empty string.
fn sort_key(m: &PstMessage) -> (String, String, String, String) {
    let s = |o: &Option<String>| o.clone().unwrap_or_default();
    (s(&m.folder), s(&m.delivery_time), s(&m.subject), s(&m.from))
}

/// Collect an iterator into a sorted, de-duplicated, capped `Vec<String>`.
fn dedup_capped<I: IntoIterator<Item = String>>(iter: I) -> Vec<String> {
    let mut v: Vec<String> = iter.into_iter().collect();
    v.sort();
    v.dedup();
    v.truncate(MAX_MESSAGES);
    v
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

// ---------------------------------------------------------------------------
// Unit tests for the pure parser, path predicates, argv builder, and the
// aggregate builder. The real `pffexport` invocation stays opt-in (the binary
// is absent on this host), matching indx_parse / ez_parse.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn as_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn build_pffexport_args_is_mode_all_target_then_artifact() {
        let args = build_pffexport_args(
            Path::new("/case/extracted/pst/pst-export-x/store"),
            Path::new("/case/evidence/outlook.pst"),
        );
        assert_eq!(
            as_strings(&args),
            vec![
                "-m",
                "all",
                "-t",
                "/case/extracted/pst/pst-export-x/store",
                "/case/evidence/outlook.pst",
            ]
        );
    }

    #[test]
    fn parse_headers_extracts_from_subject_and_delivery_time() {
        // The concrete pffexport OutlookHeaders.txt shape (see module doc).
        let text = "Client submit time:\tMar 20, 2003 12:00:00.000000000 UTC\n\
                    Delivery time:\t\tMar 20, 2003 12:00:05.000000000 UTC\n\
                    Sender name:\t\tAlice Example\n\
                    Sender email address:\talice@example.test\n\
                    Subject:\t\tQuarterly numbers\n\
                    Displayed recipients:\tBob Example; Carol Example\n";
        let msg = parse_pff_message_headers(text);
        assert_eq!(msg.from.as_deref(), Some("Alice Example"));
        assert_eq!(msg.subject.as_deref(), Some("Quarterly numbers"));
        assert_eq!(
            msg.delivery_time.as_deref(),
            Some("Mar 20, 2003 12:00:05.000000000 UTC")
        );
        assert_eq!(msg.to, vec!["Bob Example", "Carol Example"]);
        // Set by the caller from the path, not the header text.
        assert_eq!(msg.folder, None);
        assert!(!msg.recovered);
    }

    #[test]
    fn parse_headers_falls_back_to_email_and_submit_time() {
        // Blank display name → email address; no delivery time → submit time.
        let text = "Sender name:\t\nSender email address:\tmallory@example.test\n\
                    Client submit time:\tJan 01, 2020 00:00:00 UTC\nSubject:\tRe: plans\n";
        let msg = parse_pff_message_headers(text);
        assert_eq!(msg.from.as_deref(), Some("mallory@example.test"));
        assert_eq!(
            msg.delivery_time.as_deref(),
            Some("Jan 01, 2020 00:00:00 UTC")
        );
        assert_eq!(msg.subject.as_deref(), Some("Re: plans"));
        assert!(msg.to.is_empty());
    }

    #[test]
    fn parse_headers_malformed_text_yields_all_none_and_no_panic() {
        let msg = parse_pff_message_headers("garbage with no labels\n\n   \nnot even a colon");
        assert_eq!(msg.from, None);
        assert_eq!(msg.subject, None);
        assert_eq!(msg.delivery_time, None);
        assert!(msg.to.is_empty());
        assert!(!msg.recovered);
    }

    #[test]
    fn path_is_recovered_flags_recovered_and_orphan_subtrees() {
        assert!(path_is_recovered(Path::new(
            "/c/store.export/Recovered/Message00001/OutlookHeaders.txt"
        )));
        assert!(path_is_recovered(Path::new(
            "/c/store.export/Orphans/Message9/OutlookHeaders.txt"
        )));
        // A normal allocated folder is not recovered.
        assert!(!path_is_recovered(Path::new(
            "/c/store.export/Top of Personal Folders/Inbox/Message00001/OutlookHeaders.txt"
        )));
    }

    #[test]
    fn message_folder_is_the_dir_above_the_message_dir() {
        let folder = message_folder(Path::new(
            "/c/store.export/Inbox/Message00042/OutlookHeaders.txt",
        ));
        assert_eq!(folder.as_deref(), Some("Inbox"));
    }

    #[test]
    fn build_output_sorts_dedups_and_counts_recovered() {
        let mk = |folder: &str, from: &str, subject: &str, recovered: bool| PstMessage {
            from: Some(from.to_string()),
            to: Vec::new(),
            subject: Some(subject.to_string()),
            delivery_time: None,
            folder: Some(folder.to_string()),
            recovered,
        };
        // Deliberately unsorted; duplicate sender + subject across messages.
        let messages = vec![
            mk("Sent", "bob@example.test", "hello", false),
            mk("Inbox", "alice@example.test", "hello", true),
            mk("Inbox", "alice@example.test", "agenda", false),
        ];
        let out = build_output(messages, true);

        assert!(out.pffexport_available);
        assert_eq!(out.message_count, 3);
        assert_eq!(out.recovered_deleted_count, 1);
        // Sorted by folder first: Inbox entries precede Sent.
        assert_eq!(out.messages[0].folder.as_deref(), Some("Inbox"));
        assert_eq!(out.messages[2].folder.as_deref(), Some("Sent"));
        // Senders de-duplicated and sorted.
        assert_eq!(
            out.unique_senders,
            vec!["alice@example.test", "bob@example.test"]
        );
        // Subjects de-duplicated and sorted.
        assert_eq!(out.subjects, vec!["agenda", "hello"]);
    }

    #[test]
    fn unavailable_output_is_empty_and_not_available() {
        let out = unavailable_output();
        assert!(!out.pffexport_available);
        assert_eq!(out.message_count, 0);
        assert!(out.messages.is_empty());
        assert_eq!(out.recovered_deleted_count, 0);
        assert!(out.unique_senders.is_empty());
        assert!(out.subjects.is_empty());
    }

    #[test]
    fn truncate_to_passthrough_and_multibyte_safe() {
        assert_eq!(truncate_to("short".to_string(), 100), "short");
        let s: String = "\u{FFFD}".repeat(1000);
        let out = truncate_to(s, 100);
        assert!(out.ends_with("…[truncated]"));
        let body_len = out.len() - "…[truncated]".len();
        assert!(out.is_char_boundary(body_len));
    }
}
