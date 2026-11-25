//! `mft_timeline` — extract timeline events from an NTFS Master File Table.
//!
//! Spec #2 §6 + `agent-config/MEMORY.md`. The MFT is the canonical "did
//! this file ever exist?" artifact for NTFS. Combined with Prefetch
//! (`prefetch_parse`) it satisfies the SOUL.md ≥2 artifact-class rule
//! for execution claims: MFT confirms the binary was on disk; Prefetch
//! confirms it ran.
//!
//! **DFIR caveat (per MEMORY.md):** `$SI` (`$STANDARD_INFORMATION`)
//! timestamps are trivially stompable via the `SetFileTime` API.
//! `$FN` (`$FILE_NAME`) timestamps are only updated on the rare path of
//! file rename/move and are tamper-evident. Our output exposes BOTH so
//! the agent can detect timestomping by comparing them. A binary whose
//! `$SI.modified` is older than its `$FN.modified` is a strong
//! tampering signal.
//!
//! Backed by `mft = "=0.6.1"` (omerbenamram, MIT, 100% safe Rust). Parses
//! every entry (allocated and unallocated). The tool exposes the most
//! agent-relevant fields: the four MAC times for both $SI and $FN, the
//! parent reference, the file name, the resolved full path, allocation
//! and directory flags, and the logical size.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use mft::attribute::x10::StandardInfoAttr;
use mft::attribute::x30::{FileNameAttr, FileNamespace};
use mft::attribute::{FileAttributeFlags, MftAttributeContent};
use mft::entry::EntryFlags;
use mft::MftParser;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MftInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Absolute or relative path to the `$MFT` file (or a Velociraptor /
    /// `MFTECmd` export of it).
    pub mft_path: PathBuf,

    /// Optional inclusive lower bound on `$SI.modified`. UTC ISO-8601
    /// (e.g. `2026-04-25T00:00:00Z`). Entries older than this are
    /// dropped. Use to focus the timeline around an incident window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,

    /// Optional inclusive upper bound on `$SI.modified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_iso: Option<String>,

    /// Optional row cap. Default `10_000`. Returned `row_count` reports
    /// how many matched the filter; `records_seen` reports total entries
    /// scanned including those filtered out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MftEntryRow {
    /// MFT record number (entry index).
    pub record_number: u64,

    /// Parent directory's MFT record number (from `$FN`). None when no
    /// `$FN` attribute was found (rare; usually only on system entries).
    pub parent_record_number: Option<u64>,

    /// File or directory name from `$FN`. Empty string when absent.
    pub name: String,

    /// Full path resolved by walking parent references. May be None if
    /// any ancestor entry is unallocated or unparseable.
    pub full_path: Option<String>,

    /// True if the `$FN` attribute has the `FILE_ATTRIBUTE_DIRECTORY`
    /// flag set.
    pub is_directory: bool,

    /// True if the entry's `EntryFlags::ALLOCATED` bit is set. False
    /// entries are deleted/freed; their attributes may still parse but
    /// the data they reference can be reused.
    pub is_allocated: bool,

    /// Logical size from `$FN.logical_size`. 0 for directories or when
    /// `$FN` is absent.
    pub logical_size: u64,

    // ---- $STANDARD_INFORMATION timestamps (stompable, per MEMORY.md) ----
    pub si_created_iso: Option<String>,
    pub si_modified_iso: Option<String>,
    pub si_accessed_iso: Option<String>,
    pub si_mft_modified_iso: Option<String>,

    // ---- $FILE_NAME timestamps (tamper-evident reference) ----
    pub fn_created_iso: Option<String>,
    pub fn_modified_iso: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MftOutput {
    pub entries: Vec<MftEntryRow>,

    /// Per-record parse failures swallowed during the scan (e.g. broken
    /// fixup arrays). The walk does not abort on a single bad entry;
    /// counts are reported so the caller can sanity-check completeness.
    pub parse_errors: usize,

    /// Total entries the parser saw before any filter.
    pub records_seen: usize,

    /// Length of `entries` after filter + limit.
    pub row_count: usize,
}

#[derive(Debug, Error)]
pub enum MftError {
    #[error("MFT file not found: {0}")]
    MftNotFound(PathBuf),

    #[error("MFT file unreadable {path}: {source}")]
    MftUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Boxed because `mft::err::Error` is large enough to push our
    /// `Result<_, MftError>` over clippy's `result_large_err` threshold.
    #[error("MFT parser failed to open {path}: {source}")]
    MftOpen {
        path: PathBuf,
        #[source]
        source: Box<mft::err::Error>,
    },

    #[error("invalid time filter {value:?}: {reason}")]
    InvalidTimeFilter { value: String, reason: String },
}

/// Cheap pre-flight: file path looks like an MFT export.
///
/// Used by the Python agent to pick which MCP tool to dispatch. Common
/// names: `$MFT`, `MFT`, `mft.bin`, `<host>.mft`. We treat anything
/// ending in `mft` (case-insensitive) or starting with `$MFT` as a
/// candidate; the actual parser is the source of truth.
#[must_use]
pub fn path_looks_like_mft(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("$mft") || lower == "mft" {
        return true;
    }
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("mft"))
}

/// Parse an `$MFT` file and produce a timeline.
///
/// The walk is two-pass internally: pass 1 collects entries (so the
/// borrow on `parser` is released); pass 2 resolves `full_path` for
/// each retained row. This trades a small heap allocation for the
/// ability to call `get_full_path_for_entry` at all (it requires
/// `&mut parser`, which conflicts with the `iter_entries` borrow).
///
/// # Errors
/// * [`MftError::MftNotFound`] — the file does not exist.
/// * [`MftError::MftUnreadable`] — exists but cannot be read.
/// * [`MftError::MftOpen`] — file is not a valid `$MFT` (wrong magic).
/// * [`MftError::InvalidTimeFilter`] — `since_iso` or `until_iso` is
///   not a parseable RFC 3339 / ISO-8601 string.
pub fn mft_timeline(input: &MftInput) -> Result<MftOutput, MftError> {
    let path = &input.mft_path;
    if !path.is_file() {
        return Err(MftError::MftNotFound(path.clone()));
    }

    let since = parse_optional_iso(input.since_iso.as_deref())?;
    let until = parse_optional_iso(input.until_iso.as_deref())?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut parser = MftParser::from_path(path).map_err(|err| MftError::MftOpen {
        path: path.clone(),
        source: Box::new(err),
    })?;

    // Pass 1: collect raw entries so the iterator borrow on `parser`
    // ends before we ask for `get_full_path_for_entry`.
    let raw_entries: Vec<Result<mft::MftEntry, mft::err::Error>> = parser.iter_entries().collect();

    let mut entries: Vec<MftEntryRow> = Vec::new();
    let mut parse_errors: usize = 0;
    let mut records_seen: usize = 0;

    for entry_result in raw_entries {
        records_seen += 1;
        let Ok(entry) = entry_result else {
            parse_errors += 1;
            continue;
        };

        // Extract the most agent-relevant attributes.
        let (x10, x30) = extract_attrs(&entry);

        // Apply time filter against $SI.modified (the field analysts
        // typically narrow on; stompability of $SI is the agent's
        // problem to flag, not the timeline tool's to hide).
        if let Some(ref si) = x10 {
            if let Some(lo) = since {
                if si.modified < lo {
                    continue;
                }
            }
            if let Some(hi) = until {
                if si.modified > hi {
                    continue;
                }
            }
        }

        let full_path = parser
            .get_full_path_for_entry(&entry)
            .ok()
            .flatten()
            .map(|p| p.to_string_lossy().into_owned());

        entries.push(MftEntryRow {
            record_number: entry.header.record_number,
            parent_record_number: x30.as_ref().map(|f| f.parent.entry),
            name: x30.as_ref().map(|f| f.name.clone()).unwrap_or_default(),
            full_path,
            is_directory: x30.as_ref().is_some_and(|f| {
                f.flags
                    .contains(FileAttributeFlags::FILE_ATTRIBUTE_DIRECTORY)
            }),
            is_allocated: entry.header.flags.contains(EntryFlags::ALLOCATED),
            logical_size: x30.as_ref().map_or(0, |f| f.logical_size),
            si_created_iso: x10.as_ref().map(|s| iso(&s.created)),
            si_modified_iso: x10.as_ref().map(|s| iso(&s.modified)),
            si_accessed_iso: x10.as_ref().map(|s| iso(&s.accessed)),
            si_mft_modified_iso: x10.as_ref().map(|s| iso(&s.mft_modified)),
            fn_created_iso: x30.as_ref().map(|f| iso(&f.created)),
            fn_modified_iso: x30.as_ref().map(|f| iso(&f.modified)),
        });

        if entries.len() >= limit {
            break;
        }
    }

    let row_count = entries.len();
    Ok(MftOutput {
        entries,
        parse_errors,
        records_seen,
        row_count,
    })
}

/// Best-effort attribute extraction. Prefers the Win32 namespace `$FN`
/// when multiple are present (DOS 8.3 names are typically duplicates).
fn extract_attrs(entry: &mft::MftEntry) -> (Option<StandardInfoAttr>, Option<FileNameAttr>) {
    let mut x10: Option<StandardInfoAttr> = None;
    let mut x30: Option<FileNameAttr> = None;
    for attr_result in entry.iter_attributes() {
        let Ok(attr) = attr_result else {
            continue;
        };
        match attr.data {
            MftAttributeContent::AttrX10(s) => {
                if x10.is_none() {
                    x10 = Some(s);
                }
            }
            MftAttributeContent::AttrX30(f) => {
                let prefer = matches!(
                    f.namespace,
                    FileNamespace::Win32 | FileNamespace::Win32AndDos
                );
                if x30.is_none() || prefer {
                    x30 = Some(f);
                }
            }
            _ => {}
        }
    }
    (x10, x30)
}

fn iso(dt: &DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

fn parse_optional_iso(value: Option<&str>) -> Result<Option<DateTime<Utc>>, MftError> {
    value.map_or(Ok(None), |s| {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|err| MftError::InvalidTimeFilter {
                value: s.to_string(),
                reason: err.to_string(),
            })
    })
}
