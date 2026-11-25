//! `usnjrnl_query` — extract change records from an NTFS USN Journal.
//!
//! Spec #2 §6 + Pool B exfil territory. The USN Journal records every
//! file-system mutation (create, delete, rename, write, EA change, ACL
//! change) in a circular buffer at `\$Extend\$UsnJrnl:$J`. It's the
//! canonical answer to "what files were touched between time A and
//! time B" — far more complete than the MFT alone because the MFT only
//! shows the *current* state while the USN journal shows the history.
//!
//! Backed by `usnjrnl-forensic = "=0.6.0"` (MIT). The crate's
//! `UsnJournalReader` is a streaming `Read + Seek` iterator, so we can
//! handle multi-GB journals without loading everything into memory.
//!
//! **DFIR caveat (per agent-config/MEMORY.md):** `UsnJrnl` is a *circular*
//! buffer — older records get overwritten. Gaps in the timestamp
//! sequence are normal, not suspicious by themselves. Always pair USN
//! findings with MFT timeline corroboration before claiming "no
//! activity occurred at time T" — the journal may simply have wrapped
//! past T.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use usnjrnl_forensic::usn::{UsnJournalReader, UsnReason};

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UsnJrnlInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Absolute or relative path to the `$UsnJrnl:$J` data stream
    /// (carved with e.g. `MFTECmd --csv` or extracted by Velociraptor /
    /// `extractusn`). Plain raw `$J` data is what we expect; the
    /// 8-byte page headers are tolerated.
    pub usnjrnl_path: PathBuf,

    /// Optional inclusive lower bound on `timestamp`. RFC 3339 / ISO-8601
    /// (e.g. `2026-04-25T00:00:00Z`). Records older than this are dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,

    /// Optional inclusive upper bound on `timestamp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_iso: Option<String>,

    /// Optional filter on `reason` flag names. Records where NONE of the
    /// requested reasons are set are dropped. Recognized names (case-
    /// insensitive): `FILE_CREATE`, `FILE_DELETE`, `RENAME_OLD_NAME`,
    /// `RENAME_NEW_NAME`, `DATA_EXTEND`, `DATA_OVERWRITE`,
    /// `DATA_TRUNCATION`, `EA_CHANGE`, `SECURITY_CHANGE`,
    /// `BASIC_INFO_CHANGE`, `HARD_LINK_CHANGE`, `INDEXABLE_CHANGE`,
    /// `NAMED_DATA_OVERWRITE`, `NAMED_DATA_EXTEND`,
    /// `NAMED_DATA_TRUNCATION`. Unknown names yield an `InvalidReason` error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasons: Option<Vec<String>>,

    /// Hard cap on emitted rows. Default `10_000`. `records_seen`
    /// reports the pre-filter total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UsnJrnlEntry {
    /// USN — the journal sequence number; monotonic within a journal.
    pub usn: i64,

    /// Timestamp of the change as UTC ISO-8601Z.
    pub timestamp_iso: String,

    /// MFT entry number of the file that changed.
    pub mft_entry: u64,

    /// MFT entry number of the parent directory.
    pub parent_mft_entry: u64,

    /// File or directory name (just the leaf — full path resolution
    /// requires correlating against the MFT, which is a separate tool).
    pub filename: String,

    /// Human-readable reason flag names. A single record may set
    /// multiple flags simultaneously (e.g. `FILE_CREATE` + `DATA_EXTEND`).
    pub reason_flags: Vec<String>,

    /// Raw `file_attributes` bitfield from the record (Windows `FILE_ATTRIBUTE`_*).
    pub file_attributes: u32,

    /// USN record version (2 = pre-Win8, 3 = Win8+, 4 = ranges/Win10+).
    pub major_version: u16,
}

#[derive(Clone, Debug, Serialize)]
pub struct UsnJrnlOutput {
    pub entries: Vec<UsnJrnlEntry>,

    /// Per-record parse failures swallowed during the streaming walk.
    pub parse_errors: usize,

    /// Total records the parser saw before any filter.
    pub records_seen: usize,

    /// Length of `entries` after filter + limit.
    pub row_count: usize,
}

#[derive(Debug, Error)]
pub enum UsnJrnlError {
    #[error("UsnJrnl file not found: {0}")]
    UsnJrnlNotFound(PathBuf),

    #[error("UsnJrnl file unreadable {path}: {source}")]
    UsnJrnlUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Boxed because `anyhow::Error` is large and would push our
    /// `Result<_, UsnJrnlError>` over clippy's `result_large_err` limit.
    #[error("UsnJrnl parse failed for {path}: {message}")]
    UsnJrnlOpen { path: PathBuf, message: String },

    #[error("invalid time filter {value:?}: {reason}")]
    InvalidTimeFilter { value: String, reason: String },

    #[error("invalid reason name {0:?}: see schema for the allowed set")]
    InvalidReason(String),
}

/// Cheap pre-flight: file path looks like a USN Journal export.
///
/// Common names: `$J`, `usnjrnl.j`, `<host>.usnjrnl`, `usn.bin`. We
/// match on `$J` literally and on the `.j` / `.usnjrnl` extensions
/// case-insensitively.
#[must_use]
pub fn path_looks_like_usnjrnl(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        if name == "$J" || name.eq_ignore_ascii_case("usnjrnl.j") {
            return true;
        }
    }
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("j") || e.eq_ignore_ascii_case("usnjrnl"))
}

/// Stream the USN Journal at `usnjrnl_path` and emit filtered entries.
///
/// # Errors
/// * [`UsnJrnlError::UsnJrnlNotFound`] — the file does not exist.
/// * [`UsnJrnlError::UsnJrnlUnreadable`] — exists but cannot be opened
///   (permissions / I/O error).
/// * [`UsnJrnlError::UsnJrnlOpen`] — the file is not a valid USN
///   Journal (parser rejected the header).
/// * [`UsnJrnlError::InvalidTimeFilter`] — `since_iso` / `until_iso`
///   is not parseable RFC 3339 / ISO-8601.
/// * [`UsnJrnlError::InvalidReason`] — `reasons[i]` is not in the
///   recognized name set.
pub fn usnjrnl_query(input: &UsnJrnlInput) -> Result<UsnJrnlOutput, UsnJrnlError> {
    let path = &input.usnjrnl_path;
    if !path.is_file() {
        return Err(UsnJrnlError::UsnJrnlNotFound(path.clone()));
    }

    let since = parse_optional_iso(input.since_iso.as_deref())?;
    let until = parse_optional_iso(input.until_iso.as_deref())?;
    let reason_filter = parse_reasons(input.reasons.as_deref())?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let file = File::open(path).map_err(|err| UsnJrnlError::UsnJrnlUnreadable {
        path: path.clone(),
        source: err,
    })?;
    let reader = BufReader::new(file);
    let journal = UsnJournalReader::new(reader).map_err(|err| UsnJrnlError::UsnJrnlOpen {
        path: path.clone(),
        message: err.to_string(),
    })?;

    let mut entries = Vec::new();
    let mut parse_errors: usize = 0;
    let mut records_seen: usize = 0;

    for record_result in journal {
        records_seen += 1;
        let Ok(record) = record_result else {
            parse_errors += 1;
            continue;
        };

        if let Some(lo) = since {
            if record.timestamp < lo {
                continue;
            }
        }
        if let Some(hi) = until {
            if record.timestamp > hi {
                continue;
            }
        }
        if let Some(filter) = reason_filter {
            if (record.reason & filter).is_empty() {
                continue;
            }
        }

        entries.push(UsnJrnlEntry {
            usn: record.usn,
            timestamp_iso: record.timestamp.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            mft_entry: record.mft_entry,
            parent_mft_entry: record.parent_mft_entry,
            filename: record.filename,
            reason_flags: reason_flag_names(record.reason),
            file_attributes: record.file_attributes.bits(),
            major_version: record.major_version,
        });

        if entries.len() >= limit {
            break;
        }
    }

    let row_count = entries.len();
    Ok(UsnJrnlOutput {
        entries,
        parse_errors,
        records_seen,
        row_count,
    })
}

fn parse_optional_iso(value: Option<&str>) -> Result<Option<DateTime<Utc>>, UsnJrnlError> {
    value.map_or(Ok(None), |s| {
        DateTime::parse_from_rfc3339(s)
            .map(|dt| Some(dt.with_timezone(&Utc)))
            .map_err(|err| UsnJrnlError::InvalidTimeFilter {
                value: s.to_string(),
                reason: err.to_string(),
            })
    })
}

fn parse_reasons(names: Option<&[String]>) -> Result<Option<UsnReason>, UsnJrnlError> {
    let Some(names) = names else {
        return Ok(None);
    };
    let mut filter = UsnReason::empty();
    for name in names {
        let bit = match name.to_ascii_uppercase().as_str() {
            "DATA_OVERWRITE" => UsnReason::DATA_OVERWRITE,
            "DATA_EXTEND" => UsnReason::DATA_EXTEND,
            "DATA_TRUNCATION" => UsnReason::DATA_TRUNCATION,
            "NAMED_DATA_OVERWRITE" => UsnReason::NAMED_DATA_OVERWRITE,
            "NAMED_DATA_EXTEND" => UsnReason::NAMED_DATA_EXTEND,
            "NAMED_DATA_TRUNCATION" => UsnReason::NAMED_DATA_TRUNCATION,
            "FILE_CREATE" => UsnReason::FILE_CREATE,
            "FILE_DELETE" => UsnReason::FILE_DELETE,
            "EA_CHANGE" => UsnReason::EA_CHANGE,
            "SECURITY_CHANGE" => UsnReason::SECURITY_CHANGE,
            "RENAME_OLD_NAME" => UsnReason::RENAME_OLD_NAME,
            "RENAME_NEW_NAME" => UsnReason::RENAME_NEW_NAME,
            "INDEXABLE_CHANGE" => UsnReason::INDEXABLE_CHANGE,
            "BASIC_INFO_CHANGE" => UsnReason::BASIC_INFO_CHANGE,
            "HARD_LINK_CHANGE" => UsnReason::HARD_LINK_CHANGE,
            _ => return Err(UsnJrnlError::InvalidReason(name.clone())),
        };
        filter |= bit;
    }
    Ok(Some(filter))
}

fn reason_flag_names(reason: UsnReason) -> Vec<String> {
    let mut out = Vec::new();
    let pairs: &[(UsnReason, &str)] = &[
        (UsnReason::DATA_OVERWRITE, "DATA_OVERWRITE"),
        (UsnReason::DATA_EXTEND, "DATA_EXTEND"),
        (UsnReason::DATA_TRUNCATION, "DATA_TRUNCATION"),
        (UsnReason::NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
        (UsnReason::NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
        (UsnReason::NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
        (UsnReason::FILE_CREATE, "FILE_CREATE"),
        (UsnReason::FILE_DELETE, "FILE_DELETE"),
        (UsnReason::EA_CHANGE, "EA_CHANGE"),
        (UsnReason::SECURITY_CHANGE, "SECURITY_CHANGE"),
        (UsnReason::RENAME_OLD_NAME, "RENAME_OLD_NAME"),
        (UsnReason::RENAME_NEW_NAME, "RENAME_NEW_NAME"),
        (UsnReason::INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
        (UsnReason::BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
        (UsnReason::HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
    ];
    for (bit, name) in pairs {
        if reason.contains(*bit) {
            out.push((*name).to_string());
        }
    }
    out
}
