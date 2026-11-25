//! `evtx_query` — parse Windows Event Log files in-process.
//!
//! Spec #2 §6. Uses `omerbenamram/evtx = "=0.11.2"` (MIT/Apache-2.0,
//! linked directly per Spec #2 §16). ~1600× faster than python-evtx.
//!
//! Filters:
//!   * `eids` — when present, only records whose `EventID` is in
//!     this list are returned.
//!   * `xpath` — reserved for a future iteration; today the field
//!     round-trips unused but is accepted so the Python agent can
//!     forward it without a schema migration.
//!   * `limit` — caps the returned row count. Default `10_000`.
//!
//! Row shape matches Spec #2 §6's `EvtxRow` contract:
//!   `{ event_id: u32, ts: ISO8601Z, channel: String,
//!      record_id: u64, data: serde_json::Value }`
//!
//! Errors:
//!   * `EvtxNotFound` / `EvtxUnreadable` for filesystem issues.
//!   * `EvtxParseAllFailed` when *every* record in a file fails to
//!     parse. Per-record parse failures are swallowed + counted in
//!     `EvtxQueryOutput.parse_errors` so a single corrupt record
//!     doesn't abort the whole scan.

use std::path::{Path, PathBuf};

use evtx::EvtxParser;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvtxQueryInput {
    /// Case ID from a prior `case_open` call. Not required at the
    /// Rust layer today (the case dir resolver lives in the Python
    /// agent), but accepted so the agent can trace the call in the
    /// audit log.
    pub case_id: String,

    /// Absolute or relative path to the `.evtx` file to parse.
    pub evtx_path: PathBuf,

    /// Optional `EventID` filter. When present, only matching records
    /// are returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eids: Option<Vec<u32>>,

    /// Optional `XPath` filter. Reserved — not applied today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub xpath: Option<String>,

    /// Optional limit. Defaults to `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvtxRow {
    pub event_id: u32,
    pub ts: String,
    pub channel: String,
    pub record_id: u64,
    pub data: serde_json::Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvtxQueryOutput {
    pub rows: Vec<EvtxRow>,
    /// Count of records the parser dropped due to per-record errors.
    pub parse_errors: usize,
    /// Count of records returned. Equal to `rows.len()`; present
    /// for callers that don't want to recompute.
    pub row_count: usize,
    /// Count of records seen by the parser before filtering. Useful
    /// for sanity checks against external row counts (e.g. wevtutil).
    pub records_seen: usize,
}

#[derive(Debug, Error)]
pub enum EvtxError {
    #[error("evtx file not found: {0}")]
    EvtxNotFound(PathBuf),

    #[error("evtx file unreadable {path}: {source}")]
    EvtxUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    // `evtx::err::EvtxError` is ~144 bytes and blows out the enum's
    // size (clippy::result_large_err). Box it so `Result<_, EvtxError>`
    // stays cheap to move — the error path is rare anyway.
    #[error("evtx parser failed to open {path}: {source}")]
    EvtxOpen {
        path: PathBuf,
        #[source]
        source: Box<evtx::err::EvtxError>,
    },

    #[error("every record in {path} failed to parse ({errors} errors)")]
    EvtxParseAllFailed { path: PathBuf, errors: usize },
}

/// Entry point.
pub fn evtx_query(input: &EvtxQueryInput) -> Result<EvtxQueryOutput, EvtxError> {
    if !input.evtx_path.exists() {
        return Err(EvtxError::EvtxNotFound(input.evtx_path.clone()));
    }
    let meta = std::fs::metadata(&input.evtx_path).map_err(|source| EvtxError::EvtxUnreadable {
        path: input.evtx_path.clone(),
        source,
    })?;
    if !meta.is_file() {
        return Err(EvtxError::EvtxUnreadable {
            path: input.evtx_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file"),
        });
    }

    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let mut rows: Vec<EvtxRow> = Vec::with_capacity(limit.min(4096));
    let mut parse_errors: usize = 0;
    let mut records_seen: usize = 0;

    let mut parser =
        EvtxParser::from_path(&input.evtx_path).map_err(|source| EvtxError::EvtxOpen {
            path: input.evtx_path.clone(),
            source: Box::new(source),
        })?;

    // Stream records. Per-record errors are tolerated; the outer
    // fatal-error path fires only when we get zero rows AND every
    // record errored.
    for rec in parser.records_json_value() {
        records_seen += 1;
        match rec {
            Err(_) => {
                parse_errors += 1;
            }
            Ok(r) => {
                let Some(row) = extract_row(&r.data) else {
                    parse_errors += 1;
                    continue;
                };
                if let Some(eids) = &input.eids {
                    if !eids.contains(&row.event_id) {
                        continue;
                    }
                }
                let row = EvtxRow {
                    record_id: r.event_record_id,
                    ..row
                };
                rows.push(row);
                if rows.len() >= limit {
                    break;
                }
            }
        }
    }

    if records_seen > 0 && rows.is_empty() && parse_errors == records_seen {
        return Err(EvtxError::EvtxParseAllFailed {
            path: input.evtx_path.clone(),
            errors: parse_errors,
        });
    }

    Ok(EvtxQueryOutput {
        row_count: rows.len(),
        rows,
        parse_errors,
        records_seen,
    })
}

/// Best-effort extractor — walks the JSON value evtx produces and
/// pulls the canonical `Event.System.*` fields into an `EvtxRow`.
///
/// When the document shape is unexpected (rare; custom channels
/// sometimes omit required fields), returns None and the record
/// counts as a parse error.
fn extract_row(json: &serde_json::Value) -> Option<EvtxRow> {
    let system = json.pointer("/Event/System")?;

    let event_id = pick_event_id(system)?;
    let ts = system
        .pointer("/TimeCreated/#attributes/SystemTime")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();
    let channel = system
        .pointer("/Channel")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();

    Some(EvtxRow {
        event_id,
        ts,
        channel,
        record_id: 0, // filled by caller from the record-level ID
        data: json.clone(),
    })
}

/// The System/EventID node is sometimes a plain number and sometimes
/// an object `{ "#text": N, "#attributes": {...} }`. Handle both.
fn pick_event_id(system: &serde_json::Value) -> Option<u32> {
    let node = system.get("EventID")?;
    if let Some(n) = node.as_u64() {
        return u32::try_from(n).ok();
    }
    if let Some(s) = node.as_str() {
        return s.parse::<u32>().ok();
    }
    if let Some(obj) = node.as_object() {
        if let Some(t) = obj.get("#text") {
            if let Some(n) = t.as_u64() {
                return u32::try_from(n).ok();
            }
            if let Some(s) = t.as_str() {
                return s.parse::<u32>().ok();
            }
        }
    }
    None
}

/// Pure helper — also exported so the integration-test harness can
/// assert on a file's presence without pulling in evtx internals.
#[must_use]
pub fn path_looks_like_evtx(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
}

// ------------------------------------------------------------------
// Unit tests — pure helpers, zero I/O.
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pick_event_id_from_plain_number() {
        let sys = json!({ "EventID": 4624 });
        assert_eq!(pick_event_id(&sys), Some(4624));
    }

    #[test]
    fn pick_event_id_from_hash_text_object() {
        let sys = json!({
            "EventID": {
                "#text": 4672,
                "#attributes": { "Qualifiers": "0" }
            }
        });
        assert_eq!(pick_event_id(&sys), Some(4672));
    }

    #[test]
    fn pick_event_id_from_string() {
        let sys = json!({ "EventID": "7045" });
        assert_eq!(pick_event_id(&sys), Some(7045));
    }

    #[test]
    fn pick_event_id_missing_returns_none() {
        let sys = json!({ "NotEventID": 1 });
        assert_eq!(pick_event_id(&sys), None);
    }

    #[test]
    fn path_looks_like_evtx_true() {
        assert!(path_looks_like_evtx(Path::new("Security.evtx")));
        assert!(path_looks_like_evtx(Path::new("/var/log/Foo.EVTX")));
    }

    #[test]
    fn path_looks_like_evtx_false() {
        assert!(!path_looks_like_evtx(Path::new("Security.evt")));
        assert!(!path_looks_like_evtx(Path::new("README.md")));
        assert!(!path_looks_like_evtx(Path::new("no-extension")));
    }

    #[test]
    fn extract_row_with_full_system_block() {
        let doc = json!({
            "Event": {
                "System": {
                    "EventID": 4624,
                    "Channel": "Security",
                    "TimeCreated": {
                        "#attributes": { "SystemTime": "2026-04-23T02:11:06.123Z" }
                    }
                },
                "EventData": {}
            }
        });
        let row = extract_row(&doc).unwrap();
        assert_eq!(row.event_id, 4624);
        assert_eq!(row.channel, "Security");
        assert_eq!(row.ts, "2026-04-23T02:11:06.123Z");
    }

    #[test]
    fn extract_row_returns_none_on_missing_system() {
        let doc = json!({ "Event": {} });
        assert!(extract_row(&doc).is_none());
    }
}
