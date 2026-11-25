//! `sysmon_network_query` — extract Sysmon network connection events from EVTX.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SysmonNetworkInput {
    pub case_id: String,
    pub evtx_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_ids: Option<Vec<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_iso: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_iso: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_contains: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SysmonNetworkRow {
    pub ts: String,
    pub record_id: u64,
    pub event_id: u32,
    pub computer: String,
    pub image: String,
    pub process_id: Option<u32>,
    pub protocol: String,
    pub source_ip: String,
    pub source_port: Option<u16>,
    pub destination_ip: String,
    pub destination_port: Option<u16>,
    pub destination_hostname: String,
    pub user: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SysmonNetworkOutput {
    pub rows: Vec<SysmonNetworkRow>,
    pub row_count: usize,
    pub records_seen: usize,
    pub parse_errors: usize,
}

#[derive(Debug, Error)]
pub enum SysmonNetworkError {
    #[error("sysmon evtx file not found: {0}")]
    EvtxNotFound(PathBuf),
    #[error("sysmon evtx path is not a regular file: {0}")]
    EvtxNotRegular(PathBuf),
    #[error("sysmon evtx parser failed to open {path}: {source}")]
    EvtxOpen {
        path: PathBuf,
        #[source]
        source: Box<evtx::err::EvtxError>,
    },
    #[error("invalid time filter {value:?}: {reason}")]
    InvalidTimeFilter { value: String, reason: String },
}

pub fn sysmon_network_query(
    input: &SysmonNetworkInput,
) -> Result<SysmonNetworkOutput, SysmonNetworkError> {
    if !input.evtx_path.exists() {
        return Err(SysmonNetworkError::EvtxNotFound(input.evtx_path.clone()));
    }
    if !input.evtx_path.is_file() {
        return Err(SysmonNetworkError::EvtxNotRegular(input.evtx_path.clone()));
    }
    let since = parse_filter_time(input.since_iso.as_deref())?;
    let until = parse_filter_time(input.until_iso.as_deref())?;
    let event_ids = input.event_ids.clone().unwrap_or_else(|| vec![3]);
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let image_filter = input.image_contains.as_ref().map(|s| s.to_lowercase());
    let mut parser =
        EvtxParser::from_path(&input.evtx_path).map_err(|source| SysmonNetworkError::EvtxOpen {
            path: input.evtx_path.clone(),
            source: Box::new(source),
        })?;
    let mut rows = Vec::with_capacity(limit.min(1024));
    let mut records_seen = 0usize;
    let mut parse_errors = 0usize;
    for rec in parser.records_json_value() {
        records_seen += 1;
        let Ok(rec) = rec else {
            parse_errors += 1;
            continue;
        };
        let Some(row) = extract_row(&rec.data, rec.event_record_id) else {
            parse_errors += 1;
            continue;
        };
        if !event_ids.contains(&row.event_id) {
            continue;
        }
        if let Some(ts) = parse_row_time(&row.ts) {
            if since.is_some_and(|s| ts < s) || until.is_some_and(|u| ts > u) {
                continue;
            }
        }
        if image_filter
            .as_ref()
            .is_some_and(|needle| !row.image.to_lowercase().contains(needle))
        {
            continue;
        }
        if input
            .destination_ip
            .as_ref()
            .is_some_and(|ip| &row.destination_ip != ip)
        {
            continue;
        }
        if input
            .destination_port
            .is_some_and(|p| row.destination_port != Some(p))
        {
            continue;
        }
        rows.push(row);
        if rows.len() >= limit {
            break;
        }
    }
    Ok(SysmonNetworkOutput {
        row_count: rows.len(),
        rows,
        records_seen,
        parse_errors,
    })
}

fn extract_row(json: &serde_json::Value, record_id: u64) -> Option<SysmonNetworkRow> {
    let system = json.pointer("/Event/System")?;
    let event_id = pick_u32(system.get("EventID")?)?;
    let ts = system
        .pointer("/TimeCreated/#attributes/SystemTime")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let computer = system
        .get("Computer")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let fields = event_data_fields(json.pointer("/Event/EventData"));
    Some(SysmonNetworkRow {
        ts,
        record_id,
        event_id,
        computer,
        image: get_field(&fields, "Image"),
        process_id: get_field(&fields, "ProcessId").parse().ok(),
        protocol: get_field(&fields, "Protocol"),
        source_ip: get_field(&fields, "SourceIp"),
        source_port: get_field(&fields, "SourcePort").parse().ok(),
        destination_ip: get_field(&fields, "DestinationIp"),
        destination_port: get_field(&fields, "DestinationPort").parse().ok(),
        destination_hostname: get_field(&fields, "DestinationHostname"),
        user: get_field(&fields, "User"),
        fields,
    })
}

fn event_data_fields(node: Option<&serde_json::Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(data) = node.and_then(|n| n.get("Data")) else {
        return out;
    };
    match data {
        serde_json::Value::Array(items) => {
            for item in items {
                insert_data_item(&mut out, item);
            }
        }
        other => insert_data_item(&mut out, other),
    }
    out
}

fn insert_data_item(out: &mut BTreeMap<String, String>, item: &serde_json::Value) {
    let Some(name) = item
        .pointer("/#attributes/Name")
        .and_then(serde_json::Value::as_str)
    else {
        return;
    };
    let value = item
        .get("#text")
        .and_then(serde_json::Value::as_str)
        .or_else(|| item.as_str())
        .unwrap_or_default();
    out.insert(name.to_string(), value.to_string());
}

fn get_field(fields: &BTreeMap<String, String>, key: &str) -> String {
    fields.get(key).cloned().unwrap_or_default()
}

fn pick_u32(node: &serde_json::Value) -> Option<u32> {
    node.as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .or_else(|| node.as_str()?.parse().ok())
        .or_else(|| node.get("#text").and_then(pick_u32))
}

fn parse_filter_time(value: Option<&str>) -> Result<Option<DateTime<Utc>>, SysmonNetworkError> {
    let Some(value) = value else {
        return Ok(None);
    };
    DateTime::parse_from_rfc3339(value)
        .map(|dt| Some(dt.with_timezone(&Utc)))
        .map_err(|err| SysmonNetworkError::InvalidTimeFilter {
            value: value.to_string(),
            reason: err.to_string(),
        })
}

fn parse_row_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[must_use]
pub fn path_looks_like_sysmon_evtx(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("evtx"))
        && p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.to_lowercase().contains("sysmon"))
}
