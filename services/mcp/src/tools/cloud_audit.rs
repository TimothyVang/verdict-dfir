//! `cloud_audit` — one allow-listed cloud/identity audit-log verb.
//!
//! The attacker center of gravity has shifted to identity and control-plane
//! abuse (rogue IAM, OAuth consent grants, MFA fatigue, inbox-rule exfil, console
//! takeover), and no SIFT binary parses cloud logs. They are flat JSON / JSONL /
//! JSON-in-CSV / space-delimited text — parser-cheap but genuinely new code.
//!
//! `cloud_audit` normalizes them through ONE verb: the agent names a provider
//! from an **allow-list** and a log path, and gets back typed [`CloudEvent`] rows
//! with a common envelope (timestamp, actor, source IP, action, resource,
//! outcome) plus the raw record. This is pure Rust — no subprocess, no external
//! binary — so it has no `BinaryNotFound` path and runs anywhere.
//!
//! The allow-list is the boundary: an unknown provider is rejected before any
//! parsing dispatch.

use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::tools::ez_parse::parse_csv_records;

const DEFAULT_LIMIT: usize = 10_000;

/// Allow-listed cloud/identity providers.
const ALLOWED_PROVIDERS: &[&str] = &[
    "cloudtrail",
    "entra_signin",
    "entra_audit",
    "m365_ual",
    "gcp_audit",
    "workspace",
    "k8s_audit",
    "vpc_flow",
];

/// True if `provider` is on the allow-list.
#[must_use]
pub fn is_allowed_provider(provider: &str) -> bool {
    ALLOWED_PROVIDERS.contains(&provider)
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CloudAuditInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,

    /// Which cloud provider's log format to parse. MUST be one of: `cloudtrail`,
    /// `entra_signin`, `entra_audit`, `m365_ual`, `gcp_audit`, `workspace`,
    /// `k8s_audit`, `vpc_flow`. Any other value is rejected with
    /// `ProviderNotAllowed`.
    pub provider: String,

    /// Path to the log file (JSON, JSONL, JSON-in-CSV, or space-delimited flow).
    pub log_path: PathBuf,

    /// Hard cap on events emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// A normalized cloud/identity event. The common envelope lets the agent reason
/// across providers; `raw` preserves the full original record for detail.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudEvent {
    /// Event time (provider's native timestamp, as a string).
    pub timestamp: Option<String>,
    /// The acting identity (ARN / UPN / principal email / account id).
    pub actor: Option<String>,
    /// Source IP of the call, when present.
    pub source_ip: Option<String>,
    /// The operation (event name / method / verb).
    pub action: Option<String>,
    /// The target resource (service, resource id, object).
    pub resource: Option<String>,
    /// Outcome (error code / result status / flow action).
    pub outcome: Option<String>,
    /// The full original record.
    pub raw: serde_json::Map<String, Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CloudAuditOutput {
    /// The provider that was parsed (echoed for audit correlation).
    pub provider: String,
    /// Normalized events.
    pub events: Vec<CloudEvent>,
    /// Total events parsed before the limit was applied.
    pub events_seen: usize,
}

#[derive(Debug, Error)]
pub enum CloudAuditError {
    #[error("log file not found: {0}")]
    LogNotFound(PathBuf),

    #[error(
        "provider {0:?} is not on the cloud_audit allow-list; use one of: cloudtrail, \
         entra_signin, entra_audit, m365_ual, gcp_audit, workspace, k8s_audit, vpc_flow"
    )]
    ProviderNotAllowed(String),

    #[error("could not read log: {0}")]
    ReadFailed(String),

    #[error("could not parse {provider} log: {detail}")]
    ParseFailed { provider: String, detail: String },
}

/// Parse an allow-listed cloud/identity audit log into normalized events.
///
/// # Errors
/// * [`CloudAuditError::ProviderNotAllowed`] — `provider` not allow-listed.
/// * [`CloudAuditError::LogNotFound`] — `log_path` missing.
/// * [`CloudAuditError::ReadFailed`] — the file could not be read.
/// * [`CloudAuditError::ParseFailed`] — the content was not the expected format.
pub fn cloud_audit(input: &CloudAuditInput) -> Result<CloudAuditOutput, CloudAuditError> {
    if !is_allowed_provider(&input.provider) {
        return Err(CloudAuditError::ProviderNotAllowed(input.provider.clone()));
    }
    if !input.log_path.exists() {
        return Err(CloudAuditError::LogNotFound(input.log_path.clone()));
    }
    let content = std::fs::read_to_string(&input.log_path)
        .map_err(|e| CloudAuditError::ReadFailed(format!("{}: {e}", input.log_path.display())))?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    parse_provider(&input.provider, &content, limit)
}

/// Dispatch to the per-provider record loader, then map each record to the
/// common envelope. Pure + unit-tested so the whole verb is testable offline.
pub(crate) fn parse_provider(
    provider: &str,
    content: &str,
    limit: usize,
) -> Result<CloudAuditOutput, CloudAuditError> {
    let records: Vec<serde_json::Map<String, Value>> = if provider == "vpc_flow" {
        parse_vpc_flow(content)
    } else if provider == "m365_ual" {
        load_m365_records(content).map_err(|detail| CloudAuditError::ParseFailed {
            provider: provider.to_string(),
            detail,
        })?
    } else {
        load_json_records(content).map_err(|detail| CloudAuditError::ParseFailed {
            provider: provider.to_string(),
            detail,
        })?
    };

    let events_seen = records.len();
    let events: Vec<CloudEvent> = records
        .into_iter()
        .take(limit)
        .map(|r| to_cloud_event(provider, r))
        .collect();

    Ok(CloudAuditOutput {
        provider: provider.to_string(),
        events,
        events_seen,
    })
}

/// Load JSON records from any of the shapes cloud logs ship in: a top-level
/// array, `{"Records":[...]}` (`CloudTrail`), `{"value":[...]}` (Graph), or JSONL
/// (one object per line — GCP/k8s/M365 `AuditData`).
fn load_json_records(content: &str) -> Result<Vec<serde_json::Map<String, Value>>, String> {
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    // Try a single JSON document first.
    if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
        return Ok(values_from_container(value));
    }
    // Fall back to JSONL: one JSON object per non-empty line.
    let mut out = Vec::new();
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(map)) => out.push(map),
            Ok(_) => {}
            Err(e) => return Err(format!("JSONL line parse: {e}")),
        }
    }
    Ok(out)
}

/// M365 UAL exports commonly arrive as CSV where the `AuditData` column is a
/// JSON object. Accept plain JSON/JSONL first, then lift each CSV `AuditData`
/// object into the same record shape as the other providers.
fn load_m365_records(content: &str) -> Result<Vec<serde_json::Map<String, Value>>, String> {
    if let Ok(records) = load_json_records(content) {
        return Ok(records);
    }

    let records = parse_csv_records(content);
    let mut iter = records.into_iter();
    let Some(header) = iter.next() else {
        return Ok(Vec::new());
    };
    let Some(audit_data_idx) = header
        .iter()
        .position(|name| name.eq_ignore_ascii_case("AuditData"))
    else {
        return Err("JSON/JSONL parse failed and CSV has no AuditData column".to_string());
    };

    let mut out = Vec::new();
    for (row_idx, row) in iter.enumerate() {
        let Some(raw_audit_data) = row.get(audit_data_idx).map(String::as_str) else {
            continue;
        };
        if raw_audit_data.trim().is_empty() {
            continue;
        }
        let value = serde_json::from_str::<Value>(raw_audit_data)
            .map_err(|e| format!("AuditData row {} parse: {e}", row_idx + 2))?;
        let Some(mut map) = as_object(value) else {
            continue;
        };

        // Preserve non-AuditData CSV columns as provenance when the JSON body
        // does not already carry an equivalent key.
        for (col_idx, name) in header.iter().enumerate() {
            if col_idx == audit_data_idx || name.is_empty() || map.contains_key(name) {
                continue;
            }
            if let Some(value) = row.get(col_idx) {
                map.insert(name.clone(), Value::String(value.clone()));
            }
        }
        out.push(map);
    }
    Ok(out)
}

/// Extract the record array from a parsed JSON document.
fn values_from_container(value: Value) -> Vec<serde_json::Map<String, Value>> {
    match value {
        Value::Array(arr) => arr.into_iter().filter_map(as_object).collect(),
        Value::Object(map) => {
            for key in ["Records", "value", "items", "events"] {
                if let Some(Value::Array(arr)) = map.get(key) {
                    return arr.iter().filter_map(|v| as_object(v.clone())).collect();
                }
            }
            // A single object is one record.
            vec![map]
        }
        _ => Vec::new(),
    }
}

fn as_object(v: Value) -> Option<serde_json::Map<String, Value>> {
    match v {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// Parse AWS VPC flow logs: space-delimited, default v2 field order. The header
/// line (`version account-id ...`) is detected and skipped.
fn parse_vpc_flow(content: &str) -> Vec<serde_json::Map<String, Value>> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("version ") {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 14 {
            continue;
        }
        let mut map = serde_json::Map::new();
        // Default v2 field order.
        let names = [
            "version",
            "account_id",
            "interface_id",
            "srcaddr",
            "dstaddr",
            "srcport",
            "dstport",
            "protocol",
            "packets",
            "bytes",
            "start",
            "end",
            "action",
            "log_status",
        ];
        for (i, name) in names.iter().enumerate() {
            map.insert((*name).to_string(), Value::String(f[i].to_string()));
        }
        out.push(map);
    }
    out
}

/// Traverse a dotted object path (`a.b.c`) and return the leaf value.
fn get_path<'a>(record: &'a serde_json::Map<String, Value>, path: &str) -> Option<&'a Value> {
    let mut parts = path.split('.');
    let first = parts.next()?;
    let mut cur = record.get(first)?;
    for p in parts {
        cur = if let Ok(idx) = p.parse::<usize>() {
            cur.as_array()?.get(idx)?
        } else {
            cur.as_object()?.get(p)?
        };
    }
    Some(cur)
}

/// First non-empty string from a list of candidate dotted paths.
fn pick(record: &serde_json::Map<String, Value>, paths: &[&str]) -> Option<String> {
    for path in paths {
        if let Some(v) = get_path(record, path) {
            if let Some(s) = v.as_str() {
                if !s.is_empty() {
                    return Some(s.to_string());
                }
            } else if v.is_number() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// The six normalized envelope fields a provider mapper produces.
type Envelope = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// Per-provider mapping into the six [`Envelope`] fields. Split out of
/// `to_cloud_event` to keep each function bounded.
fn map_provider_fields(provider: &str, record: &serde_json::Map<String, Value>) -> Envelope {
    match provider {
        "cloudtrail" => (
            pick(record, &["eventTime"]),
            pick(
                record,
                &[
                    "userIdentity.arn",
                    "userIdentity.userName",
                    "userIdentity.principalId",
                ],
            ),
            pick(record, &["sourceIPAddress"]),
            pick(record, &["eventName"]),
            pick(record, &["eventSource"]),
            pick(record, &["errorCode", "errorMessage"]),
        ),
        "entra_signin" => (
            pick(record, &["createdDateTime"]),
            pick(record, &["userPrincipalName", "userDisplayName"]),
            pick(record, &["ipAddress"]),
            pick(record, &["appDisplayName", "clientAppUsed"]),
            pick(record, &["resourceDisplayName"]),
            pick(record, &["status.errorCode", "status.failureReason"]),
        ),
        "entra_audit" => (
            pick(record, &["activityDateTime"]),
            pick(
                record,
                &[
                    "initiatedBy.user.userPrincipalName",
                    "initiatedBy.app.displayName",
                ],
            ),
            pick(record, &["initiatedBy.user.ipAddress"]),
            pick(record, &["activityDisplayName"]),
            pick(record, &["targetResources.0.displayName", "category"]),
            pick(record, &["result"]),
        ),
        "m365_ual" => (
            pick(record, &["CreationTime", "CreationDate"]),
            pick(record, &["UserId", "UserKey"]),
            pick(record, &["ClientIP", "ClientIPAddress", "ActorIpAddress"]),
            pick(record, &["Operation"]),
            pick(record, &["Workload", "ObjectId"]),
            pick(record, &["ResultStatus"]),
        ),
        "gcp_audit" | "workspace" => (
            pick(record, &["timestamp"]),
            pick(
                record,
                &[
                    "protoPayload.authenticationInfo.principalEmail",
                    "actor.email",
                ],
            ),
            pick(record, &["protoPayload.requestMetadata.callerIp"]),
            pick(record, &["protoPayload.methodName", "events.name"]),
            pick(
                record,
                &[
                    "resource.type",
                    "protoPayload.resourceName",
                    "id.applicationName",
                ],
            ),
            pick(record, &["severity"]),
        ),
        "k8s_audit" => (
            pick(record, &["requestReceivedTimestamp", "stageTimestamp"]),
            pick(record, &["user.username"]),
            None, // sourceIPs is an array — handled below.
            pick(record, &["verb"]),
            pick(record, &["objectRef.resource", "requestURI"]),
            pick(record, &["responseStatus.code", "responseStatus.reason"]),
        ),
        "vpc_flow" => (
            pick(record, &["start"]),
            pick(record, &["account_id"]),
            pick(record, &["srcaddr"]),
            pick(record, &["action"]),
            pick(record, &["dstaddr"]),
            pick(record, &["log_status"]),
        ),
        _ => (None, None, None, None, None, None),
    }
}

/// Map one provider record into the common envelope.
fn to_cloud_event(provider: &str, record: serde_json::Map<String, Value>) -> CloudEvent {
    let (timestamp, actor, mut source_ip, action, resource, outcome) =
        map_provider_fields(provider, &record);

    // k8s sourceIPs is an array of strings; take the first.
    if source_ip.is_none() {
        source_ip = record
            .get("sourceIPs")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(ToString::to_string);
    }

    CloudEvent {
        timestamp,
        actor,
        source_ip,
        action,
        resource,
        outcome,
        raw: record,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first(out: &CloudAuditOutput) -> &CloudEvent {
        &out.events[0]
    }

    #[test]
    fn allow_list_accepts_providers_and_rejects_injection() {
        assert!(is_allowed_provider("cloudtrail"));
        assert!(is_allowed_provider("k8s_audit"));
        assert!(!is_allowed_provider("aws"));
        assert!(!is_allowed_provider("cloudtrail; rm -rf /"));
    }

    #[test]
    fn cloud_audit_rejects_off_list_provider_before_any_io() {
        let input = CloudAuditInput {
            case_id: "c".into(),
            provider: "cloudtrail && curl evil".into(),
            log_path: PathBuf::from("/nonexistent/ct.json"),
            limit: None,
        };
        match cloud_audit(&input) {
            Err(CloudAuditError::ProviderNotAllowed(p)) => {
                assert_eq!(p, "cloudtrail && curl evil");
            }
            other => panic!("expected ProviderNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn cloudtrail_records_container_maps_identity_and_action() {
        let body = r#"{"Records":[
          {"eventTime":"2026-06-13T01:00:00Z","eventName":"ConsoleLogin",
           "eventSource":"signin.amazonaws.com","sourceIPAddress":"10.0.0.9",
           "userIdentity":{"arn":"arn:aws:iam::1:user/evil"},"errorCode":"Failure"}
        ]}"#;
        let out = parse_provider("cloudtrail", body, 100).unwrap();
        assert_eq!(out.events_seen, 1);
        let e = first(&out);
        assert_eq!(e.actor.as_deref(), Some("arn:aws:iam::1:user/evil"));
        assert_eq!(e.action.as_deref(), Some("ConsoleLogin"));
        assert_eq!(e.source_ip.as_deref(), Some("10.0.0.9"));
        assert_eq!(e.outcome.as_deref(), Some("Failure"));
    }

    #[test]
    fn entra_signin_value_container_maps_upn_and_ip() {
        let body = r#"{"value":[
          {"createdDateTime":"2026-06-13T02:00:00Z","userPrincipalName":"a@b.com",
           "ipAddress":"1.2.3.4","appDisplayName":"Azure Portal",
           "status":{"errorCode":50126}}
        ]}"#;
        let out = parse_provider("entra_signin", body, 100).unwrap();
        let e = first(&out);
        assert_eq!(e.actor.as_deref(), Some("a@b.com"));
        assert_eq!(e.source_ip.as_deref(), Some("1.2.3.4"));
        assert_eq!(e.action.as_deref(), Some("Azure Portal"));
        assert_eq!(
            e.outcome.as_deref(),
            Some("50126"),
            "numeric code stringified"
        );
    }

    #[test]
    fn entra_audit_maps_first_target_resource_from_array_path() {
        let body = r#"{"value":[
          {"activityDateTime":"2026-06-13T02:05:00Z",
           "initiatedBy":{"user":{"userPrincipalName":"admin@contoso.com","ipAddress":"5.6.7.8"}},
           "activityDisplayName":"Add member to role",
           "targetResources":[{"displayName":"Global Administrator"}],
           "result":"success"}
        ]}"#;
        let out = parse_provider("entra_audit", body, 100).unwrap();
        let e = first(&out);
        assert_eq!(e.actor.as_deref(), Some("admin@contoso.com"));
        assert_eq!(e.source_ip.as_deref(), Some("5.6.7.8"));
        assert_eq!(e.action.as_deref(), Some("Add member to role"));
        assert_eq!(e.resource.as_deref(), Some("Global Administrator"));
        assert_eq!(e.outcome.as_deref(), Some("success"));
    }

    #[test]
    fn m365_ual_csv_lifts_auditdata_json_column() {
        let body = "RecordType,CreationDate,AuditData\n\
                    1,2026-06-13T03:00:00Z,\"{\"\"CreationTime\"\":\"\"2026-06-13T03:00:00Z\"\",\"\"UserId\"\":\"\"analyst@contoso.com\"\",\"\"ClientIP\"\":\"\"203.0.113.9\"\",\"\"Operation\"\":\"\"Set-Mailbox\"\",\"\"Workload\"\":\"\"Exchange\"\",\"\"ResultStatus\"\":\"\"Succeeded\"\"}\"\n";
        let out = parse_provider("m365_ual", body, 100).unwrap();
        assert_eq!(out.events_seen, 1);
        let e = first(&out);
        assert_eq!(e.timestamp.as_deref(), Some("2026-06-13T03:00:00Z"));
        assert_eq!(e.actor.as_deref(), Some("analyst@contoso.com"));
        assert_eq!(e.source_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(e.action.as_deref(), Some("Set-Mailbox"));
        assert_eq!(e.resource.as_deref(), Some("Exchange"));
        assert_eq!(e.outcome.as_deref(), Some("Succeeded"));
        assert_eq!(e.raw.get("RecordType").and_then(Value::as_str), Some("1"));
    }

    #[test]
    fn k8s_jsonl_takes_first_source_ip_from_array() {
        let body = "{\"requestReceivedTimestamp\":\"2026-06-13T03:00:00Z\",\
                     \"user\":{\"username\":\"system:anonymous\"},\
                     \"sourceIPs\":[\"172.16.0.5\",\"10.0.0.1\"],\"verb\":\"create\",\
                     \"objectRef\":{\"resource\":\"pods\"},\
                     \"responseStatus\":{\"code\":201}}\n";
        let out = parse_provider("k8s_audit", body, 100).unwrap();
        let e = first(&out);
        assert_eq!(e.actor.as_deref(), Some("system:anonymous"));
        assert_eq!(e.source_ip.as_deref(), Some("172.16.0.5"));
        assert_eq!(e.action.as_deref(), Some("create"));
        assert_eq!(e.resource.as_deref(), Some("pods"));
    }

    #[test]
    fn gcp_jsonl_maps_principal_and_method() {
        let body = "{\"timestamp\":\"2026-06-13T04:00:00Z\",\"protoPayload\":\
                     {\"authenticationInfo\":{\"principalEmail\":\"svc@proj.iam\"},\
                     \"requestMetadata\":{\"callerIp\":\"8.8.8.8\"},\
                     \"methodName\":\"storage.objects.get\"}}\n";
        let out = parse_provider("gcp_audit", body, 100).unwrap();
        let e = first(&out);
        assert_eq!(e.actor.as_deref(), Some("svc@proj.iam"));
        assert_eq!(e.source_ip.as_deref(), Some("8.8.8.8"));
        assert_eq!(e.action.as_deref(), Some("storage.objects.get"));
    }

    #[test]
    fn vpc_flow_parses_space_delimited_and_skips_header() {
        let body = "version account-id interface-id srcaddr dstaddr srcport dstport \
                    protocol packets bytes start end action log-status\n\
                    2 123456789 eni-1 10.0.0.5 93.184.216.34 4444 443 6 20 4000 \
                    1700000000 1700000060 REJECT OK\n";
        let out = parse_provider("vpc_flow", body, 100).unwrap();
        assert_eq!(out.events_seen, 1, "header line skipped");
        let e = first(&out);
        assert_eq!(e.source_ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(e.resource.as_deref(), Some("93.184.216.34"));
        assert_eq!(e.outcome.as_deref(), Some("OK"));
        assert_eq!(e.action.as_deref(), Some("REJECT"));
    }

    #[test]
    fn parse_provider_respects_limit() {
        let body = r#"[{"eventName":"A"},{"eventName":"B"},{"eventName":"C"}]"#;
        let out = parse_provider("cloudtrail", body, 2).unwrap();
        assert_eq!(out.events_seen, 3);
        assert_eq!(out.events.len(), 2);
    }
}
