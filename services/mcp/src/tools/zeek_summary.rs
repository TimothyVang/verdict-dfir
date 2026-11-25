//! `zeek_summary` — summarize Zeek TSV logs without linking Zeek libraries.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 100_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ZeekSummaryInput {
    pub case_id: String,
    pub zeek_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZeekCount {
    pub value: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZeekConnection {
    pub ts: String,
    pub src: String,
    pub dst: String,
    pub dst_port: String,
    pub proto: String,
    pub service: String,
    pub orig_bytes: String,
    pub resp_bytes: String,
    pub conn_state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZeekSummaryOutput {
    pub log_files: usize,
    pub rows_seen: usize,
    pub parse_errors: usize,
    pub conn_count: usize,
    pub dns_count: usize,
    pub http_count: usize,
    pub tls_count: usize,
    pub top_hosts: Vec<ZeekCount>,
    pub top_dns_queries: Vec<ZeekCount>,
    pub top_http_hosts: Vec<ZeekCount>,
    pub notable_connections: Vec<ZeekConnection>,
}

#[derive(Debug, Error)]
pub enum ZeekSummaryError {
    #[error("zeek path not found: {0}")]
    NotFound(PathBuf),
    #[error("zeek path unreadable {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn zeek_summary(input: &ZeekSummaryInput) -> Result<ZeekSummaryOutput, ZeekSummaryError> {
    if !input.zeek_path.exists() {
        return Err(ZeekSummaryError::NotFound(input.zeek_path.clone()));
    }
    let mut files = Vec::new();
    if input.zeek_path.is_file() {
        files.push(input.zeek_path.clone());
    } else {
        collect_logs(&input.zeek_path, &mut files).map_err(|source| {
            ZeekSummaryError::Unreadable {
                path: input.zeek_path.clone(),
                source,
            }
        })?;
    }
    let mut out = ZeekSummaryOutput {
        log_files: files.len(),
        rows_seen: 0,
        parse_errors: 0,
        conn_count: 0,
        dns_count: 0,
        http_count: 0,
        tls_count: 0,
        top_hosts: Vec::new(),
        top_dns_queries: Vec::new(),
        top_http_hosts: Vec::new(),
        notable_connections: Vec::new(),
    };
    let mut hosts: HashMap<String, usize> = HashMap::new();
    let mut dns: HashMap<String, usize> = HashMap::new();
    let mut http: HashMap<String, usize> = HashMap::new();
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    for file in files {
        if out.rows_seen >= limit {
            break;
        }
        parse_log_file(&file, limit, &mut out, &mut hosts, &mut dns, &mut http)?;
    }
    out.top_hosts = top_counts(&hosts, 10);
    out.top_dns_queries = top_counts(&dns, 10);
    out.top_http_hosts = top_counts(&http, 10);
    Ok(out)
}

fn collect_logs(dir: &Path, files: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_logs(&path, files)?;
        } else if path_looks_like_zeek_log(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn parse_log_file(
    path: &Path,
    limit: usize,
    out: &mut ZeekSummaryOutput,
    hosts: &mut HashMap<String, usize>,
    dns: &mut HashMap<String, usize>,
    http: &mut HashMap<String, usize>,
) -> Result<(), ZeekSummaryError> {
    let text = std::fs::read_to_string(path).map_err(|source| ZeekSummaryError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_lowercase();
    let mut fields: Vec<String> = Vec::new();
    for line in text.lines() {
        if out.rows_seen >= limit {
            break;
        }
        if let Some(rest) = line.strip_prefix("#fields") {
            fields = rest
                .split('\t')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        if fields.is_empty() {
            out.parse_errors += 1;
            continue;
        }
        let vals: Vec<&str> = line.split('\t').collect();
        if vals.len() < fields.len() {
            out.parse_errors += 1;
            continue;
        }
        out.rows_seen += 1;
        let row: BTreeMap<&str, &str> = fields
            .iter()
            .map(String::as_str)
            .zip(vals.iter().copied())
            .collect();
        if name == "conn.log" || name.ends_with("/conn.log") {
            handle_conn(&row, out, hosts);
        } else if name == "dns.log" {
            out.dns_count += 1;
            bump(dns, row.get("query").copied().unwrap_or(""));
        } else if name == "http.log" {
            out.http_count += 1;
            bump(http, row.get("host").copied().unwrap_or(""));
        } else if name == "ssl.log" || name == "tls.log" {
            out.tls_count += 1;
            bump(hosts, row.get("server_name").copied().unwrap_or(""));
        }
    }
    Ok(())
}

fn handle_conn(
    row: &BTreeMap<&str, &str>,
    out: &mut ZeekSummaryOutput,
    hosts: &mut HashMap<String, usize>,
) {
    out.conn_count += 1;
    let src = row.get("id.orig_h").copied().unwrap_or("");
    let dst = row.get("id.resp_h").copied().unwrap_or("");
    bump(hosts, src);
    bump(hosts, dst);
    if out.notable_connections.len() < 50 {
        out.notable_connections.push(ZeekConnection {
            ts: row.get("ts").copied().unwrap_or("").to_string(),
            src: src.to_string(),
            dst: dst.to_string(),
            dst_port: row.get("id.resp_p").copied().unwrap_or("").to_string(),
            proto: row.get("proto").copied().unwrap_or("").to_string(),
            service: row.get("service").copied().unwrap_or("").to_string(),
            orig_bytes: row.get("orig_bytes").copied().unwrap_or("").to_string(),
            resp_bytes: row.get("resp_bytes").copied().unwrap_or("").to_string(),
            conn_state: row.get("conn_state").copied().unwrap_or("").to_string(),
        });
    }
}

fn bump(map: &mut HashMap<String, usize>, value: &str) {
    if !value.is_empty() && value != "-" {
        *map.entry(value.to_string()).or_insert(0) += 1;
    }
}

fn top_counts(map: &HashMap<String, usize>, limit: usize) -> Vec<ZeekCount> {
    let mut rows: Vec<ZeekCount> = map
        .iter()
        .map(|(value, count)| ZeekCount {
            value: value.clone(),
            count: *count,
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.value.cmp(&b.value)));
    rows.truncate(limit);
    rows
}

#[must_use]
pub fn path_looks_like_zeek_log(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("log"))
}
