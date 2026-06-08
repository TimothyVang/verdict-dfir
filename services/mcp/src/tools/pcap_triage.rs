//! `pcap_triage` — summarize PCAPs via fixed Zeek/tshark subprocess invocations.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::zeek_summary::{zeek_summary, ZeekCount, ZeekSummaryInput, ZeekSummaryOutput};

// A small cap silently truncates real captures — targeted activity (e.g. an
// anonymous-email POST) often sits tens of thousands of packets in. Keep a bound
// so a pathological pcap can't run unbounded, but high enough to read normal
// captures whole.
const DEFAULT_LIMIT: usize = 500_000;
// Keep the per-request list bounded; dedup is by (src, host, method).
const MAX_HTTP_REQUESTS: usize = 300;
const MAX_URI_LEN: usize = 256;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PcapTriageInput {
    pub case_id: String,
    pub pcap_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analyzer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapConversation {
    pub src: String,
    pub dst: String,
    pub dst_port: String,
    pub proto: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PcapHttpRequest {
    pub src: String,
    pub host: String,
    pub method: String,
    pub uri: String,
    pub has_cookie: bool,
    pub count: usize,
    // Epoch seconds (string, to keep the struct Eq) of the first/last packet for
    // this (src, host, method) — lets the playbook correlate activity in time.
    pub first_ts: String,
    pub last_ts: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PcapTriageOutput {
    pub analyzer: String,
    pub packets_seen: usize,
    pub conversations: Vec<PcapConversation>,
    pub dns_queries: Vec<ZeekCount>,
    pub http_hosts: Vec<ZeekCount>,
    // HTTP requests deduped by (src, host, method) — gives the playbook the
    // source-host -> host linkage and authentication (cookie) signal needed to
    // attribute web activity (which the count-only fields above cannot).
    pub http_requests: Vec<PcapHttpRequest>,
    pub zeek: Option<ZeekSummaryOutput>,
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum PcapTriageError {
    #[error("pcap file not found: {0}")]
    PcapNotFound(PathBuf),
    #[error("pcap path is not a regular file: {0}")]
    PcapNotRegular(PathBuf),
    #[error("invalid analyzer {0:?}; expected auto, tshark, or zeek")]
    InvalidAnalyzer(String),
    #[error(
        "neither tshark nor zeek binary is on PATH (set $TSHARK_BIN or $ZEEK_BIN to override)"
    )]
    BinaryNotFound,
    #[error("{binary} exited {exit_code}: {stderr}")]
    SubprocessFailed {
        binary: String,
        exit_code: i32,
        stderr: String,
    },
    #[error("pcap triage output parse failed: {0}")]
    OutputParse(String),
}

pub fn pcap_triage(input: &PcapTriageInput) -> Result<PcapTriageOutput, PcapTriageError> {
    if !input.pcap_path.exists() {
        return Err(PcapTriageError::PcapNotFound(input.pcap_path.clone()));
    }
    if !input.pcap_path.is_file() {
        return Err(PcapTriageError::PcapNotRegular(input.pcap_path.clone()));
    }
    let analyzer = input.analyzer.as_deref().unwrap_or("auto").to_lowercase();
    match analyzer.as_str() {
        "tshark" => run_tshark(input),
        "zeek" => run_zeek(input),
        "auto" => {
            if resolve_binary("TSHARK_BIN", &["tshark", "tshark.exe"]).is_some() {
                run_tshark(input)
            } else if resolve_binary("ZEEK_BIN", &["zeek", "zeek.exe"]).is_some() {
                run_zeek(input)
            } else {
                Err(PcapTriageError::BinaryNotFound)
            }
        }
        other => Err(PcapTriageError::InvalidAnalyzer(other.to_string())),
    }
}

fn run_tshark(input: &PcapTriageInput) -> Result<PcapTriageOutput, PcapTriageError> {
    let binary = resolve_binary("TSHARK_BIN", &["tshark", "tshark.exe"])
        .ok_or(PcapTriageError::BinaryNotFound)?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT).to_string();
    let proc = Command::new(&binary)
        .arg("-r")
        .arg(&input.pcap_path)
        .arg("-c")
        .arg(&limit)
        .arg("-T")
        .arg("fields")
        .arg("-E")
        .arg("separator=\t")
        .arg("-e")
        .arg("ip.src")
        .arg("-e")
        .arg("ip.dst")
        .arg("-e")
        .arg("tcp.dstport")
        .arg("-e")
        .arg("udp.dstport")
        .arg("-e")
        .arg("_ws.col.Protocol")
        .arg("-e")
        .arg("dns.qry.name")
        .arg("-e")
        .arg("http.host")
        .arg("-e")
        .arg("http.request.method")
        .arg("-e")
        .arg("http.request.uri")
        .arg("-e")
        .arg("http.cookie")
        .arg("-e")
        .arg("frame.time_epoch")
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                PcapTriageError::BinaryNotFound
            } else {
                PcapTriageError::SubprocessFailed {
                    binary: "tshark".to_string(),
                    exit_code: -1,
                    stderr: format!("spawn failed: {err}"),
                }
            }
        })?;
    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);
    let stdout = String::from_utf8_lossy(&proc.stdout);
    // tshark exits non-zero on a truncated final packet ("cut short in the middle
    // of a packet") — common in real captures — but still emits every readable
    // packet first. Only hard-fail when there is genuinely nothing to parse;
    // otherwise triage the packets we did get and keep the warning in stderr_tail.
    if !proc.status.success() && stdout.trim().is_empty() {
        return Err(PcapTriageError::SubprocessFailed {
            binary: "tshark".to_string(),
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }
    parse_tshark(&stdout, stderr_tail)
}

/// Per-(src, host, method) accumulator built while scanning tshark output.
#[derive(Default)]
struct ReqAgg {
    uri: String,
    has_cookie: bool,
    count: usize,
    first_ts: f64,
    last_ts: f64,
}

fn parse_tshark(stdout: &str, stderr_tail: String) -> Result<PcapTriageOutput, PcapTriageError> {
    let mut conv: HashMap<(String, String, String, String), usize> = HashMap::new();
    let mut dns: HashMap<String, usize> = HashMap::new();
    let mut http: HashMap<String, usize> = HashMap::new();
    // (src, host, method) -> (representative uri, any cookie seen, count,
    // first_ts, last_ts). Timestamps are epoch seconds; 0.0 means "unset".
    let mut reqs: HashMap<(String, String, String), ReqAgg> = HashMap::new();
    let mut packets_seen = 0usize;
    for line in stdout.lines() {
        packets_seen += 1;
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 11 {
            return Err(PcapTriageError::OutputParse(
                "tshark emitted fewer fields than requested".to_string(),
            ));
        }
        let port = if cols[2].is_empty() { cols[3] } else { cols[2] };
        if !cols[0].is_empty() || !cols[1].is_empty() {
            *conv
                .entry((
                    cols[0].to_string(),
                    cols[1].to_string(),
                    port.to_string(),
                    cols[4].to_string(),
                ))
                .or_insert(0) += 1;
        }
        bump(&mut dns, cols[5]);
        bump(&mut http, cols[6]);
        // HTTP request row: method (col 7) is set. Record src->host with method,
        // a representative URI, whether a session cookie rode along, and the
        // first/last packet time so the playbook can correlate activity in time.
        if !cols[7].is_empty() {
            let ts: f64 = cols[10].parse().unwrap_or(0.0);
            let entry = reqs
                .entry((
                    cols[0].to_string(),
                    cols[6].to_string(),
                    cols[7].to_string(),
                ))
                .or_default();
            if entry.uri.is_empty() && !cols[8].is_empty() {
                entry.uri = truncate_to(cols[8].to_string(), MAX_URI_LEN);
            }
            entry.has_cookie |= !cols[9].is_empty();
            entry.count += 1;
            if ts > 0.0 {
                if entry.first_ts == 0.0 || ts < entry.first_ts {
                    entry.first_ts = ts;
                }
                if ts > entry.last_ts {
                    entry.last_ts = ts;
                }
            }
        }
    }
    Ok(PcapTriageOutput {
        analyzer: "tshark".to_string(),
        packets_seen,
        conversations: top_conversations(&conv, 50),
        dns_queries: top_counts(&dns, 25),
        http_hosts: top_counts(&http, 25),
        http_requests: top_http_requests(&reqs, MAX_HTTP_REQUESTS),
        zeek: None,
        stderr_tail,
    })
}

fn run_zeek(input: &PcapTriageInput) -> Result<PcapTriageOutput, PcapTriageError> {
    let binary =
        resolve_binary("ZEEK_BIN", &["zeek", "zeek.exe"]).ok_or(PcapTriageError::BinaryNotFound)?;
    let out_dir = std::env::temp_dir().join(format!(
        "findevil-zeek-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    std::fs::create_dir_all(&out_dir)
        .map_err(|err| PcapTriageError::OutputParse(format!("create temp dir: {err}")))?;
    let proc = Command::new(&binary)
        .current_dir(&out_dir)
        .arg("-r")
        .arg(&input.pcap_path)
        .output()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::NotFound {
                PcapTriageError::BinaryNotFound
            } else {
                PcapTriageError::SubprocessFailed {
                    binary: "zeek".to_string(),
                    exit_code: -1,
                    stderr: format!("spawn failed: {err}"),
                }
            }
        })?;
    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);
    if !proc.status.success() {
        let _ = std::fs::remove_dir_all(&out_dir);
        return Err(PcapTriageError::SubprocessFailed {
            binary: "zeek".to_string(),
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }
    let summary = zeek_summary(&ZeekSummaryInput {
        case_id: input.case_id.clone(),
        zeek_path: out_dir.clone(),
        limit: input.limit,
    })
    .map_err(|err| PcapTriageError::OutputParse(err.to_string()))?;
    let _ = std::fs::remove_dir_all(&out_dir);
    Ok(PcapTriageOutput {
        analyzer: "zeek".to_string(),
        packets_seen: summary.rows_seen,
        conversations: summary
            .notable_connections
            .iter()
            .map(|c| PcapConversation {
                src: c.src.clone(),
                dst: c.dst.clone(),
                dst_port: c.dst_port.clone(),
                proto: c.proto.clone(),
                count: 1,
            })
            .collect(),
        dns_queries: summary.top_dns_queries.clone(),
        http_hosts: summary.top_http_hosts.clone(),
        // Per-request src/cookie linkage requires raw packet fields; the zeek
        // summary path doesn't carry them, so leave this empty here.
        http_requests: Vec::new(),
        zeek: Some(summary),
        stderr_tail,
    })
}

fn resolve_binary(env_name: &str, names: &[&str]) -> Option<PathBuf> {
    if let Ok(env_path) = std::env::var(env_name) {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Some(p);
        }
    }
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        for name in names {
            let p = dir.join(name);
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

fn bump(map: &mut HashMap<String, usize>, value: &str) {
    if !value.is_empty() {
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
fn top_conversations(
    map: &HashMap<(String, String, String, String), usize>,
    limit: usize,
) -> Vec<PcapConversation> {
    let mut rows: Vec<PcapConversation> = map
        .iter()
        .map(|((src, dst, dst_port, proto), count)| PcapConversation {
            src: src.clone(),
            dst: dst.clone(),
            dst_port: dst_port.clone(),
            proto: proto.clone(),
            count: *count,
        })
        .collect();
    rows.sort_by(|a, b| b.count.cmp(&a.count));
    rows.truncate(limit);
    rows
}
fn fmt_ts(ts: f64) -> String {
    if ts > 0.0 {
        format!("{ts:.3}")
    } else {
        String::new()
    }
}
fn top_http_requests(
    map: &HashMap<(String, String, String), ReqAgg>,
    limit: usize,
) -> Vec<PcapHttpRequest> {
    let mut rows: Vec<PcapHttpRequest> = map
        .iter()
        .map(|((src, host, method), agg)| PcapHttpRequest {
            src: src.clone(),
            host: host.clone(),
            method: method.clone(),
            uri: agg.uri.clone(),
            has_cookie: agg.has_cookie,
            count: agg.count,
            first_ts: fmt_ts(agg.first_ts),
            last_ts: fmt_ts(agg.last_ts),
        })
        .collect();
    // Surface the most attributable requests first so the cap never drops them:
    // authenticated requests, then POSTs (submissions), then by frequency.
    rows.sort_by(|a, b| {
        b.has_cookie
            .cmp(&a.has_cookie)
            .then_with(|| (b.method == "POST").cmp(&(a.method == "POST")))
            .then_with(|| b.count.cmp(&a.count))
            .then_with(|| a.host.cmp(&b.host))
    });
    rows.truncate(limit);
    rows
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        let start = s.len() - max;
        s = format!("…{}", &s[start..]);
    }
    s
}

#[must_use]
pub fn path_looks_like_pcap(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "pcap" | "pcapng" | "cap"))
}
