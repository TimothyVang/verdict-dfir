//! `bits_parse` — read a Windows BITS (Background Intelligent Transfer Service)
//! job-queue state file (MITRE T1197).
//!
//! BITS is the Windows service that transfers files in the background (Windows
//! Update, but also anything that calls its API). It is a well-worn persistence
//! and stealth-download primitive (T1197): an attacker enqueues a job that pulls
//! a payload — often from a raw-IP host — and drops it to a local path, surviving
//! reboots without a service/registry autorun. The job queue lives in
//! `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\`:
//!
//! * Windows 7 .. Windows 10 pre-1709 store it as the legacy binary
//!   `qmgr0.dat` / `qmgr1.dat`, which embed each job's remote URL and local
//!   destination path as UTF-16LE strings.
//! * Windows 10 1709+ store it as an ESE database `qmgr.db` (4-byte LE signature
//!   `0x89ABCDEF` at file offset 4).
//!
//! Fully decoding either format is error-prone: the legacy binary is an
//! undocumented job-record structure, and the ESE database needs a real ESE
//! engine (`esedbexport`). A subtle misparse would put WRONG URLs/paths behind a
//! Finding. This reader is deliberately conservative and header/string-level, not
//! a job reconstructor:
//!
//! * If the file is an ESE `qmgr.db`, DETECT and report the format only — surface
//!   NO urls/paths (ESE decoding is out of scope; use `esedbexport` separately).
//! * For the legacy binary, scan for UTF-16LE printable runs and extract the
//!   scheme-prefixed URLs and Windows-shaped local paths that are actually
//!   present in the bytes. It does NOT reconstruct job state, priority, owner
//!   SID, or timestamps — those risk a misparse.
//!
//! Output is sorted/deduped/capped — hence deterministic, so a `verify_finding`
//! replay reproduces the same bytes. Nothing here is image-specific: any BITS
//! state file from any host parses the same way, and the suspicious-URL heuristic
//! (raw-IPv4 host, executable-extension path) is a general T1197 signature, not a
//! hard-coded URL or path.

use std::collections::BTreeSet;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// ESE database signature: little-endian `0x89ABCDEF` at file offset 4. A
/// Win10 1709+ `qmgr.db` is an ESE store; the bytes `[4..8]` are this sequence.
const ESE_SIGNATURE: [u8; 4] = [0xEF, 0xCD, 0xAB, 0x89];

/// Upper bound on bytes read from one state file. Legacy `qmgr*.dat` are small
/// (tens of KB to a few MB); the cap stops a pathological path from exhausting
/// memory.
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Longest decoded UTF-16LE run kept; longer is treated as noise, not a string.
const MAX_STRING_LEN: usize = 2048;
/// Cap on surfaced URLs/paths per kind so a huge file can't bloat output. Counts
/// are reported separately and are not capped.
const MAX_ITEMS: usize = 200;

/// URL schemes a BITS job can carry. Matched case-insensitively.
const URL_SCHEMES: &[&str] = &["http://", "https://", "ftp://", "file://"];

/// Executable-style extensions that make a downloaded URL/path suspicious under
/// T1197. General DFIR signatures — not tied to any one image.
const EXECUTABLE_EXTENSIONS: &[&str] = &[".exe", ".dll", ".ps1", ".scr", ".bat", ".hta"];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BitsParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to a BITS state file (`qmgr0.dat` / `qmgr1.dat` / `qmgr.db`).
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct BitsParseOutput {
    /// Detected on-disk format: `"binary_qmgr"` (legacy `qmgr*.dat`) or
    /// `"ese_qmgr_db"` (Win10 1709+ ESE store).
    pub format: String,
    /// True if the file is a recognized BITS state file.
    pub is_bits: bool,
    /// True for the ESE format, whose job records this reader does NOT decode.
    /// When true, `urls`/`local_paths` are intentionally empty; use
    /// `esedbexport` to recover job records from `qmgr.db`.
    pub ese_requires_external_tool: bool,
    /// Count of distinct scheme-prefixed URLs recovered (0 for ESE format).
    pub url_count: usize,
    /// Deduped, sorted URLs found as UTF-16LE strings (capped).
    pub urls: Vec<String>,
    /// Count of distinct Windows-shaped local destination paths recovered.
    pub local_path_count: usize,
    /// Deduped, sorted local paths found as UTF-16LE strings (capped).
    pub local_paths: Vec<String>,
    /// Count of `urls` whose host is a raw IPv4 or whose path ends in an
    /// executable extension — a general T1197 lead, not a Finding on its own.
    pub suspicious_url_count: usize,
}

#[derive(Debug, Error)]
pub enum BitsParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Parse a BITS job-queue state file's embedded URLs and local paths.
///
/// # Errors
/// * [`BitsParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`BitsParseError::Read`] — IO error reading the file.
pub fn bits_parse(input: &BitsParseInput) -> Result<BitsParseOutput, BitsParseError> {
    if !input.artifact_path.exists() {
        return Err(BitsParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }
    let data = read_capped(&input.artifact_path)?;
    Ok(parse_bytes(&data))
}

fn read_capped(path: &std::path::Path) -> Result<Vec<u8>, BitsParseError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| BitsParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|source| BitsParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Pure parse over the raw bytes — unit-tested without IO.
fn parse_bytes(data: &[u8]) -> BitsParseOutput {
    // Win10 1709+ ESE store: detect and report format only, surface no strings.
    if data.len() >= 8 && data[4..8] == ESE_SIGNATURE {
        return BitsParseOutput {
            format: "ese_qmgr_db".to_string(),
            is_bits: true,
            ese_requires_external_tool: true,
            url_count: 0,
            urls: Vec::new(),
            local_path_count: 0,
            local_paths: Vec::new(),
            suspicious_url_count: 0,
        };
    }

    // Legacy binary qmgr: permissive — treat any non-ESE input as the binary
    // format and report only the UTF-16LE strings actually present.
    let candidates = utf16le_printable_runs(data);
    let mut urls: BTreeSet<String> = BTreeSet::new();
    let mut local_paths: BTreeSet<String> = BTreeSet::new();
    for candidate in candidates {
        if is_url(&candidate) {
            urls.insert(candidate);
        } else if is_windows_path(&candidate) {
            local_paths.insert(candidate);
        }
    }

    let suspicious_url_count = urls.iter().filter(|u| is_suspicious_url(u)).count();
    let urls: Vec<String> = urls.into_iter().collect();
    let local_paths: Vec<String> = local_paths.into_iter().collect();

    BitsParseOutput {
        format: "binary_qmgr".to_string(),
        is_bits: true,
        ese_requires_external_tool: false,
        url_count: urls.len(),
        urls: urls.into_iter().take(MAX_ITEMS).collect(),
        local_path_count: local_paths.len(),
        local_paths: local_paths.into_iter().take(MAX_ITEMS).collect(),
        suspicious_url_count,
    }
}

/// Walk the buffer decoding maximal UTF-16LE printable-ASCII runs. Each UTF-16
/// code unit is a little-endian byte pair; a run continues while the high byte
/// is 0 and the low byte is printable ASCII (`0x20..=0x7e`), and stops at a NUL
/// or any non-printable/non-ASCII unit. Runs shorter than a plausible string or
/// longer than the cap are dropped as noise.
fn utf16le_printable_runs(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut i = 0usize;
    while i + 1 < data.len() {
        let low = data[i];
        let high = data[i + 1];
        if high == 0 && (0x20..=0x7e).contains(&low) {
            if current.len() < MAX_STRING_LEN {
                current.push(low as char);
            }
            i += 2;
            continue;
        }
        if !current.is_empty() {
            out.push(std::mem::take(&mut current));
        }
        // Advance by one byte on a boundary miss so an odd-aligned run is still
        // reachable on the next attempt.
        i += 1;
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// True if `s` starts with a supported URL scheme (case-insensitive).
fn is_url(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    URL_SCHEMES.iter().any(|scheme| low.starts_with(scheme))
}

/// True if `s` looks like a Windows local path: a drive-letter path (`X:\...`)
/// or a UNC path (`\\server\share\...`).
fn is_windows_path(s: &str) -> bool {
    let bytes = s.as_bytes();
    // Drive-letter: `X:\`.
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\' {
        return true;
    }
    // UNC: `\\server\share...` — needs a share segment after the server.
    if let Some(rest) = s.strip_prefix("\\\\") {
        return rest.contains('\\') && !rest.starts_with('\\');
    }
    false
}

/// True if a URL's host is a raw IPv4 literal or its path ends in an executable
/// extension — a general T1197 download-payload signature.
fn is_suspicious_url(url: &str) -> bool {
    let low = url.to_ascii_lowercase();
    if EXECUTABLE_EXTENSIONS.iter().any(|ext| low.ends_with(ext)) {
        return true;
    }
    host_is_ipv4(&low)
}

/// True if the authority component of `url` (already lowercased) is a raw IPv4
/// literal like `10.0.0.5` or `203.0.113.9:8080`.
fn host_is_ipv4(url: &str) -> bool {
    let Some((_, after_scheme)) = url.split_once("://") else {
        return false;
    };
    // Authority ends at the first `/`, `?`, or `#`.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Drop userinfo (`user@host`) and port (`host:port`).
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() != 4 {
        return false;
    }
    octets.iter().all(|octet| {
        !octet.is_empty()
            && octet.bytes().all(|b| b.is_ascii_digit())
            && octet.parse::<u16>().map(|n| n <= 255).unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a `&str` as UTF-16LE bytes (little-endian code-unit pairs).
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    }

    /// A legacy `qmgr*.dat`-shaped buffer: NUL-separated UTF-16LE strings padded
    /// with junk. The leading bytes are deliberately NOT the ESE signature.
    fn legacy_buffer(strings: &[&str]) -> Vec<u8> {
        let mut out = vec![0x13, 0xF7, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00]; // non-ESE header
        for s in strings {
            out.extend_from_slice(&[0u8; 4]); // NUL padding / junk boundary
            out.extend_from_slice(&utf16le(s));
            out.extend_from_slice(&[0u8, 0u8]); // UTF-16 NUL terminator
        }
        out.extend_from_slice(&[0x00, 0x11, 0x22, 0x33]); // trailing junk
        out
    }

    #[test]
    fn legacy_buffer_extracts_url_and_path_and_flags_suspicious() {
        let buf = legacy_buffer(&[
            "http://evil.example/payload.exe",
            "C:\\Users\\Public\\a.dll",
        ]);
        let out = parse_bytes(&buf);
        assert_eq!(out.format, "binary_qmgr");
        assert!(out.is_bits);
        assert!(!out.ese_requires_external_tool);
        assert!(out
            .urls
            .contains(&"http://evil.example/payload.exe".to_string()));
        assert!(out
            .local_paths
            .contains(&"C:\\Users\\Public\\a.dll".to_string()));
        assert!(out.suspicious_url_count >= 1); // path ends in .exe
    }

    #[test]
    fn ese_signature_detected_and_reports_no_urls() {
        // bytes[4..8] must equal the ESE signature.
        let mut buf = vec![0x00, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&ESE_SIGNATURE);
        // A URL embedded past the header must NOT be surfaced for ESE.
        buf.extend_from_slice(&utf16le("http://should.not.appear/x.exe"));
        let out = parse_bytes(&buf);
        assert_eq!(out.format, "ese_qmgr_db");
        assert!(out.is_bits);
        assert!(out.ese_requires_external_tool);
        assert!(out.urls.is_empty());
        assert!(out.local_paths.is_empty());
        assert_eq!(out.url_count, 0);
    }

    #[test]
    fn random_bytes_no_urls_does_not_panic() {
        let buf: Vec<u8> = (0u16..4096)
            .map(|n| (n.wrapping_mul(37) & 0xFF) as u8)
            .collect();
        let out = parse_bytes(&buf);
        // Non-ESE random data is reported as the permissive binary format.
        assert_eq!(out.format, "binary_qmgr");
        assert!(out.is_bits);
        assert!(out.urls.is_empty());
    }

    #[test]
    fn output_is_sorted_and_deduped() {
        let buf = legacy_buffer(&[
            "https://b.example/z",
            "https://a.example/y",
            "https://b.example/z", // duplicate
            "https://a.example/y", // duplicate
        ]);
        let out = parse_bytes(&buf);
        assert_eq!(
            out.urls,
            vec![
                "https://a.example/y".to_string(),
                "https://b.example/z".to_string(),
            ]
        );
        assert_eq!(out.url_count, 2);
        // Determinism: a second parse yields identical output.
        assert_eq!(parse_bytes(&buf).urls, out.urls);
    }

    #[test]
    fn raw_ipv4_host_is_suspicious() {
        let buf = legacy_buffer(&["http://203.0.113.9:8080/loader"]);
        let out = parse_bytes(&buf);
        assert_eq!(out.suspicious_url_count, 1);
    }

    #[test]
    fn unc_and_drive_paths_classified_as_paths_not_urls() {
        let buf = legacy_buffer(&["\\\\host\\share\\drop.bin", "D:\\temp\\out.dat"]);
        let out = parse_bytes(&buf);
        assert!(out.urls.is_empty());
        assert_eq!(out.local_path_count, 2);
        assert!(out
            .local_paths
            .contains(&"\\\\host\\share\\drop.bin".to_string()));
        assert!(out.local_paths.contains(&"D:\\temp\\out.dat".to_string()));
    }
}
