//! `vol_malfind` — subprocess wrapper for Volatility 3's `windows.malfind`.
//!
//! Spec #2 §6 + Pool B exfil / general malware territory. `windows.malfind`
//! is THE canonical code-injection detector for Windows memory: it walks
//! every process's VAD tree looking for memory regions that are (a)
//! marked RWX (read-write-execute, the classic injection footprint) and
//! (b) contain an MZ header in unexpected places — both strong indicators
//! that something has been injected into a legitimate process.
//!
//! Pair with `vol_pslist` for memory-context corroboration: pslist tells
//! you WHAT processes exist, malfind tells you WHICH of them contain
//! suspicious memory regions. This is still memory-only evidence; disk,
//! event-log, or network artifacts are needed before making execution or
//! exfiltration claims.
//!
//! Volatility invocation: `<vol> -f <memory> -r json windows.malfind`.
//! Reuses the same binary-discovery helper as `vol_pslist`.

use std::path::PathBuf;
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;
const PREVIEW_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolMalfindInput {
    /// Case ID from a prior `case_open` call.
    pub case_id: String,

    /// Path to the memory image (`.mem`, `.raw`, `.dmp`, `.vmem`, `.img`).
    pub memory_path: PathBuf,

    /// Optional PID filter. When supplied, only injections in
    /// processes whose PID is in this list are returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_filter: Option<Vec<u32>>,

    /// Hard cap on rows emitted. Default `10_000`. malfind is much
    /// chattier than pslist on a compromised host (one process can
    /// have dozens of suspicious VADs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolInjection {
    /// PID of the process containing the suspicious VAD.
    pub pid: u32,

    /// Process image name (e.g. `explorer.exe`).
    pub image_name: String,

    /// VAD start address as a hex string (`0x...`).
    pub vad_start_hex: String,

    /// VAD end address as a hex string.
    pub vad_end_hex: String,

    /// Memory protection flags (e.g. `PAGE_EXECUTE_READWRITE`,
    /// `PAGE_EXECUTE_WRITECOPY`).
    pub protection: String,

    /// True if the start of the VAD contains an MZ header (the
    /// hallmark of an injected PE in a region that shouldn't have one).
    pub mz_match: bool,

    /// First 64 bytes at the VAD start, lowercase hex. Lets the agent
    /// classify the injection (PE header, shellcode, etc.) without
    /// pulling the full dump.
    pub sample_hex: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolMalfindOutput {
    pub injections: Vec<VolInjection>,

    /// Total injections Volatility reported before our filter / limit.
    pub injections_seen: usize,

    /// Stderr tail (capped at 4096 bytes).
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VolMalfindError {
    #[error("memory image not found: {0}")]
    MemoryNotFound(PathBuf),

    #[error("memory image is not a regular file: {0}")]
    MemoryNotRegular(PathBuf),

    #[error(
        "volatility binary not on PATH (set $VOLATILITY_BIN to override). \
         Install: `pip install volatility3` or use the SIFT VM bundle."
    )]
    BinaryNotFound,

    #[error("volatility exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("could not parse volatility JSON output: {0}")]
    OutputParse(String),
}

/// Run Volatility's `windows.malfind` plugin against a memory image.
///
/// # Errors
/// * [`VolMalfindError::MemoryNotFound`] / [`VolMalfindError::MemoryNotRegular`] —
///   filesystem path missing or not a file.
/// * [`VolMalfindError::BinaryNotFound`] — Volatility not on PATH and
///   `$VOLATILITY_BIN` unset.
/// * [`VolMalfindError::SubprocessFailed`] — Volatility returned non-zero;
///   check `stderr_tail`.
/// * [`VolMalfindError::OutputParse`] — JSON output was malformed.
pub fn vol_malfind(input: &VolMalfindInput) -> Result<VolMalfindOutput, VolMalfindError> {
    if !input.memory_path.exists() {
        return Err(VolMalfindError::MemoryNotFound(input.memory_path.clone()));
    }
    if !input.memory_path.is_file() {
        return Err(VolMalfindError::MemoryNotRegular(input.memory_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.arg("-f")
        .arg(&input.memory_path)
        .arg("-r")
        .arg("json")
        .arg("-q")
        .arg("windows.malfind");

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VolMalfindError::BinaryNotFound
        } else {
            VolMalfindError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VolMalfindError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_injections(
        stdout.as_ref(),
        input.pid_filter.as_deref(),
        limit,
        stderr_tail,
    )
}

fn resolve_binary() -> Result<PathBuf, VolMalfindError> {
    // Same logic as vol_pslist::resolve_binary; not extracted to a shared
    // helper because the error type is different (we want each tool's
    // BinaryNotFound message to point at install docs in its own voice).
    if let Ok(env_path) = std::env::var("VOLATILITY_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        let candidates: &[&str] = if cfg!(windows) {
            &["vol.exe", "volatility3.exe", "volatility.exe", "vol.py"]
        } else {
            &["vol", "volatility3", "volatility", "vol.py"]
        };
        for dir in std::env::split_paths(&path_var) {
            for name in candidates {
                let candidate = dir.join(name);
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(VolMalfindError::BinaryNotFound)
}

fn parse_injections(
    stdout: &str,
    pid_filter: Option<&[u32]>,
    limit: usize,
    stderr_tail: String,
) -> Result<VolMalfindOutput, VolMalfindError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VolMalfindOutput {
            injections: Vec::new(),
            injections_seen: 0,
            stderr_tail,
        });
    }
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).map_err(|e| VolMalfindError::OutputParse(e.to_string()))?;

    let injections_seen = raw.len();
    let mut out = Vec::with_capacity(injections_seen.min(limit));
    for value in raw {
        let injection = json_value_to_injection(&value);
        if let Some(filter) = pid_filter {
            if !filter.contains(&injection.pid) {
                continue;
            }
        }
        out.push(injection);
        if out.len() >= limit {
            break;
        }
    }

    Ok(VolMalfindOutput {
        injections: out,
        injections_seen,
        stderr_tail,
    })
}

/// Best-effort projection of one Volatility malfind row into our typed
/// shape. Tolerates the 2-3 most common field-name spellings.
fn json_value_to_injection(v: &serde_json::Value) -> VolInjection {
    let map = v.as_object().cloned().unwrap_or_default();
    let pick_u32 = |keys: &[&str]| -> u32 {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(n) = val.as_u64() {
                    return u32::try_from(n).unwrap_or(0);
                }
                if let Some(s) = val.as_str() {
                    if let Ok(n) = s.parse::<u32>() {
                        return n;
                    }
                }
            }
        }
        0
    };
    let pick_str = |keys: &[&str]| -> String {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(s) = val.as_str() {
                    return s.to_string();
                }
            }
        }
        String::new()
    };
    let pick_bool = |keys: &[&str]| -> bool {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(b) = val.as_bool() {
                    return b;
                }
                if let Some(s) = val.as_str() {
                    return matches!(s, "True" | "true" | "Yes" | "yes" | "1");
                }
            }
        }
        false
    };

    // VAD start/end may come as either hex strings or numeric values.
    // Normalize to lowercase 0x-prefixed hex.
    let vad_start_hex = normalize_hex_field(map.get("Start VPN").or_else(|| map.get("start")));
    let vad_end_hex = normalize_hex_field(map.get("End VPN").or_else(|| map.get("end")));

    // Pull the data preview if present (Volatility emits "Hexdump" or
    // similar for malfind; varies wildly across versions).
    let preview_raw = pick_str(&["Hexdump", "Disasm", "Data", "data"]);
    let sample_hex = if preview_raw.is_empty() {
        String::new()
    } else {
        // Strip whitespace and ASCII noise, keep only hex chars,
        // truncate to PREVIEW_BYTES * 2 chars.
        let cleaned: String = preview_raw
            .chars()
            .filter(char::is_ascii_hexdigit)
            .take(PREVIEW_BYTES * 2)
            .collect::<String>()
            .to_ascii_lowercase();
        cleaned
    };

    // mz_match: prefer the explicit boolean field; fall back to a
    // case-insensitive "MZ" substring check on the free-form Notes field
    // (Volatility 3 emits e.g. "MZ header" / "MZ header detected" there
    // rather than a JSON bool — `pick_bool` would silently return false
    // for any of those strings, masking real injections).
    let mz_from_bool = pick_bool(&["MZ Header", "mz_header"]);
    let mz_from_notes = map
        .get("Notes")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| s.to_ascii_uppercase().contains("MZ"));

    VolInjection {
        pid: pick_u32(&["PID", "pid"]),
        image_name: pick_str(&["Process", "ImageFileName", "image_name"]),
        vad_start_hex,
        vad_end_hex,
        protection: pick_str(&["Protection", "protection"]),
        mz_match: mz_from_bool || mz_from_notes,
        sample_hex,
    }
}

fn normalize_hex_field(value: Option<&serde_json::Value>) -> String {
    match value {
        Some(serde_json::Value::String(s)) => {
            if s.starts_with("0x") || s.starts_with("0X") {
                s.to_lowercase()
            } else {
                format!("0x{}", s.trim_start_matches('+').to_lowercase())
            }
        }
        Some(serde_json::Value::Number(n)) => {
            n.as_u64().map_or_else(String::new, |v| format!("{v:#x}"))
        }
        _ => String::new(),
    }
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        // Walk to the nearest char boundary so multi-byte UTF-8 doesn't
        // panic `String::truncate` (Vol3 stderr can contain Unicode
        // progress markers; from_utf8_lossy can also insert a 3-byte
        // U+FFFD that straddles the boundary).
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("…[truncated]");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mz_match_true_when_notes_contains_mz_substring() {
        // P1 regression: Vol3 emits `Notes: "MZ header"` (free-form
        // string), not a JSON bool. `pick_bool` would silently return
        // false on those strings, masking real PE-injection findings.
        let v = serde_json::json!({
            "PID": 1234,
            "Process": "explorer.exe",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Notes": "MZ header detected",
        });
        let inj = json_value_to_injection(&v);
        assert_eq!(inj.pid, 1234);
        assert!(
            inj.mz_match,
            "MZ in Notes string must surface as mz_match=true"
        );
    }

    #[test]
    fn mz_match_true_when_explicit_boolean_field_set() {
        let v = serde_json::json!({
            "PID": 1234,
            "Process": "lsass.exe",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "MZ Header": true,
        });
        let inj = json_value_to_injection(&v);
        assert!(inj.mz_match);
    }

    #[test]
    fn mz_match_false_when_notes_lacks_mz() {
        let v = serde_json::json!({
            "PID": 1234,
            "Process": "explorer.exe",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Notes": "Suspicious permissions",
        });
        let inj = json_value_to_injection(&v);
        assert!(!inj.mz_match);
    }
}
