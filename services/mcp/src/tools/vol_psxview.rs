//! `vol_psxview` — subprocess wrapper for Volatility 3's `windows.psxview`.
//!
//! `psxview` cross-references several process-enumeration methods. It is the
//! natural follow-up when `vol_pslist` and `vol_psscan` diverge, because it
//! shows which process views can see each recovered process object.

use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolPsxviewInput {
    /// Case ID from a prior `case_open` call.
    pub case_id: String,

    /// Path to the memory image (`.mem`, `.raw`, `.dmp`, `.vmem`, `.img`).
    pub memory_path: PathBuf,

    /// Optional PID filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_filter: Option<Vec<u32>>,

    /// Hard cap on rows emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolPsxviewRow {
    pub pid: u32,
    pub image_name: String,
    pub offset_v: Option<u64>,
    pub pslist: Option<bool>,
    pub psscan: Option<bool>,
    pub thrdproc: Option<bool>,
    pub pspcid: Option<bool>,
    pub csrss: Option<bool>,
    pub session: Option<bool>,
    pub deskthrd: Option<bool>,
    pub exit_time_iso: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolPsxviewOutput {
    pub processes: Vec<VolPsxviewRow>,
    pub processes_seen: usize,
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VolPsxviewError {
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

/// Run Volatility's `windows.psxview` against a memory image.
pub fn vol_psxview(input: &VolPsxviewInput) -> Result<VolPsxviewOutput, VolPsxviewError> {
    if !input.memory_path.exists() {
        return Err(VolPsxviewError::MemoryNotFound(input.memory_path.clone()));
    }
    if !input.memory_path.is_file() {
        return Err(VolPsxviewError::MemoryNotRegular(input.memory_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.arg("-f")
        .arg(&input.memory_path)
        .arg("-r")
        .arg("json")
        .arg("-q")
        .arg("windows.psxview");

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VolPsxviewError::BinaryNotFound
        } else {
            VolPsxviewError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VolPsxviewError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_processes(
        stdout.as_ref(),
        input.pid_filter.as_deref(),
        limit,
        stderr_tail,
    )
}

fn resolve_binary() -> Result<PathBuf, VolPsxviewError> {
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
    Err(VolPsxviewError::BinaryNotFound)
}

fn parse_processes(
    stdout: &str,
    pid_filter: Option<&[u32]>,
    limit: usize,
    stderr_tail: String,
) -> Result<VolPsxviewOutput, VolPsxviewError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VolPsxviewOutput {
            processes: Vec::new(),
            processes_seen: 0,
            stderr_tail,
        });
    }
    let volatility_rows: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).map_err(|e| VolPsxviewError::OutputParse(e.to_string()))?;

    let processes_seen = volatility_rows.len();
    let mut out = Vec::with_capacity(processes_seen.min(limit));
    for value in volatility_rows {
        let row = json_value_to_row(&value);
        if let Some(filter) = pid_filter {
            if !filter.contains(&row.pid) {
                continue;
            }
        }
        out.push(row);
        if out.len() >= limit {
            break;
        }
    }

    Ok(VolPsxviewOutput {
        processes: out,
        processes_seen,
        stderr_tail,
    })
}

fn json_value_to_row(v: &serde_json::Value) -> VolPsxviewRow {
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
    let pick_str = |keys: &[&str]| -> Option<String> {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(s) = val.as_str() {
                    if !s.is_empty() && s != "N/A" && s != "-" {
                        return Some(s.to_string());
                    }
                }
            }
        }
        None
    };
    let pick_u64 = |keys: &[&str]| -> Option<u64> {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(n) = val.as_u64() {
                    return Some(n);
                }
                if let Some(s) = val.as_str() {
                    if let Some(stripped) = s.strip_prefix("0x") {
                        if let Ok(n) = u64::from_str_radix(stripped, 16) {
                            return Some(n);
                        }
                    }
                }
            }
        }
        None
    };
    let pick_bool = |keys: &[&str]| -> Option<bool> {
        for k in keys {
            if let Some(val) = map.get(*k) {
                if let Some(b) = val.as_bool() {
                    return Some(b);
                }
                if let Some(s) = val.as_str() {
                    match s.to_ascii_lowercase().as_str() {
                        "true" | "yes" | "1" => return Some(true),
                        "false" | "no" | "0" => return Some(false),
                        _ => {}
                    }
                }
            }
        }
        None
    };

    VolPsxviewRow {
        pid: pick_u32(&["PID", "pid"]),
        image_name: pick_str(&[
            "ImageFileName",
            "ImageName",
            "Name",
            "process",
            "image_name",
        ])
        .unwrap_or_default(),
        offset_v: pick_u64(&["Offset(V)", "offset_v", "Offset"]),
        pslist: pick_bool(&["pslist", "PsList"]),
        psscan: pick_bool(&["psscan", "PsScan"]),
        thrdproc: pick_bool(&["thrdproc", "Thrdproc"]),
        pspcid: pick_bool(&["pspcid", "PspCid"]),
        csrss: pick_bool(&["csrss", "Csrss"]),
        session: pick_bool(&["session", "Session"]),
        deskthrd: pick_bool(&["deskthrd", "Deskthrd"]),
        exit_time_iso: pick_str(&["ExitTime", "exit_time"]),
    }
}

/// Cheap pre-flight: file path looks like a memory image.
#[must_use]
pub fn path_looks_like_memory(path: &Path) -> bool {
    path.extension().is_some_and(|e| {
        e.eq_ignore_ascii_case("mem")
            || e.eq_ignore_ascii_case("raw")
            || e.eq_ignore_ascii_case("dmp")
            || e.eq_ignore_ascii_case("vmem")
            || e.eq_ignore_ascii_case("lime")
            || e.eq_ignore_ascii_case("aff4")
            || e.eq_ignore_ascii_case("img")
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("...[truncated]");
    }
    s
}
