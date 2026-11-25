//! `vol_pslist` — subprocess wrapper for Volatility 3's `windows.pslist`.
//!
//! Spec #2 §6 + invariant: Volatility 3 is BSD-2-Clause (compatible
//! with our Apache-2.0 submission), but per CLAUDE.md the project's
//! convention is to invoke Volatility as a SUBPROCESS — the
//! Python-based runtime would be a heavy dependency and we already
//! pay a subprocess cost for `hayabusa_scan`, so the consistency wins.
//!
//! `windows.pslist` is the canonical "first look" memory plugin —
//! it walks the kernel's process list (`PsActiveProcessHead`) and
//! emits one row per live process. Pair with `vol_psscan` and
//! `vol_psxview` for process-view corroboration, then use
//! `vol_malfind` for code-injection triage.
//!
//! Volatility invocation: `<vol> -f <memory> -r json windows.pslist`.
//! `-r json` writes a clean JSON array to stdout. Binary discovery
//! tries `$VOLATILITY_BIN`, then `vol`, `vol.py`, `volatility3`,
//! `volatility` on PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolPslistInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the memory image (`.mem`, `.raw`, `.dmp`, `.vmem`, `.img`).
    /// Volatility auto-detects the OS profile.
    pub memory_path: PathBuf,

    /// Optional PID filter. When supplied, only processes whose PID
    /// is in this list are returned. Useful for drilling down after
    /// a coarse first sweep.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid_filter: Option<Vec<u32>>,

    /// Hard cap on rows emitted. Default `10_000` (a typical Windows
    /// host has 100-500 live processes, so the limit is mostly a
    /// safety net for malformed images).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolProcess {
    /// Process ID.
    pub pid: u32,

    /// Parent process ID.
    pub ppid: u32,

    /// Process image name (e.g. `explorer.exe`, `lsass.exe`).
    pub image_name: String,

    /// Process creation time as UTC ISO-8601Z, when known.
    pub create_time_iso: Option<String>,

    /// Process exit time as UTC ISO-8601Z; `None` for live processes
    /// (which is most of them in a typical pslist).
    pub exit_time_iso: Option<String>,

    /// Thread count.
    pub threads: u32,

    /// Handle count.
    pub handles: u32,

    /// Session ID (for distinguishing console / RDP sessions).
    pub session_id: u32,

    /// True for 32-bit processes running under `WoW64`.
    pub wow64: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolPslistOutput {
    pub processes: Vec<VolProcess>,

    /// Total processes Volatility reported before our filter / limit.
    pub processes_seen: usize,

    /// Stderr tail (capped at 4096 bytes) — Volatility prints
    /// progress + plugin warnings here; useful when output is empty.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VolError {
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

/// Run Volatility's `windows.pslist` against a memory image.
///
/// # Errors
/// * [`VolError::MemoryNotFound`] / [`VolError::MemoryNotRegular`] —
///   filesystem path missing or not a file.
/// * [`VolError::BinaryNotFound`] — Volatility not on PATH and
///   `$VOLATILITY_BIN` unset.
/// * [`VolError::SubprocessFailed`] — Volatility returned non-zero;
///   check `stderr_tail` in the error or in the typed output.
/// * [`VolError::OutputParse`] — JSON output was malformed (rare;
///   indicates a Volatility version mismatch).
pub fn vol_pslist(input: &VolPslistInput) -> Result<VolPslistOutput, VolError> {
    if !input.memory_path.exists() {
        return Err(VolError::MemoryNotFound(input.memory_path.clone()));
    }
    if !input.memory_path.is_file() {
        return Err(VolError::MemoryNotRegular(input.memory_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.arg("-f")
        .arg(&input.memory_path)
        .arg("-r")
        .arg("json")
        .arg("-q") // quiet — suppress progress on stderr where possible
        .arg("windows.pslist");

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VolError::BinaryNotFound
        } else {
            VolError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VolError::SubprocessFailed {
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

fn resolve_binary() -> Result<PathBuf, VolError> {
    if let Ok(env_path) = std::env::var("VOLATILITY_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            return Ok(p);
        }
    }
    if let Ok(path_var) = std::env::var("PATH") {
        // Try the most-common command names in order. The SIFT VM ships
        // `vol.py`; pip installs put `vol` and/or `volatility3` on PATH.
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
    Err(VolError::BinaryNotFound)
}

fn parse_processes(
    stdout: &str,
    pid_filter: Option<&[u32]>,
    limit: usize,
    stderr_tail: String,
) -> Result<VolPslistOutput, VolError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VolPslistOutput {
            processes: Vec::new(),
            processes_seen: 0,
            stderr_tail,
        });
    }
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).map_err(|e| VolError::OutputParse(e.to_string()))?;

    let processes_seen = raw.len();
    let mut out = Vec::with_capacity(processes_seen.min(limit));
    for value in raw {
        let proc = json_value_to_process(&value);
        if let Some(filter) = pid_filter {
            if !filter.contains(&proc.pid) {
                continue;
            }
        }
        out.push(proc);
        if out.len() >= limit {
            break;
        }
    }

    Ok(VolPslistOutput {
        processes: out,
        processes_seen,
        stderr_tail,
    })
}

/// Tolerant projection of one Volatility row into our typed shape.
/// Volatility's JSON field names have varied across versions — these
/// pickers accept the historical names so a Vol3 minor version bump
/// doesn't silently break the agent.
fn json_value_to_process(v: &serde_json::Value) -> VolProcess {
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

    VolProcess {
        pid: pick_u32(&["PID", "pid"]),
        ppid: pick_u32(&["PPID", "ppid"]),
        image_name: pick_str(&["ImageFileName", "ImageName", "image_name"]).unwrap_or_default(),
        create_time_iso: pick_str(&["CreateTime", "create_time", "CreatedTime"]),
        exit_time_iso: pick_str(&["ExitTime", "exit_time"]),
        threads: pick_u32(&["Threads", "threads"]),
        handles: pick_u32(&["Handles", "handles"]),
        session_id: pick_u32(&["SessionId", "session_id"]),
        wow64: map
            .get("Wow64")
            .or_else(|| map.get("wow64"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
    }
}

/// Cheap pre-flight: file path looks like a memory image.
#[must_use]
pub fn path_looks_like_memory_image(path: &Path) -> bool {
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
        // Walk to the nearest char boundary so multi-byte UTF-8 (Vol3
        // progress output uses Unicode box-drawing characters) doesn't
        // panic `String::truncate`. Bounded at 4 bytes per codepoint.
        let mut boundary = max;
        while boundary > 0 && !s.is_char_boundary(boundary) {
            boundary -= 1;
        }
        s.truncate(boundary);
        s.push_str("…[truncated]");
    }
    s
}
