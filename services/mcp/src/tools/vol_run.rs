//! `vol_run` — one allow-listed Volatility 3 plugin verb.
//!
//! The four bespoke `vol_*` tools (pslist/psscan/psxview/malfind) each wrap a
//! single plugin with a fully typed output. That is the right shape for the
//! high-value pivots, but the Vol3 evil-hunting surface is ~40 plugins across
//! Windows + Linux + macOS, and writing 40 bespoke files would explode the
//! verb count and shred the "narrow typed surface" pitch.
//!
//! `vol_run` collapses the long tail into ONE verb: the agent names a plugin
//! from a **canonical-name allow-list** and gets back the plugin's raw rows as
//! typed JSON maps. The allow-list is the security boundary — a parameterized
//! verb is only safe if the parameter can never become an arbitrary command,
//! so any plugin string not on the list is rejected before argv is built.
//!
//! Output is intentionally generic (`rows: Vec<Map>`): different plugins emit
//! different columns, so we hand the agent the plugin's own schema rather than
//! forcing a lossy projection. The four bespoke tools stay for the pivots whose
//! typed output the playbooks depend on.
//!
//! Invocation: `<vol> -f <memory> -r json -q <plugin> [--pid <n>]`. Binary
//! discovery matches `vol_pslist` (`$VOLATILITY_BIN`, then PATH).

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const DEFAULT_LIMIT: usize = 10_000;

/// Canonical Vol3 plugin names this verb will run. Curated from the
/// parser-coverage roadmap's memory section — the evil-hunting plugins that run
/// argless or with only a `--pid` scope. Names use real Vol3 namespaces; the
/// non-existent `windows.clipboard` / `hollowfind` / `threadmap` are
/// deliberately absent. Plugins that require richer args (printkey `--key`,
/// dumpfiles file extraction) are out of scope for this typed verb.
const ALLOWED_PLUGINS: &[&str] = &[
    // Windows — process / execution context
    "windows.cmdline",
    "windows.dlllist",
    "windows.ldrmodules",
    "windows.handles",
    "windows.getsids",
    "windows.privileges",
    "windows.sessions",
    "windows.envars",
    // Windows — services / network
    "windows.svcscan",
    "windows.netscan",
    "windows.netstat",
    // Windows — console / shell history
    "windows.consoles",
    "windows.cmdscan",
    // Windows — credentials
    "windows.registry.hashdump",
    "windows.registry.lsadump",
    "windows.registry.cachedump",
    // Windows — injection / hollowing depth
    "windows.hollowprocesses",
    "windows.suspicious_threads",
    "windows.vadinfo",
    // Windows — kernel rootkit surface
    "windows.modules",
    "windows.modscan",
    "windows.driverscan",
    "windows.ssdt",
    "windows.callbacks",
    // Windows — file objects / MFT in memory
    "windows.filescan",
    "windows.mftscan.MFTScan",
    // Windows — in-memory registry
    "windows.registry.hivelist",
    "windows.registry.userassist",
    // Linux
    "linux.pslist",
    "linux.psscan",
    "linux.pstree",
    "linux.bash",
    "linux.malfind",
    "linux.lsmod",
    "linux.check_modules",
    "linux.check_syscall",
    "linux.hidden_modules",
    // macOS
    "mac.pslist",
    "mac.psaux",
    "mac.lsmod",
    "mac.malfind",
    "mac.check_syscall",
];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VolRunInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the memory image (`.mem`, `.raw`, `.dmp`, `.vmem`, `.lime`,
    /// `.img`). Volatility auto-detects the OS profile; Linux/macOS images also
    /// need their ISF symbol table on the Vol3 symbol path.
    pub memory_path: PathBuf,

    /// Volatility 3 plugin to run. MUST be one of the allow-listed canonical
    /// names (see the tool description); any other value is rejected with
    /// `PluginNotAllowed` before a subprocess is spawned.
    pub plugin: String,

    /// Optional `--pid` scope. When set, the plugin runs against only this PID
    /// (valid for the per-process plugins: handles, dlllist, ldrmodules,
    /// envars, cmdline, etc.). A `u32` can never be a shell fragment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,

    /// Hard cap on rows emitted. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VolRunOutput {
    /// The plugin that was run (echoed for audit correlation).
    pub plugin: String,

    /// Raw plugin rows as JSON objects. Columns vary by plugin — the agent gets
    /// the plugin's own schema rather than a lossy projection.
    pub rows: Vec<serde_json::Map<String, serde_json::Value>>,

    /// Total rows the plugin reported before the limit was applied.
    pub rows_seen: usize,

    /// Stderr tail (capped at 4096 bytes) — Vol3 prints progress + plugin
    /// warnings here; useful when `rows` is empty.
    pub stderr_tail: String,
}

#[derive(Debug, Error)]
pub enum VolRunError {
    #[error("memory image not found: {0}")]
    MemoryNotFound(PathBuf),

    #[error("memory image is not a regular file: {0}")]
    MemoryNotRegular(PathBuf),

    #[error(
        "plugin {0:?} is not on the vol_run allow-list; use one of the canonical \
         Vol3 names in the tool description, or the bespoke vol_pslist/psscan/\
         psxview/malfind tools"
    )]
    PluginNotAllowed(String),

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

/// True if `plugin` is on the allow-list (exact match).
#[must_use]
pub fn is_allowed_plugin(plugin: &str) -> bool {
    ALLOWED_PLUGINS.contains(&plugin)
}

/// Build the fixed argv for a Vol3 run. Pure + unit-tested so the arg contract
/// (globals before plugin, `--pid` after) can't regress. The plugin is assumed
/// already allow-list-validated by the caller.
fn build_vol_args(memory: &Path, plugin: &str, pid: Option<u32>) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "-f".into(),
        memory.as_os_str().to_os_string(),
        "-r".into(),
        "json".into(),
        "-q".into(),
        plugin.into(),
    ];
    if let Some(p) = pid {
        args.push("--pid".into());
        args.push(p.to_string().into());
    }
    args
}

/// Run an allow-listed Volatility 3 plugin against a memory image.
///
/// # Errors
/// * [`VolRunError::PluginNotAllowed`] — `plugin` is not on the allow-list
///   (checked BEFORE any filesystem or subprocess work).
/// * [`VolRunError::MemoryNotFound`] / [`VolRunError::MemoryNotRegular`] — path
///   missing or not a file.
/// * [`VolRunError::BinaryNotFound`] — Volatility not on PATH and
///   `$VOLATILITY_BIN` unset.
/// * [`VolRunError::SubprocessFailed`] — Volatility returned non-zero.
/// * [`VolRunError::OutputParse`] — JSON output malformed.
pub fn vol_run(input: &VolRunInput) -> Result<VolRunOutput, VolRunError> {
    // Allow-list FIRST — the security boundary for a parameterized verb.
    if !is_allowed_plugin(&input.plugin) {
        return Err(VolRunError::PluginNotAllowed(input.plugin.clone()));
    }
    if !input.memory_path.exists() {
        return Err(VolRunError::MemoryNotFound(input.memory_path.clone()));
    }
    if !input.memory_path.is_file() {
        return Err(VolRunError::MemoryNotRegular(input.memory_path.clone()));
    }

    let binary = resolve_binary()?;
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let mut cmd = Command::new(&binary);
    cmd.args(build_vol_args(&input.memory_path, &input.plugin, input.pid));

    let proc = cmd.output().map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            VolRunError::BinaryNotFound
        } else {
            VolRunError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            }
        }
    })?;

    let stderr_tail = truncate_to(String::from_utf8_lossy(&proc.stderr).into_owned(), 4096);

    if !proc.status.success() {
        return Err(VolRunError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: stderr_tail,
        });
    }

    let stdout = String::from_utf8_lossy(&proc.stdout);
    parse_rows(&input.plugin, stdout.as_ref(), limit, stderr_tail)
}

fn resolve_binary() -> Result<PathBuf, VolRunError> {
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
    Err(VolRunError::BinaryNotFound)
}

fn parse_rows(
    plugin: &str,
    stdout: &str,
    limit: usize,
    stderr_tail: String,
) -> Result<VolRunOutput, VolRunError> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(VolRunOutput {
            plugin: plugin.to_string(),
            rows: Vec::new(),
            rows_seen: 0,
            stderr_tail,
        });
    }
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(trimmed).map_err(|e| VolRunError::OutputParse(e.to_string()))?;

    let rows_seen = raw.len();
    let rows: Vec<serde_json::Map<String, serde_json::Value>> = raw
        .into_iter()
        .take(limit)
        .map(|v| v.as_object().cloned().unwrap_or_default())
        .collect();

    Ok(VolRunOutput {
        plugin: plugin.to_string(),
        rows,
        rows_seen,
        stderr_tail,
    })
}

fn truncate_to(mut s: String, max: usize) -> String {
    if s.len() > max {
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

    fn as_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn allow_list_accepts_canonical_plugins() {
        assert!(is_allowed_plugin("windows.cmdline"));
        assert!(is_allowed_plugin("windows.registry.hashdump"));
        assert!(is_allowed_plugin("linux.bash"));
        assert!(is_allowed_plugin("mac.pslist"));
    }

    #[test]
    fn allow_list_rejects_off_list_and_shell_injection() {
        // An off-list plugin is rejected.
        assert!(!is_allowed_plugin("windows.dumpfiles"));
        // The non-existent names the roadmap warns against.
        assert!(!is_allowed_plugin("windows.clipboard"));
        assert!(!is_allowed_plugin("hollowfind"));
        // A shell-injection-shaped plugin string is NOT on the list, so it can
        // never reach argv — this is the no-shell guarantee for the verb.
        assert!(!is_allowed_plugin("windows.cmdline; rm -rf /"));
        assert!(!is_allowed_plugin("windows.cmdline && curl evil"));
        assert!(!is_allowed_plugin("$(reboot)"));
    }

    #[test]
    fn vol_run_rejects_off_list_plugin_before_any_io() {
        // A missing memory path would normally error — but the allow-list check
        // runs first, so an off-list plugin fails with PluginNotAllowed even
        // when the path does not exist (proving no IO/subprocess happens).
        let input = VolRunInput {
            case_id: "c".into(),
            memory_path: PathBuf::from("/nonexistent/image.mem"),
            plugin: "windows.cmdline; rm -rf /".into(),
            pid: None,
            limit: None,
        };
        match vol_run(&input) {
            Err(VolRunError::PluginNotAllowed(p)) => {
                assert_eq!(p, "windows.cmdline; rm -rf /");
            }
            other => panic!("expected PluginNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn build_vol_args_puts_globals_before_plugin() {
        let args = build_vol_args(Path::new("/img.mem"), "windows.cmdline", None);
        let s = as_strings(&args);
        assert_eq!(
            s,
            vec!["-f", "/img.mem", "-r", "json", "-q", "windows.cmdline"]
        );
    }

    #[test]
    fn build_vol_args_appends_pid_after_plugin() {
        let args = build_vol_args(Path::new("/img.mem"), "windows.handles", Some(1234));
        let s = as_strings(&args);
        let plugin_pos = s.iter().position(|a| a == "windows.handles").unwrap();
        let pid_flag = s.iter().position(|a| a == "--pid").unwrap();
        assert!(pid_flag > plugin_pos, "--pid must follow the plugin: {s:?}");
        assert_eq!(s[pid_flag + 1], "1234");
    }

    #[test]
    fn parse_rows_handles_empty_and_array() {
        let empty = parse_rows("windows.cmdline", "   \n", 100, String::new()).unwrap();
        assert_eq!(empty.rows_seen, 0);

        let body = r#"[{"PID":4,"Args":"System"},{"PID":680,"Args":"smss.exe"}]"#;
        let out = parse_rows("windows.cmdline", body, 100, String::new()).unwrap();
        assert_eq!(out.rows_seen, 2);
        assert_eq!(out.plugin, "windows.cmdline");
        assert_eq!(
            out.rows[0].get("PID").and_then(serde_json::Value::as_u64),
            Some(4)
        );
    }

    #[test]
    fn parse_rows_respects_limit() {
        let body = r#"[{"PID":1},{"PID":2},{"PID":3}]"#;
        let out = parse_rows("windows.pslist", body, 2, String::new()).unwrap();
        assert_eq!(out.rows_seen, 3, "rows_seen reports pre-limit count");
        assert_eq!(out.rows.len(), 2, "rows are capped at the limit");
    }
}
