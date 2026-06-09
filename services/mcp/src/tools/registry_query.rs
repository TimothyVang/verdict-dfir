//! `registry_query` — read keys + values from an offline Windows Registry hive.
//!
//! Spec #2 §6 + Pool A persistence territory. Registry hives are the
//! canonical Windows persistence surface: Run, `RunOnce`, IFEO, Services,
//! WMI subscription consumers, scheduled tasks (via Schedule\TaskCache).
//! This tool reads any offline hive file (NTUSER.DAT / SOFTWARE /
//! SYSTEM / SECURITY / SAM / a UsrClass.dat) without mounting it.
//!
//! Backed by `frnsc-hive = "=0.13.4"` (MIT, `ForensicRS`, same author as
//! `frnsc-prefetch` already used by `prefetch_parse`). The crate
//! integrates with `forensic-rs::traits::vfs::StdVirtualFS`, mirroring
//! the prefetch tool exactly.
//!
//! The tool intentionally normalizes the value-data side: `REG_SZ` /
//! `REG_EXPAND_SZ` / `REG_MULTI_SZ` are flattened to readable strings;
//! `REG_DWORD` / `REG_QWORD` become decimal; `REG_BINARY` is hex-encoded.
//! The agent gets a stable shape regardless of the underlying type and
//! can keyword-match against persistence indicators (`LOLBins`, certutil
//! invocations, `mshta http://...`, etc.) without juggling type-tagged
//! union output.

use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::regf::{Hive, Key, RegfError};

const DEFAULT_LIMIT: usize = 10_000;
const MAX_RECURSION_DEPTH: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RegistryInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Absolute or relative path to the hive primary file (e.g. the
    /// `SOFTWARE` hive at `Windows/System32/config/SOFTWARE`, or a
    /// per-user `NTUSER.DAT`). Transaction logs (`.LOG1`, `.LOG2`) are
    /// not loaded by this tool — agents that need transaction-replay
    /// can pass a pre-merged hive.
    pub hive_path: PathBuf,

    /// Key path relative to the hive root, using either `\` or `/` as
    /// the separator. Empty string returns the root key. Common values:
    /// `Microsoft\Windows\CurrentVersion\Run` (Run keys), `Microsoft\
    /// Windows\CurrentVersion\Image File Execution Options` (IFEO),
    /// `ControlSet001\Services` (services). Optional `HKLM\` /
    /// `HKCU\` / `HKU\` prefix is stripped.
    pub key_path: String,

    /// When true, recursively descend into all subkeys and emit one
    /// entry per key visited. Capped at depth 16 + the limit below.
    /// Default false — non-recursive returns just the requested key.
    #[serde(default, skip_serializing_if = "is_false")]
    pub recursive: bool,

    /// Hard cap on total entries emitted. Default `10_000`. Use a smaller
    /// value (e.g. 100) for an interactive triage; larger when sweeping
    /// a known-large path like `Services`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryValue {
    pub name: String,

    /// One of: `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`,
    /// `REG_QWORD`, `REG_BINARY`. Unknown types fall through to `REG_BINARY`.
    pub value_type: String,

    /// String-formatted data. `SZ/EXPAND_SZ/MULTI_SZ` → text (`MULTI_SZ` is
    /// joined by `|`). DWORD/QWORD → decimal. BINARY → lowercase hex
    /// (capped at 4096 bytes — longer values are truncated and tagged
    /// with `…[truncated, full N bytes]`).
    pub data_str: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryEntry {
    /// Path of the key under the hive root, using `\` separators.
    pub key_path: String,

    /// Key's `last_write_time` as UTC ISO-8601Z, or None if the
    /// underlying `KeyNode` reports a zero filetime (rare; usually a
    /// freshly-formatted hive's root).
    pub last_write_time_iso: Option<String>,

    /// All values directly attached to this key. Subkey-level values
    /// appear in their own entries when `recursive=true`.
    pub values: Vec<RegistryValue>,

    /// Names of direct subkeys (one level down). For full recursion,
    /// each subkey gets its own entry.
    pub subkeys: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RegistryOutput {
    pub entries: Vec<RegistryEntry>,
    pub keys_visited: usize,
    pub parse_errors: usize,
    /// False when the requested key path is absent from this hive. That is a
    /// normal analytical result (e.g. a user with no `…\Run` autoruns), NOT a
    /// tool failure — `entries` is empty and callers should read it as "no such
    /// key here," not retry.
    pub key_present: bool,
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("registry hive not found: {0}")]
    HiveNotFound(PathBuf),

    #[error("registry hive unreadable {path}: {source}")]
    HiveUnreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("registry hive parse failed for {path}: {source}")]
    HiveOpen {
        path: PathBuf,
        #[source]
        source: RegfError,
    },
}

/// Cheap pre-flight: file path looks like a registry hive.
///
/// We accept the canonical hive base names (case-insensitive) plus
/// any file whose extension is `.dat` (NTUSER.DAT / UsrClass.dat).
/// The actual parser is the source of truth on whether a file is
/// genuinely a hive.
#[must_use]
pub fn path_looks_like_hive(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("dat"))
    {
        return true;
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_uppercase().as_str(),
        "SOFTWARE" | "SYSTEM" | "SECURITY" | "SAM" | "DEFAULT" | "NTUSER.DAT" | "USRCLASS.DAT"
    )
}

/// Read keys + values from an offline registry hive.
///
/// # Errors
/// * [`RegistryError::HiveNotFound`] — the file does not exist.
/// * [`RegistryError::HiveUnreadable`] — exists but cannot be opened
///   (permissions / I/O).
/// * [`RegistryError::HiveOpen`] — file is not a valid hive (wrong
///   magic / corrupt header).
///
/// A key path that is absent from the hive is NOT an error: it returns an empty
/// [`RegistryOutput`] with `key_present == false`.
pub fn registry_query(input: &RegistryInput) -> Result<RegistryOutput, RegistryError> {
    let path = &input.hive_path;
    if !path.is_file() {
        return Err(RegistryError::HiveNotFound(path.clone()));
    }

    let hive = Hive::open(path).map_err(|err| match err {
        RegfError::Io(source) => RegistryError::HiveUnreadable {
            path: path.clone(),
            source,
        },
        other => RegistryError::HiveOpen {
            path: path.clone(),
            source: other,
        },
    })?;

    let normalized = normalize_key_path(&input.key_path);
    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);

    let Some(key) = hive.find(&normalized) else {
        // An absent key is a valid finding ("no such persistence here"), not an
        // error. Return an empty result so the agent records "0 entries" rather
        // than treating it as a tool failure that needs a course-correction.
        return Ok(RegistryOutput {
            entries: Vec::new(),
            keys_visited: 0,
            parse_errors: 0,
            key_present: false,
        });
    };

    let mut output = RegistryOutput {
        entries: Vec::new(),
        keys_visited: 0,
        parse_errors: 0,
        key_present: true,
    };

    walk(
        &hive,
        key,
        &normalized,
        input.recursive,
        limit,
        0,
        &mut output,
    );

    Ok(output)
}

fn walk(
    hive: &Hive,
    key: Key,
    key_path: &str,
    recursive: bool,
    limit: usize,
    depth: usize,
    output: &mut RegistryOutput,
) {
    if output.entries.len() >= limit || depth > MAX_RECURSION_DEPTH {
        return;
    }
    output.keys_visited += 1;

    // Resolve children once so we can both report their names and recurse
    // without re-finding each one from the root.
    let children: Vec<(String, Key)> = hive
        .subkeys(key)
        .into_iter()
        .map(|k| (hive.key_name(k), k))
        .collect();

    output
        .entries
        .push(build_entry(hive, key, key_path, &children));

    if recursive {
        for (name, child) in children {
            if output.entries.len() >= limit {
                break;
            }
            let child_path = if key_path.is_empty() {
                name
            } else {
                format!("{key_path}\\{name}")
            };
            walk(
                hive,
                child,
                &child_path,
                recursive,
                limit,
                depth + 1,
                output,
            );
        }
    }
}

fn build_entry(hive: &Hive, key: Key, key_path: &str, children: &[(String, Key)]) -> RegistryEntry {
    let last_write_time_iso = filetime_to_iso(hive.key_timestamp(key));

    let values: Vec<RegistryValue> = hive
        .values(key)
        .into_iter()
        .map(|v| {
            let (value_type, data_str) = format_value(v.value_type, &v.data);
            RegistryValue {
                name: v.name,
                value_type,
                data_str,
            }
        })
        .collect();

    let subkeys = children.iter().map(|(name, _)| name.clone()).collect();

    RegistryEntry {
        key_path: key_path.to_string(),
        last_write_time_iso,
        values,
        subkeys,
    }
}

// Windows registry value-type constants.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_DWORD_BIG_ENDIAN: u32 = 5;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

/// Decode a NUL-terminated UTF-16LE string from raw value data.
fn utf16le_string(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Normalize raw (type, data) into a stable (type-label, string) shape so the
/// agent can keyword-match without juggling a type-tagged union.
fn format_value(value_type: u32, data: &[u8]) -> (String, String) {
    match value_type {
        REG_SZ => ("REG_SZ".into(), utf16le_string(data)),
        REG_EXPAND_SZ => ("REG_EXPAND_SZ".into(), utf16le_string(data)),
        REG_MULTI_SZ => {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let joined = String::from_utf16_lossy(&units)
                .split('\0')
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join("|");
            ("REG_MULTI_SZ".into(), joined)
        }
        REG_DWORD => {
            let n = data
                .get(0..4)
                .map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            ("REG_DWORD".into(), n.to_string())
        }
        REG_DWORD_BIG_ENDIAN => {
            let n = data
                .get(0..4)
                .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            ("REG_DWORD".into(), n.to_string())
        }
        REG_QWORD => {
            let n = data
                .get(0..8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_le_bytes);
            ("REG_QWORD".into(), n.to_string())
        }
        // REG_BINARY and any unknown type → hex (capped, like before).
        _ => {
            const MAX_HEX: usize = 4096;
            if data.len() <= MAX_HEX {
                ("REG_BINARY".into(), hex::encode(data))
            } else {
                let suffix = format!("…[truncated, full {} bytes]", data.len());
                let mut out = hex::encode(&data[..MAX_HEX]);
                out.push_str(&suffix);
                ("REG_BINARY".into(), out)
            }
        }
    }
}

fn normalize_key_path(input: &str) -> String {
    let trimmed = input.trim().trim_matches(|c| c == '\\' || c == '/');
    // Strip the optional HKLM\ / HKCU\ / HKU\ prefix the agent might
    // include — only the path inside the hive matters here.
    let without_prefix = trimmed
        .strip_prefix("HKLM\\")
        .or_else(|| trimmed.strip_prefix("HKEY_LOCAL_MACHINE\\"))
        .or_else(|| trimmed.strip_prefix("HKCU\\"))
        .or_else(|| trimmed.strip_prefix("HKEY_CURRENT_USER\\"))
        .or_else(|| trimmed.strip_prefix("HKU\\"))
        .or_else(|| trimmed.strip_prefix("HKEY_USERS\\"))
        .unwrap_or(trimmed);
    // Normalize forward slashes to backslashes to match the underlying
    // crate's expectation.
    without_prefix.replace('/', "\\")
}

// 116444736000000000 ticks = FILETIME for 1970-01-01 (Unix epoch).
const FILETIME_UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

fn filetime_to_iso(raw: u64) -> Option<String> {
    if raw == 0 {
        return None;
    }
    let unix_100ns = i64::try_from(raw).ok()? - FILETIME_UNIX_EPOCH_TICKS;
    let secs = unix_100ns / 10_000_000;
    let nanos = u32::try_from((unix_100ns % 10_000_000) * 100).ok()?;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}
