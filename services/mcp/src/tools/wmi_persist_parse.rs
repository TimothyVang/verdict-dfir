//! `wmi_persist_parse` — surface WMI event-consumer persistence from the CIM
//! repository (`OBJECTS.DATA`).
//!
//! WMI permanent event subscriptions are a durable, fileless persistence and
//! lateral-movement primitive (MITRE **T1546.003**). An attacker registers an
//! `__EventFilter` (the trigger — e.g. a process-start WQL query), an event
//! consumer that carries the payload (`CommandLineEventConsumer` with a command
//! line, or `ActiveScriptEventConsumer` with inline VBScript/JScript), and a
//! `__FilterToConsumerBinding` that wires the two together. All three live in the
//! CIM repository at `%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`.
//!
//! Fully decoding the CIM repository is complex and error-prone (that is what the
//! `python-cim` library exists for), and a subtle misparse would put WRONG text
//! behind a Finding. This reader is deliberately **conservative**, mirroring
//! `oe_dbx_parse` / `bits_parse`: it does not reconstruct CIM objects. It scans
//! the raw repository bytes for the WMI persistence **class-name signatures** and
//! the printable strings adjacent to a consumer definition (command lines, script
//! text), reporting only what is actually present. It cannot prove a binding is
//! active — it flags the *pattern* (a consumer plus a filter plus a binding all
//! present) as a persistence **lead** for corroboration, never as proof.
//!
//! Nothing here is image-specific: it keys on the general WMI class names and
//! MITRE-technique signatures, never on any host's usernames, paths, or scripts.
//! Every surfaced string is read straight from the artifact bytes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Upper bound on bytes read. `OBJECTS.DATA` is typically tens of MB; the cap
/// stops a pathological path from exhausting memory.
const MAX_BYTES: usize = 512 * 1024 * 1024;
/// Cap on surfaced strings per kind so a huge repository cannot bloat output.
/// Counts are reported separately and are not capped.
const MAX_ITEMS: usize = 50;
/// Longest extracted string kept; longer runs are treated as noise.
const MAX_STRING_LEN: usize = 2048;
/// Shortest printable run kept, to skip single-character noise.
const MIN_STRING_LEN: usize = 4;

/// Event-consumer class names — the payload carriers. Presence of one of these
/// plus a filter and a binding is the T1546.003 persistence pattern.
const CONSUMER_CLASSES: &[&str] = &[
    "CommandLineEventConsumer",
    "ActiveScriptEventConsumer",
    "LogFileEventConsumer",
    "NTEventLogEventConsumer",
    "ScriptingStandardConsumerSetting",
    "SMTPEventConsumer",
];
/// Filter class name — the trigger half of a subscription.
const FILTER_CLASS: &str = "__EventFilter";
/// Binding class name — wires a filter to a consumer.
const BINDING_CLASS: &str = "__FilterToConsumerBinding";

/// Property-name markers that immediately precede an embedded command line or
/// script body in a consumer definition. Used only to label extracted strings;
/// the strings themselves are surfaced regardless.
const COMMAND_MARKERS: &[&str] = &["CommandLineTemplate", "ExecutablePath"];
const SCRIPT_MARKERS: &[&str] = &["ScriptText", "ScriptFileName"];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WmiPersistParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to a WMI CIM repository `OBJECTS.DATA` file.
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct WmiPersistParseOutput {
    /// True if the bytes carry recognizable WMI class-name signatures.
    pub is_wmi_repository: bool,
    /// Consumer class names present (sorted, deduped).
    pub consumer_classes_found: Vec<String>,
    /// Count of `__EventFilter` occurrences.
    pub filter_count: usize,
    /// Count of `__FilterToConsumerBinding` occurrences.
    pub binding_count: usize,
    /// Command lines / executable paths adjacent to a command consumer (sorted,
    /// deduped, capped).
    pub command_strings: Vec<String>,
    /// Inline script bodies / script filenames adjacent to a script consumer
    /// (sorted, deduped, capped).
    pub script_strings: Vec<String>,
    /// True when a consumer AND a filter AND a binding are all present — the
    /// T1546.003 subscription pattern. A LEAD for corroboration, not proof that
    /// the subscription is active.
    pub persistence_pattern_present: bool,
}

impl WmiPersistParseOutput {
    /// The "not a WMI repository" shape: falsy, never an error.
    const fn empty() -> Self {
        Self {
            is_wmi_repository: false,
            consumer_classes_found: Vec::new(),
            filter_count: 0,
            binding_count: 0,
            command_strings: Vec::new(),
            script_strings: Vec::new(),
            persistence_pattern_present: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum WmiPersistParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Surface WMI event-consumer persistence indicators from `OBJECTS.DATA`.
///
/// # Errors
/// * [`WmiPersistParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`WmiPersistParseError::Read`] — IO error reading the file.
pub fn wmi_persist_parse(
    input: &WmiPersistParseInput,
) -> Result<WmiPersistParseOutput, WmiPersistParseError> {
    if !input.artifact_path.exists() {
        return Err(WmiPersistParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }
    let data = read_capped(&input.artifact_path)?;
    Ok(parse_bytes(&data))
}

fn read_capped(path: &std::path::Path) -> Result<Vec<u8>, WmiPersistParseError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| WmiPersistParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|source| WmiPersistParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Pure parse over the raw repository bytes — unit-tested without IO. Extracts
/// every printable ASCII and UTF-16LE string, then classifies against the WMI
/// class-name and property-marker signatures. Reporting strings actually present
/// (never decoded CIM objects) keeps a misparse from inventing structure.
fn parse_bytes(data: &[u8]) -> WmiPersistParseOutput {
    let strings = extract_strings(data);
    if strings.is_empty() {
        return WmiPersistParseOutput::empty();
    }

    let mut consumers: BTreeSet<String> = BTreeSet::new();
    let mut filter_count = 0usize;
    let mut binding_count = 0usize;
    let mut commands: BTreeSet<String> = BTreeSet::new();
    let mut scripts: BTreeSet<String> = BTreeSet::new();
    let mut saw_wmi_token = false;

    for s in &strings {
        for consumer in CONSUMER_CLASSES {
            if s.contains(consumer) {
                consumers.insert((*consumer).to_string());
                saw_wmi_token = true;
            }
        }
        if s.contains(FILTER_CLASS) {
            filter_count += 1;
            saw_wmi_token = true;
        }
        if s.contains(BINDING_CLASS) {
            binding_count += 1;
            saw_wmi_token = true;
        }
        // A string that looks like a command line or script body is surfaced by
        // shape (a marker property name nearby, or an executable/script tell).
        if looks_like_command(s) {
            commands.insert(truncate(s));
        }
        if looks_like_script(s) {
            scripts.insert(truncate(s));
        }
    }

    if !saw_wmi_token {
        return WmiPersistParseOutput::empty();
    }

    let persistence_pattern_present =
        !consumers.is_empty() && filter_count > 0 && binding_count > 0;

    WmiPersistParseOutput {
        is_wmi_repository: true,
        consumer_classes_found: consumers.into_iter().collect(),
        filter_count,
        binding_count,
        command_strings: commands.into_iter().take(MAX_ITEMS).collect(),
        script_strings: scripts.into_iter().take(MAX_ITEMS).collect(),
        persistence_pattern_present,
    }
}

/// A string carries a command-consumer payload if it names a command marker or
/// looks like an executable invocation (a general T1546.003 tell, not an
/// image-specific value).
fn looks_like_command(s: &str) -> bool {
    let low = s.to_ascii_lowercase();
    if COMMAND_MARKERS.iter().any(|m| s.contains(m)) {
        return true;
    }
    low.contains("cmd.exe")
        || low.contains("powershell")
        || low.contains("wscript")
        || low.contains("cscript")
        || low.contains("rundll32")
        || low.contains("mshta")
}

/// A string carries a script-consumer payload if it names a script marker or
/// carries scripting-engine syntax tells.
fn looks_like_script(s: &str) -> bool {
    if SCRIPT_MARKERS.iter().any(|m| s.contains(m)) {
        return true;
    }
    let low = s.to_ascii_lowercase();
    low.contains("createobject")
        || low.contains("wscript.shell")
        || low.contains("eval(")
        || low.contains("<script")
}

/// Truncate an over-long extracted string so one huge blob cannot bloat output.
fn truncate(s: &str) -> String {
    if s.len() <= MAX_STRING_LEN {
        s.to_string()
    } else {
        s.chars().take(MAX_STRING_LEN).collect()
    }
}

/// Every printable string in the buffer, from both ASCII and UTF-16LE runs. A
/// CIM repository stores class/property names and values in both encodings, so
/// both are scanned. Runs shorter than `MIN_STRING_LEN` are dropped as noise.
fn extract_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    out.extend(ascii_runs(data));
    out.extend(utf16le_runs(data));
    out
}

/// Maximal printable-ASCII runs (bytes 0x20..=0x7E).
fn ascii_runs(data: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();
    for &b in data {
        if (0x20..=0x7E).contains(&b) {
            current.push(b as char);
        } else if current.chars().count() >= MIN_STRING_LEN {
            runs.push(std::mem::take(&mut current));
        } else {
            current.clear();
        }
    }
    if current.chars().count() >= MIN_STRING_LEN {
        runs.push(current);
    }
    runs
}

/// Maximal printable UTF-16LE runs: consecutive little-endian code units whose
/// high byte is zero and low byte is printable ASCII (covers the class/property
/// names and most command/script text in the repository).
fn utf16le_runs(data: &[u8]) -> Vec<String> {
    let mut runs = Vec::new();
    let mut current = String::new();
    let mut i = 0;
    while i + 1 < data.len() {
        let low = data[i];
        let high = data[i + 1];
        if high == 0 && (0x20..=0x7E).contains(&low) {
            current.push(low as char);
            i += 2;
        } else {
            if current.chars().count() >= MIN_STRING_LEN {
                runs.push(std::mem::take(&mut current));
            } else {
                current.clear();
            }
            i += 1;
        }
    }
    if current.chars().count() >= MIN_STRING_LEN {
        runs.push(current);
    }
    runs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a `&str` as UTF-16LE bytes.
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// Build a synthetic OBJECTS.DATA-shaped buffer from UTF-16LE tokens joined
    /// by NUL padding (as the repository interleaves records).
    fn repo(tokens: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for t in tokens {
            out.extend(utf16le(t));
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        out
    }

    #[test]
    fn full_subscription_triad_flags_persistence_pattern() {
        let bytes = repo(&[
            "__EventFilter",
            "CommandLineEventConsumer",
            "CommandLineTemplate cmd.exe /c powershell -enc ZQBjAGgAbwA=",
            "__FilterToConsumerBinding",
        ]);
        let out = parse_bytes(&bytes);
        assert!(out.is_wmi_repository);
        assert!(out
            .consumer_classes_found
            .contains(&"CommandLineEventConsumer".to_string()));
        assert_eq!(out.filter_count, 1);
        assert_eq!(out.binding_count, 1);
        assert!(out.persistence_pattern_present);
        assert!(out.command_strings.iter().any(|c| c.contains("powershell")));
    }

    #[test]
    fn script_consumer_surfaces_script_string() {
        let bytes = repo(&[
            "__EventFilter",
            "ActiveScriptEventConsumer",
            "ScriptText CreateObject(\"WScript.Shell\").Run",
            "__FilterToConsumerBinding",
        ]);
        let out = parse_bytes(&bytes);
        assert!(out
            .consumer_classes_found
            .contains(&"ActiveScriptEventConsumer".to_string()));
        assert!(out.persistence_pattern_present);
        assert!(out
            .script_strings
            .iter()
            .any(|s| s.contains("WScript.Shell")));
    }

    #[test]
    fn consumer_without_filter_or_binding_is_not_the_pattern() {
        let bytes = repo(&["CommandLineEventConsumer", "some other data here"]);
        let out = parse_bytes(&bytes);
        assert!(out.is_wmi_repository);
        assert!(
            !out.persistence_pattern_present,
            "no filter/binding present"
        );
    }

    #[test]
    fn non_wmi_bytes_return_falsy_without_error() {
        let bytes = repo(&["just some ordinary text", "nothing to see here at all"]);
        let out = parse_bytes(&bytes);
        assert!(!out.is_wmi_repository);
        assert!(out.consumer_classes_found.is_empty());
        assert!(!out.persistence_pattern_present);
    }

    #[test]
    fn empty_buffer_is_falsy() {
        let out = parse_bytes(&[]);
        assert!(!out.is_wmi_repository);
        assert_eq!(out.filter_count, 0);
    }

    #[test]
    fn output_vecs_are_sorted_and_deduped() {
        let bytes = repo(&[
            "__EventFilter",
            "ActiveScriptEventConsumer",
            "CommandLineEventConsumer",
            "CommandLineTemplate cmd.exe /c a",
            "CommandLineTemplate cmd.exe /c a",
            "__FilterToConsumerBinding",
        ]);
        let out = parse_bytes(&bytes);
        let mut sorted = out.consumer_classes_found.clone();
        sorted.sort();
        assert_eq!(out.consumer_classes_found, sorted);
        // Duplicate command deduped.
        let dupes = out
            .command_strings
            .iter()
            .filter(|c| c.contains("/c a"))
            .count();
        assert_eq!(dupes, 1);
    }
}
