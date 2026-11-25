//! `oe_dbx_parse` — read an Outlook Express `.dbx` message store.
//!
//! Outlook Express stores each mail/news folder as a `.dbx` file: a
//! `CF AD 12 FE`-signed message store. No other product parser reads it (plaso
//! has no DBX parser; `browser_history` is SQLite-only), so without this an OE
//! store is invisible to the pipeline.
//!
//! The full on-disk format is a B-tree of message-info nodes pointing at
//! segmented bodies; decoding that tree is error-prone, and a subtle misparse
//! would put WRONG content behind a Finding. This reader is deliberately
//! conservative: it validates the OE signature first, then extracts the
//! structured RFC822 headers (`Subject`/`From`/`Newsgroups`) the messages carry,
//! rejecting binary noise. Output is sorted/deduped — hence deterministic, so a
//! `verify_finding` replay reproduces the same bytes. This is a header-level
//! reader, not a full message reconstructor; it deliberately does not claim to
//! recover deleted bodies.
//!
//! Nothing here is image-specific: any OE `.dbx` from any host parses the same
//! way, and the hacking-newsgroup tokens are general DFIR signatures.

use std::collections::BTreeSet;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Little-endian `0xFE12ADCF` — the signature of every OE `.dbx` store.
const OE_DBX_MAGIC: [u8; 4] = [0xCF, 0xAD, 0x12, 0xFE];
/// 16-byte class GUID that marks a MESSAGE store (vs a `Folders.dbx` index).
const OE_MESSAGE_STORE_GUID: [u8; 16] = [
    0xC5, 0xFD, 0x74, 0x6F, 0x66, 0xE3, 0xD1, 0x11, 0x9A, 0x4E, 0x00, 0xC0, 0x4F, 0xA3, 0x09, 0xD4,
];

/// Upper bound on bytes read from one store. OE `.dbx` are small (tens of KB to
/// a few MB); the cap stops a pathological path from exhausting memory.
const MAX_BYTES: usize = 64 * 1024 * 1024;
/// Longest header value kept; longer is treated as noise, not a header.
const MAX_HEADER_LEN: usize = 300;
/// Cap on surfaced headers per kind so a huge store can't bloat output. Counts
/// are reported separately and are not capped.
const MAX_ITEMS: usize = 50;

/// Tokens that mark a newsgroup name as hacking/cracking/piracy oriented.
/// General DFIR signatures — not tied to any one image.
const HACKING_GROUP_TOKENS: &[&str] = &[
    "2600", "hack", "crack", "phreak", "warez", "cardz", "carding", "exploit", "malic", "dss.hack",
];

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OeDbxParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to an Outlook Express `.dbx` message store.
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct OeDbxParseOutput {
    /// True if the file carries the OE `.dbx` signature.
    pub is_oe_dbx: bool,
    /// True if it is a message store (vs a `Folders.dbx` index).
    pub is_message_store: bool,
    /// Count of parsed `Subject` headers — a lower bound on stored messages
    /// whose bodies were downloaded.
    pub message_subject_count: usize,
    /// Deduped, sorted message subjects (capped).
    pub subjects: Vec<String>,
    /// Deduped, sorted `From` values (capped).
    pub senders: Vec<String>,
    /// Deduped, sorted newsgroup names from `Newsgroups` headers (capped).
    pub newsgroups: Vec<String>,
    /// Subset of `newsgroups` that are hacking/cracking/piracy groups.
    pub hacking_newsgroups: Vec<String>,
}

#[derive(Debug, Error)]
pub enum OeDbxParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Parse an OE `.dbx` store's message headers.
///
/// # Errors
/// * [`OeDbxParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`OeDbxParseError::Read`] — IO error reading the file.
pub fn oe_dbx_parse(input: &OeDbxParseInput) -> Result<OeDbxParseOutput, OeDbxParseError> {
    if !input.artifact_path.exists() {
        return Err(OeDbxParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }
    let data = read_capped(&input.artifact_path)?;
    Ok(parse_bytes(&data))
}

fn read_capped(path: &std::path::Path) -> Result<Vec<u8>, OeDbxParseError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| OeDbxParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|source| OeDbxParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Pure parse over the raw bytes — unit-tested without IO.
fn parse_bytes(data: &[u8]) -> OeDbxParseOutput {
    if data.len() < 4 || data[0..4] != OE_DBX_MAGIC {
        return OeDbxParseOutput {
            is_oe_dbx: false,
            is_message_store: false,
            message_subject_count: 0,
            subjects: Vec::new(),
            senders: Vec::new(),
            newsgroups: Vec::new(),
            hacking_newsgroups: Vec::new(),
        };
    }
    let is_message_store = data.len() >= 20 && data[4..20] == OE_MESSAGE_STORE_GUID;
    let subjects = header_values(data, b"Subject");
    let senders = header_values(data, b"From");

    let mut newsgroups: BTreeSet<String> = BTreeSet::new();
    for line in header_values(data, b"Newsgroups") {
        for token in line.split(',') {
            let name = token.trim();
            if is_valid_newsgroup(name) {
                newsgroups.insert(name.to_string());
            }
        }
    }
    let hacking_newsgroups: Vec<String> = newsgroups
        .iter()
        .filter(|ng| {
            let low = ng.to_ascii_lowercase();
            HACKING_GROUP_TOKENS.iter().any(|tok| low.contains(tok))
        })
        .take(MAX_ITEMS)
        .cloned()
        .collect();

    OeDbxParseOutput {
        is_oe_dbx: true,
        is_message_store,
        message_subject_count: subjects.len(),
        subjects: dedup_sorted_capped(subjects),
        senders: dedup_sorted_capped(senders),
        newsgroups: newsgroups.into_iter().take(MAX_ITEMS).collect(),
        hacking_newsgroups,
    }
}

/// Every clean RFC822 `<field>:` value in the store, in file order.
///
/// A header is anchored at a line start: file start, a newline, OR a NUL — OE
/// pads segment boundaries with NULs, so a message's first header line is often
/// preceded by `\0` rather than `\n`. Only printable-ASCII values are kept, so a
/// false match this looser anchor lets through is dropped.
fn header_values(data: &[u8], field: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let n = data.len();
    let flen = field.len();
    let mut i = 0usize;
    while i + flen < n {
        let anchored = i == 0 || matches!(data[i - 1], b'\n' | b'\r' | 0);
        if anchored && data[i..i + flen] == *field && data[i + flen] == b':' {
            let mut j = i + flen + 1;
            while j < n && (data[j] == b' ' || data[j] == b'\t') {
                j += 1;
            }
            let start = j;
            while j < n && data[j] != b'\r' && data[j] != b'\n' {
                j += 1;
            }
            let raw = &data[start..j];
            if !raw.is_empty()
                && raw.len() <= MAX_HEADER_LEN
                && raw.iter().all(|&b| (0x20..=0x7e).contains(&b))
            {
                // SAFETY of unwrap: just verified every byte is printable ASCII.
                let value = std::str::from_utf8(raw).unwrap_or("").trim();
                if !value.is_empty() {
                    out.push(value.to_string());
                }
            }
            i = j.max(i + 1);
            continue;
        }
        i += 1;
    }
    out
}

/// A valid Usenet group name: dot-separated tokens, >= 2 segments, first char
/// alphanumeric, each segment from `[a-z0-9+_-]`. Anchored shape rejects tokens
/// carrying NUL / control bytes (raw B-tree pointer noise next to the text).
fn is_valid_newsgroup(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return false;
    }
    let mut segments = 0usize;
    for seg in name.split('.') {
        if seg.is_empty()
            || !seg.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'_' | b'-')
            })
        {
            return false;
        }
        segments += 1;
    }
    segments >= 2
}

fn dedup_sorted_capped(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_ITEMS)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(messages: &[&[u8]], guid: [u8; 16]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&OE_DBX_MAGIC);
        out.extend_from_slice(&guid);
        out.extend_from_slice(&[0u8; 0xB0]); // header padding (content is what we read)
        for m in messages {
            out.extend_from_slice(m);
        }
        out
    }

    fn msg(subject: &str, sender: &str, newsgroups: &str) -> Vec<u8> {
        format!("From: {sender}\r\nNewsgroups: {newsgroups}\r\nSubject: {subject}\r\n\r\nbody\r\n")
            .into_bytes()
    }

    #[test]
    fn non_dbx_returns_falsy_shape() {
        let out = parse_bytes(b"not a dbx file at all");
        assert!(!out.is_oe_dbx);
        assert!(!out.is_message_store);
        assert!(out.subjects.is_empty() && out.newsgroups.is_empty());
    }

    #[test]
    fn signature_and_message_store_guid_detected() {
        let s = store(&[&msg("hi", "a@b", "alt.hacking")], OE_MESSAGE_STORE_GUID);
        let out = parse_bytes(&s);
        assert!(out.is_oe_dbx);
        assert!(out.is_message_store);
    }

    #[test]
    fn folders_store_guid_is_oe_but_not_message_store() {
        let out = parse_bytes(&store(&[], [0u8; 16]));
        assert!(out.is_oe_dbx);
        assert!(!out.is_message_store);
    }

    #[test]
    fn extracts_subjects_senders_newsgroups() {
        let s = store(
            &[
                &msg(
                    "How to hack hotmail",
                    "evil@example.com",
                    "alt.2600.hackerz",
                ),
                &msg(
                    "Bios Password Hacking",
                    "mr@evil.net",
                    "alt.hacking,alt.dss.hack",
                ),
            ],
            OE_MESSAGE_STORE_GUID,
        );
        let out = parse_bytes(&s);
        assert_eq!(out.message_subject_count, 2);
        assert!(out.subjects.contains(&"How to hack hotmail".to_string()));
        assert!(out.senders.contains(&"evil@example.com".to_string()));
        assert_eq!(
            out.newsgroups,
            vec![
                "alt.2600.hackerz".to_string(),
                "alt.dss.hack".to_string(),
                "alt.hacking".to_string()
            ]
        );
    }

    #[test]
    fn binary_noise_newsgroup_token_is_filtered() {
        let mut noisy = Vec::new();
        noisy.extend_from_slice(&OE_DBX_MAGIC);
        noisy.extend_from_slice(&OE_MESSAGE_STORE_GUID);
        noisy.extend_from_slice(&[0u8; 0xB0]);
        noisy.extend_from_slice(b"Newsgroups: alt\x00+\x04.dss.hack\r\nSubject: x\r\n");
        noisy.extend_from_slice(&msg("clean", "a@b", "alt.2600.crackz"));
        let out = parse_bytes(&noisy);
        assert_eq!(out.newsgroups, vec!["alt.2600.crackz".to_string()]);
    }

    #[test]
    fn output_is_sorted_deduped_and_deterministic() {
        let s = store(
            &[
                &msg("dup", "a@b", "alt.hacking"),
                &msg("dup", "a@b", "alt.hacking"),
                &msg("aaa", "z@z", "alt.2600.hackerz"),
            ],
            OE_MESSAGE_STORE_GUID,
        );
        let out = parse_bytes(&s);
        assert_eq!(out.subjects, vec!["aaa".to_string(), "dup".to_string()]);
        assert_eq!(
            out.newsgroups,
            vec!["alt.2600.hackerz".to_string(), "alt.hacking".to_string()]
        );
        assert_eq!(parse_bytes(&s).subjects, out.subjects); // determinism
    }

    #[test]
    fn hacking_newsgroups_flags_only_hacking_groups() {
        let s = store(
            &[
                &msg("a", "x@y", "alt.2600.hackerz"),
                &msg("b", "x@y", "alt.binaries.hacking.beginner"),
                &msg("c", "x@y", "alt.cracks"),
                &msg("d", "x@y", "rec.video.desktop.toaster"),
                &msg("e", "x@y", "comp.lang.python"),
            ],
            OE_MESSAGE_STORE_GUID,
        );
        let out = parse_bytes(&s);
        assert_eq!(
            out.hacking_newsgroups,
            vec![
                "alt.2600.hackerz".to_string(),
                "alt.binaries.hacking.beginner".to_string(),
                "alt.cracks".to_string(),
            ]
        );
    }
}
