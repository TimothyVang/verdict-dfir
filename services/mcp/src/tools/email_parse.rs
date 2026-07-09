//! `email_parse` — read a standalone RFC 5322 email (`.eml`) or an `mbox`
//! archive of many messages.
//!
//! A `.eml` file is a single RFC 5322 message (headers + optional MIME body); an
//! `mbox` file is a flat archive of many such messages, each introduced by an
//! mbox `From ` separator line. No other product parser reads loose mail on disk
//! (`oe_dbx_parse` is Outlook-Express-only; `browser_history` is SQLite-only), so
//! without this a dropped `.eml`/`mbox` is invisible to the pipeline.
//!
//! This reader is deliberately conservative. It surfaces only the DFIR-relevant
//! *metadata* a message carries — the `From`/`To` addresses, `Subject`, `Date`,
//! and the *names* of any attachments — and it counts how many messages the
//! archive holds. It NEVER decodes an attachment or a body, and it NEVER writes
//! any body or attachment payload to disk: the attachment surface is the filename
//! and the message's own attachment count, nothing more. Output is
//! sorted/deduped and free of any wall-clock or random input, so it is
//! deterministic — a `verify_finding` replay reproduces the same bytes.
//!
//! Nothing here is image-specific: any mailbox from any host parses the same way.
//! There are no hard-coded addresses, subjects, hostnames, or per-image tokens —
//! detection keys only on the general RFC 5322 / mbox structure.

use std::collections::BTreeSet;
use std::path::PathBuf;

use mail_parser::{Addr, Address, Message, MessageParser, MimeHeaders};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The mbox message separator: a line beginning with `From ` (note the space,
/// which distinguishes it from an RFC 5322 `From:` header).
const MBOX_FROM: &[u8] = b"From ";

/// Upper bound on bytes read from one artifact. Loose `.eml` are small; an mbox
/// can be large, so the cap is generous but still bounds memory. Anything past
/// the cap is truncated rather than read.
const MAX_BYTES: usize = 256 * 1024 * 1024;
/// Cap on the number of mbox messages actually parsed. The true total message
/// count is reported separately and is never capped.
const MAX_MESSAGES: usize = 5_000;
/// Cap on the length of any surfaced Vec so a huge mailbox cannot bloat output.
/// Counts are reported separately and are not capped.
const MAX_ITEMS: usize = 200;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmailParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to a `.eml` message or an `mbox` archive.
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct MessageSummary {
    /// First `From` address (email preferred, display name as fallback).
    pub from: Option<String>,
    /// Deduped, sorted `To` addresses.
    pub to: Vec<String>,
    /// `Subject`, if present.
    pub subject: Option<String>,
    /// `Date` rendered as RFC 3339, if present.
    pub date: Option<String>,
    /// Deduped, sorted attachment file names (metadata only — no payload).
    pub attachment_names: Vec<String>,
    /// Total attachment parts on this message, including any without a name.
    pub attachment_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct EmailParseOutput {
    /// True if at least one parseable email message was found. False (without an
    /// error) when the bytes are not email at all.
    pub is_email: bool,
    /// `"eml"` for a single message, `"mbox"` for a `From `-separated archive.
    pub format: String,
    /// True total messages found (uncapped). For `mbox` this is the number of
    /// `From ` separators; for `eml` it is 0 or 1.
    pub message_count: usize,
    /// Per-message summaries, in file order (capped at `MAX_ITEMS`).
    pub messages: Vec<MessageSummary>,
    /// Deduped, sorted unique sender addresses across all messages (capped).
    pub unique_senders: Vec<String>,
    /// Deduped, sorted unique recipient addresses across all messages (capped).
    pub unique_recipients: Vec<String>,
    /// Deduped, sorted unique subjects across all messages (capped).
    pub subjects: Vec<String>,
    /// Deduped, sorted unique attachment names across all messages (capped).
    pub attachment_names: Vec<String>,
}

#[derive(Debug, Error)]
pub enum EmailParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Parse a `.eml` message or an `mbox` archive into header/attachment metadata.
///
/// # Errors
/// * [`EmailParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`EmailParseError::Read`] — IO error reading the file.
pub fn email_parse(input: &EmailParseInput) -> Result<EmailParseOutput, EmailParseError> {
    if !input.artifact_path.exists() {
        return Err(EmailParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }
    let data = read_capped(&input.artifact_path)?;
    Ok(parse_bytes(&data))
}

fn read_capped(path: &std::path::Path) -> Result<Vec<u8>, EmailParseError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| EmailParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|source| EmailParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Pure parse over the raw bytes — unit-tested without IO.
fn parse_bytes(data: &[u8]) -> EmailParseOutput {
    let starts = mbox_message_starts(data);
    if starts.is_empty() {
        parse_single(data)
    } else {
        parse_mbox(data, &starts)
    }
}

/// Byte offsets of every mbox `From ` separator (line start). Empty for a single
/// `.eml`, whose leading line is a `From:` header (colon, not space).
fn mbox_message_starts(data: &[u8]) -> Vec<usize> {
    let mut starts = Vec::new();
    let n = data.len();
    let mut i = 0usize;
    while i < n {
        let at_line_start = i == 0 || data[i - 1] == b'\n';
        if at_line_start && data[i] == b'F' && data[i..].starts_with(MBOX_FROM) {
            starts.push(i);
        }
        i += 1;
    }
    starts
}

fn parse_single(data: &[u8]) -> EmailParseOutput {
    let messages: Vec<MessageSummary> = MessageParser::default()
        .parse(data)
        .and_then(|msg| summarize(&msg))
        .into_iter()
        .collect();
    build_output("eml", messages.len(), messages)
}

fn parse_mbox(data: &[u8], starts: &[usize]) -> EmailParseOutput {
    let total = starts.len();
    let mut messages = Vec::new();
    for (idx, &start) in starts.iter().enumerate() {
        if idx >= MAX_MESSAGES {
            break;
        }
        let end = starts.get(idx + 1).copied().unwrap_or(data.len());
        let chunk = strip_mbox_from_line(&data[start..end]);
        let summary = MessageParser::default()
            .parse(chunk)
            .and_then(|msg| summarize(&msg));
        if let Some(summary) = summary {
            messages.push(summary);
        }
    }
    build_output("mbox", total, messages)
}

/// Drop the leading mbox `From ` separator line so what remains is a clean
/// RFC 5322 message (headers first). Leaves a chunk without one untouched.
fn strip_mbox_from_line(chunk: &[u8]) -> &[u8] {
    if chunk.starts_with(MBOX_FROM) {
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            return &chunk[pos + 1..];
        }
    }
    chunk
}

/// Reduce a parsed message to its DFIR metadata. Returns `None` when the message
/// carries none of the email-defining fields (so raw noise is not counted).
fn summarize(msg: &Message<'_>) -> Option<MessageSummary> {
    let from = addresses(msg.from()).into_iter().next();
    let to = dedup_sorted(addresses(msg.to()));
    let subject = msg
        .subject()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let date = msg.date().map(mail_parser::DateTime::to_rfc3339);

    let mut names: Vec<String> = Vec::new();
    let mut attachment_count = 0usize;
    for part in msg.attachments() {
        attachment_count += 1;
        if let Some(name) = part.attachment_name() {
            let trimmed = name.trim();
            if !trimmed.is_empty() {
                names.push(trimmed.to_string());
            }
        }
    }
    let attachment_names = dedup_sorted(names);

    if from.is_none()
        && to.is_empty()
        && subject.is_none()
        && date.is_none()
        && attachment_count == 0
    {
        return None;
    }
    Some(MessageSummary {
        from,
        to,
        subject,
        date,
        attachment_names,
        attachment_count,
    })
}

/// Every non-empty address in a header field, email preferred over display name.
fn addresses(field: Option<&Address<'_>>) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(address) = field {
        for addr in address.iter() {
            if let Some(value) = addr_string(addr) {
                out.push(value);
            }
        }
    }
    out
}

fn addr_string(addr: &Addr<'_>) -> Option<String> {
    if let Some(email) = addr.address() {
        let trimmed = email.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Some(name) = addr.name() {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn build_output(
    format: &str,
    message_count: usize,
    messages: Vec<MessageSummary>,
) -> EmailParseOutput {
    let mut senders: BTreeSet<String> = BTreeSet::new();
    let mut recipients: BTreeSet<String> = BTreeSet::new();
    let mut subjects: BTreeSet<String> = BTreeSet::new();
    let mut attachment_names: BTreeSet<String> = BTreeSet::new();
    for m in &messages {
        if let Some(from) = &m.from {
            senders.insert(from.clone());
        }
        for to in &m.to {
            recipients.insert(to.clone());
        }
        if let Some(subject) = &m.subject {
            subjects.insert(subject.clone());
        }
        for name in &m.attachment_names {
            attachment_names.insert(name.clone());
        }
    }
    EmailParseOutput {
        is_email: !messages.is_empty(),
        format: format.to_string(),
        message_count,
        messages: messages.into_iter().take(MAX_ITEMS).collect(),
        unique_senders: cap_set(senders),
        unique_recipients: cap_set(recipients),
        subjects: cap_set(subjects),
        attachment_names: cap_set(attachment_names),
    }
}

fn cap_set(set: BTreeSet<String>) -> Vec<String> {
    set.into_iter().take(MAX_ITEMS).collect()
}

fn dedup_sorted(values: Vec<String>) -> Vec<String> {
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

    #[test]
    fn single_eml_parses_headers() {
        let raw = "From: alice@example.com\r\n\
             To: bob@example.com\r\n\
             Subject: Quarterly report\r\n\
             Date: Wed, 25 Aug 2004 12:00:00 +0000\r\n\
             \r\n\
             Hello, this is the body.\r\n";
        let out = parse_bytes(raw.as_bytes());
        assert!(out.is_email);
        assert_eq!(out.format, "eml");
        assert_eq!(out.message_count, 1);
        assert_eq!(out.messages.len(), 1);
        assert_eq!(out.messages[0].from.as_deref(), Some("alice@example.com"));
        assert_eq!(out.messages[0].subject.as_deref(), Some("Quarterly report"));
        assert!(out
            .unique_senders
            .contains(&"alice@example.com".to_string()));
        assert!(out
            .unique_recipients
            .contains(&"bob@example.com".to_string()));
    }

    #[test]
    fn mbox_with_two_messages_counts_both() {
        let raw = "From alice@example.com Wed Aug 25 12:00:00 2004\r\n\
             From: alice@example.com\r\n\
             Subject: one\r\n\
             \r\n\
             body one\r\n\
             From bob@example.net Wed Aug 25 13:00:00 2004\r\n\
             From: bob@example.net\r\n\
             Subject: two\r\n\
             \r\n\
             body two\r\n";
        let out = parse_bytes(raw.as_bytes());
        assert_eq!(out.format, "mbox");
        assert_eq!(out.message_count, 2);
        assert_eq!(
            out.unique_senders,
            vec![
                "alice@example.com".to_string(),
                "bob@example.net".to_string()
            ]
        );
    }

    #[test]
    fn eml_with_attachment_surfaces_name_not_payload() {
        let raw = "From: alice@example.com\r\n\
             To: bob@example.com\r\n\
             Subject: with attachment\r\n\
             MIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=\"BOUND\"\r\n\
             \r\n\
             --BOUND\r\n\
             Content-Type: text/plain\r\n\
             \r\n\
             body text here\r\n\
             --BOUND\r\n\
             Content-Type: application/zip\r\n\
             Content-Disposition: attachment; filename=\"x.zip\"\r\n\
             Content-Transfer-Encoding: base64\r\n\
             \r\n\
             UEsDBAoAAAAAAA==\r\n\
             --BOUND--\r\n";
        let out = parse_bytes(raw.as_bytes());
        assert!(out.is_email);
        assert!(out.attachment_names.contains(&"x.zip".to_string()));
        assert!(out.messages[0].attachment_count >= 1);
        // The decoded/encoded payload bytes must never appear in output.
        let rendered = format!("{out:?}");
        assert!(!rendered.contains("UEsDBAo"));
        assert!(!rendered.contains("body text here"));
    }

    #[test]
    fn random_non_email_bytes_is_not_email_without_error() {
        let out = parse_bytes(b"\x00\x01\x02\x03 just some random noise \xff\xfe not mail");
        assert!(!out.is_email);
        assert!(out.messages.is_empty());
        assert_eq!(out.message_count, 0);
    }

    #[test]
    fn aggregate_vecs_are_sorted_and_deduped() {
        let raw = "From zoe@example.com Wed Aug 25 12:00:00 2004\r\n\
             From: zoe@example.com\r\n\
             Subject: zeta\r\n\
             \r\n\
             one\r\n\
             From alice@example.com Wed Aug 25 13:00:00 2004\r\n\
             From: alice@example.com\r\n\
             Subject: alpha\r\n\
             \r\n\
             two\r\n\
             From zoe@example.com Wed Aug 25 14:00:00 2004\r\n\
             From: zoe@example.com\r\n\
             Subject: zeta\r\n\
             \r\n\
             three\r\n";
        let out = parse_bytes(raw.as_bytes());
        assert_eq!(out.message_count, 3);
        // Sorted ascending and de-duplicated (zoe appears twice).
        assert_eq!(
            out.unique_senders,
            vec![
                "alice@example.com".to_string(),
                "zoe@example.com".to_string()
            ]
        );
        assert_eq!(out.subjects, vec!["alpha".to_string(), "zeta".to_string()]);
        let mut sorted = out.unique_senders.clone();
        sorted.sort();
        assert_eq!(out.unique_senders, sorted);
        // Deterministic replay.
        assert_eq!(
            parse_bytes(raw.as_bytes()).unique_senders,
            out.unique_senders
        );
    }
}
