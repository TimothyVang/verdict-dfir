//! `thumbcache_parse` — read a Windows thumbnail cache.
//!
//! Windows keeps thumbnails of images the shell has rendered, and those
//! thumbnails outlive the originals: a catalog row plus a cached bitmap is the
//! canonical "an image file existed / was viewed here" artifact even after the
//! file itself was deleted. Two on-disk formats exist and this tool reads both:
//!
//! * **XP `Thumbs.db`** — an OLE/CFB compound file. The `Catalog` stream holds
//!   {entry size, index, original-file FILETIME, original filename UTF-16LE}
//!   rows; each row's thumbnail lives in a stream whose name is the decimal
//!   index reversed (index 12 → stream "21").
//! * **Vista+ `thumbcache_*.db` / `iconcache_*.db`** — a flat `CMMM` record
//!   file (format documented by the `thumbcache_viewer` project). Each record
//!   carries a 64-bit cache-entry hash, an identifier string, and the raw
//!   image payload. The version field selects the record layout (Vista adds a
//!   wide-char extension; Win8+ adds width/height).
//!
//! Output discipline: no raw image bytes are returned — only sizes and
//! SHA-256 digests of the embedded payloads, so a recovered thumbnail can be
//! corroborated byte-for-byte without bloating the audit chain. Entries are
//! sorted by (index, cache entry hash) and carry no wall-clock values, so a
//! `verify_finding` replay reproduces the same bytes. Truncated or corrupt
//! tails stop the scan cleanly and are recorded in `parse_errors` — never a
//! panic. Format detection is by magic bytes, never by filename.
//!
//! Nothing here is image-specific: any thumbnail cache from any host parses
//! the same way.

use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// OLE/CFB compound-file signature (`D0 CF 11 E0 A1 B1 1A E1`).
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
/// Vista+ thumbcache file/record signature.
const CMMM_MAGIC: [u8; 4] = *b"CMMM";

/// Refuse anything larger than this — a thumbnail cache is small; a huge file
/// at this path is either not a cache or a decompression-bomb-style hazard.
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;

/// Default cap on returned entries when the input omits `limit`.
const DEFAULT_LIMIT: usize = 500;
/// Hard cap on records scanned per file so a pathological cache cannot
/// exhaust memory; hitting it is recorded in `parse_errors`.
const MAX_SCANNED_ENTRIES: usize = 100_000;

/// CMMM version values (`thumbcache_viewer`): Vista = 0x14, Win7 = 0x15,
/// Win8 and later = 0x1A..; the record layout is keyed off these.
const CMMM_VERSION_VISTA: u32 = 0x14;
const CMMM_VERSION_WIN7: u32 = 0x15;
const CMMM_VERSION_WIN8_MIN: u32 = 0x1A;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ThumbcacheParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to one thumbnail cache file: an XP `Thumbs.db` or a Vista+
    /// `thumbcache_*.db` / `iconcache_*.db`. Format is detected by magic.
    pub thumbcache_path: PathBuf,
    /// Maximum entries returned (post-sort). Defaults to 500.
    #[serde(default = "default_limit")]
    pub limit: usize,
}

const fn default_limit() -> usize {
    DEFAULT_LIMIT
}

#[derive(Clone, Debug, Serialize)]
pub struct ThumbcacheParseOutput {
    /// Echo of the input `case_id`.
    pub case_id: String,
    /// Echo of the input path.
    pub thumbcache_path: PathBuf,
    /// Detected on-disk format: `olecfb_xp` (XP `Thumbs.db`) or `cmmm`
    /// (Vista+ `thumbcache_*.db` / `iconcache_*.db`).
    pub format: String,
    /// Parsed entries, sorted by (index, cache entry hash) and capped at
    /// `limit`. Raw image bytes are never included.
    pub entries: Vec<ThumbcacheEntry>,
    /// Entries parsed before the `limit` cap (empty/deallocated CMMM slots
    /// are not counted).
    pub entries_seen: usize,
    /// Non-fatal parse notes: truncated tails, bad record magic, missing
    /// thumbnail streams. Never carries evidence content.
    pub parse_errors: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThumbcacheEntry {
    /// XP catalog index (`None` for CMMM records).
    pub index: Option<u32>,
    /// Vista+ 64-bit cache entry hash as 16-char lowercase hex (`None` for
    /// XP catalog rows).
    pub cache_entry_hash: Option<String>,
    /// Original file name from the XP catalog (`None` for CMMM — the Vista+
    /// format stores no filename; the mapping lives in `Windows.edb`).
    pub original_filename: Option<String>,
    /// Original file's modification FILETIME from the XP catalog as UTC
    /// ISO-8601 with trailing `Z` (`None` for CMMM — the format carries no
    /// timestamps).
    pub modified_iso: Option<String>,
    /// Size in bytes of the embedded thumbnail payload (0 when absent).
    pub data_size_bytes: u64,
    /// SHA-256 hex of the embedded thumbnail bytes; `None` when the payload
    /// is empty or not fully present in the file.
    pub content_sha256: Option<String>,
}

#[derive(Debug, Error)]
pub enum ThumbcacheParseError {
    #[error("thumbcache not found: {0}")]
    NotFound(PathBuf),
    #[error("thumbcache path is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("thumbcache too large: {size_bytes} bytes exceeds the {max_bytes}-byte cap: {path}")]
    TooLarge {
        path: PathBuf,
        size_bytes: u64,
        max_bytes: u64,
    },
    #[error(
        "not a thumbnail cache (magic is neither OLE/CFB nor CMMM, \
         or the OLE file has no Catalog stream): {0}"
    )]
    NotThumbcache(PathBuf),
    #[error("could not read thumbcache {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// True if the file name looks like a Windows thumbnail cache. Advisory
/// routing only — `thumbcache_parse` itself detects the format by magic.
#[must_use]
pub fn path_looks_like_thumbcache(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let has_db_ext = Path::new(&lower)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("db"));
    lower == "thumbs.db"
        || ((lower.starts_with("thumbcache_") || lower.starts_with("iconcache_")) && has_db_ext)
}

/// Parse a Windows thumbnail cache (XP OLE/CFB or Vista+ CMMM).
///
/// # Errors
/// * [`ThumbcacheParseError::NotFound`] — `thumbcache_path` missing.
/// * [`ThumbcacheParseError::NotRegular`] — path is not a regular file.
/// * [`ThumbcacheParseError::TooLarge`] — file exceeds the 512 MiB cap.
/// * [`ThumbcacheParseError::NotThumbcache`] — unrecognized magic, or an OLE
///   file without a `Catalog` stream.
/// * [`ThumbcacheParseError::Read`] — IO error reading the file.
pub fn thumbcache_parse(
    input: &ThumbcacheParseInput,
) -> Result<ThumbcacheParseOutput, ThumbcacheParseError> {
    let path = &input.thumbcache_path;
    let meta = std::fs::metadata(path).map_err(|_| ThumbcacheParseError::NotFound(path.clone()))?;
    if !meta.is_file() {
        return Err(ThumbcacheParseError::NotRegular(path.clone()));
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(ThumbcacheParseError::TooLarge {
            path: path.clone(),
            size_bytes: meta.len(),
            max_bytes: MAX_FILE_BYTES,
        });
    }
    let data = std::fs::read(path).map_err(|source| ThumbcacheParseError::Read {
        path: path.clone(),
        source,
    })?;

    let mut parsed =
        parse_bytes(&data).ok_or_else(|| ThumbcacheParseError::NotThumbcache(path.clone()))?;

    parsed.entries.sort_by(|a, b| {
        a.index
            .cmp(&b.index)
            .then_with(|| a.cache_entry_hash.cmp(&b.cache_entry_hash))
            .then_with(|| a.original_filename.cmp(&b.original_filename))
    });
    let entries_seen = parsed.entries.len();
    parsed.entries.truncate(input.limit);

    Ok(ThumbcacheParseOutput {
        case_id: input.case_id.clone(),
        thumbcache_path: path.clone(),
        format: parsed.format.to_string(),
        entries: parsed.entries,
        entries_seen,
        parse_errors: parsed.parse_errors,
    })
}

/// Intermediate parse result before sorting / limiting.
struct ParsedCache {
    format: &'static str,
    entries: Vec<ThumbcacheEntry>,
    parse_errors: Vec<String>,
}

/// Detect the format by magic and parse. `None` means the bytes are not a
/// recognizable thumbnail cache.
fn parse_bytes(data: &[u8]) -> Option<ParsedCache> {
    if data.len() >= CFB_MAGIC.len() && data[..CFB_MAGIC.len()] == CFB_MAGIC {
        return parse_olecfb(data);
    }
    if data.len() >= CMMM_MAGIC.len() && data[..CMMM_MAGIC.len()] == CMMM_MAGIC {
        return Some(parse_cmmm(data));
    }
    None
}

// ---------------------------------------------------------------------------
// Vista+ flat CMMM format
// ---------------------------------------------------------------------------

/// Per-version CMMM record geometry: byte offsets are relative to the start
/// of the record (magic at 0, record size u32 at 4, entry hash u64 at 8).
struct CmmmLayout {
    /// Offset of the identifier-string length field (u32, bytes).
    id_len_off: usize,
    /// Offset of the padding-size field (u32); data size follows at +4.
    padding_off: usize,
    /// Total fixed-header length; identifier string starts here.
    header_len: usize,
}

const fn cmmm_layout(version: u32) -> Option<CmmmLayout> {
    match version {
        // Vista: 8-byte wide-char extension between the hash and the lengths.
        CMMM_VERSION_VISTA => Some(CmmmLayout {
            id_len_off: 24,
            padding_off: 28,
            header_len: 56,
        }),
        // Win7: no extension field.
        CMMM_VERSION_WIN7 => Some(CmmmLayout {
            id_len_off: 16,
            padding_off: 20,
            header_len: 48,
        }),
        // Win8 / 8.1 / 10: width + height + unknown after the data size.
        v if v >= CMMM_VERSION_WIN8_MIN => Some(CmmmLayout {
            id_len_off: 16,
            padding_off: 20,
            header_len: 56,
        }),
        _ => None,
    }
}

#[allow(clippy::too_many_lines)]
fn parse_cmmm(data: &[u8]) -> ParsedCache {
    let mut entries: Vec<ThumbcacheEntry> = Vec::new();
    let mut parse_errors: Vec<String> = Vec::new();

    let done = |entries, parse_errors| ParsedCache {
        format: "cmmm",
        entries,
        parse_errors,
    };

    let Some(version) = read_u32(data, 4) else {
        parse_errors.push("file header truncated before the version field".to_string());
        return done(entries, parse_errors);
    };
    let Some(layout) = cmmm_layout(version) else {
        parse_errors.push(format!("unsupported CMMM version {version}; stopping"));
        return done(entries, parse_errors);
    };
    // File header: magic, version, cache type, then (Win8+ only) an extra
    // unknown u32, then the first-cache-entry offset.
    let first_entry_field = if version >= CMMM_VERSION_WIN8_MIN {
        16
    } else {
        12
    };
    let Some(first_entry) = read_u32(data, first_entry_field) else {
        parse_errors.push("file header truncated before the first-entry offset".to_string());
        return done(entries, parse_errors);
    };
    let Ok(mut offset) = usize::try_from(first_entry) else {
        parse_errors.push("first-entry offset does not fit in memory".to_string());
        return done(entries, parse_errors);
    };
    if offset < first_entry_field + 4 || offset > data.len() {
        parse_errors.push(format!(
            "first-entry offset {offset} is outside the file; stopping"
        ));
        return done(entries, parse_errors);
    }

    let mut scanned = 0_usize;
    while offset + 4 <= data.len() {
        if scanned >= MAX_SCANNED_ENTRIES {
            parse_errors.push(format!(
                "record scan capped at {MAX_SCANNED_ENTRIES} records"
            ));
            break;
        }
        let magic = &data[offset..offset + 4];
        if magic == [0u8; 4] {
            // Zero fill after the last allocated record — clean end.
            break;
        }
        if *magic != CMMM_MAGIC {
            parse_errors.push(format!(
                "record at offset {offset}: bad record magic; stopping"
            ));
            break;
        }
        let Some(record_size) = read_u32(data, offset + 4).and_then(|s| usize::try_from(s).ok())
        else {
            parse_errors.push(format!(
                "record at offset {offset}: truncated before the size field; stopping"
            ));
            break;
        };
        if record_size < layout.header_len {
            parse_errors.push(format!(
                "record at offset {offset}: declared size {record_size} is smaller than \
                 the fixed header; stopping"
            ));
            break;
        }
        let record_end = offset.saturating_add(record_size);
        let truncated_record = record_end > data.len();
        if offset + layout.header_len > data.len() {
            parse_errors.push(format!(
                "record at offset {offset}: fixed header extends past end of file; stopping"
            ));
            break;
        }
        scanned += 1;

        // Fixed fields — all guaranteed in-bounds by the header_len check.
        let entry_hash = read_u64(data, offset + 8).unwrap_or(0);
        let id_len = read_u32(data, offset + layout.id_len_off)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        let padding = read_u32(data, offset + layout.padding_off)
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(0);
        let data_size = read_u32(data, offset + layout.padding_off + 4).unwrap_or(0);

        // Skip deallocated / placeholder slots so they cannot crowd real
        // entries out of the limit window.
        if entry_hash == 0 && data_size == 0 {
            if truncated_record {
                parse_errors.push(format!(
                    "record at offset {offset}: extends past end of file; stopping"
                ));
                break;
            }
            offset = record_end;
            continue;
        }

        let payload_start = offset + layout.header_len + id_len + padding;
        let payload_len = usize::try_from(data_size).unwrap_or(usize::MAX);
        let payload_end = payload_start.saturating_add(payload_len);
        let content_sha256 = if data_size > 0 && payload_end <= data.len() {
            Some(sha256_hex(&data[payload_start..payload_end]))
        } else {
            if data_size > 0 {
                parse_errors.push(format!(
                    "record at offset {offset}: payload truncated; digest omitted"
                ));
            }
            None
        };

        entries.push(ThumbcacheEntry {
            index: None,
            cache_entry_hash: Some(format!("{entry_hash:016x}")),
            original_filename: None,
            modified_iso: None,
            data_size_bytes: u64::from(data_size),
            content_sha256,
        });

        if truncated_record {
            parse_errors.push(format!(
                "record at offset {offset}: extends past end of file; stopping"
            ));
            break;
        }
        offset = record_end;
    }

    done(entries, parse_errors)
}

// ---------------------------------------------------------------------------
// XP Thumbs.db (OLE/CFB compound file)
// ---------------------------------------------------------------------------

/// Parse an XP `Thumbs.db`. Returns `None` when the compound file opens but
/// carries no `Catalog` stream — a valid OLE file that is not a thumbnail
/// cache (e.g. an Office document).
fn parse_olecfb(data: &[u8]) -> Option<ParsedCache> {
    let mut entries: Vec<ThumbcacheEntry> = Vec::new();
    let mut parse_errors: Vec<String> = Vec::new();

    let Ok(mut compound) = cfb::CompoundFile::open(Cursor::new(data)) else {
        // CFB magic but the container is corrupt: still a (broken) cache
        // candidate — surface the condition instead of misclassifying.
        return Some(ParsedCache {
            format: "olecfb_xp",
            entries,
            parse_errors: vec![
                "OLE compound file failed to open (corrupt or truncated container)".to_string(),
            ],
        });
    };
    if !compound.is_stream("/Catalog") {
        return None;
    }
    let mut catalog = Vec::new();
    if let Err(e) = compound
        .open_stream("/Catalog")
        .and_then(|mut s| s.read_to_end(&mut catalog))
    {
        parse_errors.push(format!("Catalog stream unreadable: {e}"));
        return Some(ParsedCache {
            format: "olecfb_xp",
            entries,
            parse_errors,
        });
    }

    // Catalog header: u16 header size (16), u16 version, u32 declared entry
    // count, u32 thumbnail width, u32 thumbnail height.
    let header_size = catalog
        .get(0..2)
        .map_or(0, |b| usize::from(u16::from_le_bytes([b[0], b[1]])));
    if !(16..=64).contains(&header_size) || header_size > catalog.len() {
        parse_errors.push("Catalog header malformed; stopping".to_string());
        return Some(ParsedCache {
            format: "olecfb_xp",
            entries,
            parse_errors,
        });
    }
    let declared_count = read_u32(&catalog, 4).unwrap_or(0);

    let mut pos = header_size;
    while pos + 16 <= catalog.len() && entries.len() < MAX_SCANNED_ENTRIES {
        let Some(entry_size) = read_u32(&catalog, pos).and_then(|s| usize::try_from(s).ok()) else {
            break;
        };
        if entry_size < 16 || pos + entry_size > catalog.len() {
            parse_errors.push(format!(
                "catalog entry at offset {pos}: truncated or undersized; stopping"
            ));
            break;
        }
        let index = read_u32(&catalog, pos + 4).unwrap_or(0);
        let modified_iso = read_u64(&catalog, pos + 8).and_then(filetime_to_iso);
        let original_filename = utf16le_until_nul(&catalog[pos + 16..pos + entry_size]);

        let (data_size_bytes, content_sha256) = match read_thumbnail_stream(&mut compound, index) {
            Some(payload) if payload.is_empty() => (0, None),
            Some(payload) => (
                u64::try_from(payload.len()).unwrap_or(u64::MAX),
                Some(sha256_hex(&payload)),
            ),
            None => {
                parse_errors.push(format!("no thumbnail stream for catalog index {index}"));
                (0, None)
            }
        };

        entries.push(ThumbcacheEntry {
            index: Some(index),
            cache_entry_hash: None,
            original_filename: Some(original_filename),
            modified_iso,
            data_size_bytes,
            content_sha256,
        });
        pos += entry_size;
    }
    if pos < catalog.len() && catalog[pos..].iter().any(|&b| b != 0) {
        parse_errors.push(format!(
            "catalog carries unparsed trailing bytes after offset {pos}"
        ));
    }
    let parsed_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    if declared_count != parsed_count {
        parse_errors.push(format!(
            "catalog declared {declared_count} entries; parsed {parsed_count}"
        ));
    }

    Some(ParsedCache {
        format: "olecfb_xp",
        entries,
        parse_errors,
    })
}

/// Fetch the thumbnail payload for a catalog index. The stream name is the
/// decimal index reversed (index 1 → "1", index 12 → "21"). When the stream
/// begins with the standard 12-byte XP thumbnail header immediately followed
/// by a JPEG SOI marker, the header is stripped so the digest matches the
/// extractable image; otherwise the whole stream is hashed as-is.
fn read_thumbnail_stream(
    compound: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    index: u32,
) -> Option<Vec<u8>> {
    let reversed: String = index.to_string().chars().rev().collect();
    let stream_path = format!("/{reversed}");
    if !compound.is_stream(&stream_path) {
        return None;
    }
    let mut bytes = Vec::new();
    compound
        .open_stream(&stream_path)
        .and_then(|mut s| s.read_to_end(&mut bytes))
        .ok()?;
    let has_jpeg_header = bytes.len() > 14
        && read_u32(&bytes, 0) == Some(12)
        && bytes[12] == 0xFF
        && bytes[13] == 0xD8;
    if has_jpeg_header {
        return Some(bytes[12..].to_vec());
    }
    Some(bytes)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(data: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// UTF-16LE bytes up to the first NUL code unit, lossily decoded.
fn utf16le_until_nul(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

// 116444736000000000 ticks = FILETIME for 1970-01-01 (Unix epoch).
const FILETIME_UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

/// Convert a Windows FILETIME (100-ns ticks since 1601-01-01 UTC) to the
/// project-standard ISO-8601Z string. FILETIME 0 means "never" → `None`.
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

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    /// FILETIME ticks for 2021-01-01T00:00:00Z.
    const FT_2021: u64 = 132_539_328_000_000_000;

    // -- CMMM fixture builders ---------------------------------------------

    fn cmmm_file_header(version: u32, first_entry: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&CMMM_MAGIC);
        h.extend_from_slice(&version.to_le_bytes());
        h.extend_from_slice(&0_u32.to_le_bytes()); // cache type
        if version >= CMMM_VERSION_WIN8_MIN {
            h.extend_from_slice(&0_u32.to_le_bytes()); // unknown
        }
        h.extend_from_slice(&first_entry.to_le_bytes());
        h.extend_from_slice(&0_u32.to_le_bytes()); // first available entry
        h.extend_from_slice(&0_u32.to_le_bytes()); // entry count (Vista/7)
        while h.len() < usize::try_from(first_entry).unwrap() {
            h.push(0);
        }
        h
    }

    fn cmmm_record(version: u32, hash: u64, identifier: &str, payload: &[u8]) -> Vec<u8> {
        let layout = cmmm_layout(version).unwrap();
        let id_bytes: Vec<u8> = identifier
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let record_size =
            u32::try_from(layout.header_len + id_bytes.len() + payload.len()).unwrap();
        let mut r = Vec::new();
        r.extend_from_slice(&CMMM_MAGIC);
        r.extend_from_slice(&record_size.to_le_bytes());
        r.extend_from_slice(&hash.to_le_bytes());
        if version == CMMM_VERSION_VISTA {
            r.extend_from_slice(&[0_u8; 8]); // wide-char extension
        }
        r.extend_from_slice(&u32::try_from(id_bytes.len()).unwrap().to_le_bytes());
        r.extend_from_slice(&0_u32.to_le_bytes()); // padding size
        r.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        if version >= CMMM_VERSION_WIN8_MIN {
            r.extend_from_slice(&0_u32.to_le_bytes()); // width
            r.extend_from_slice(&0_u32.to_le_bytes()); // height
        }
        r.extend_from_slice(&0_u32.to_le_bytes()); // unknown
        r.extend_from_slice(&0_u64.to_le_bytes()); // data checksum
        r.extend_from_slice(&0_u64.to_le_bytes()); // header checksum
        assert_eq!(r.len(), layout.header_len);
        r.extend_from_slice(&id_bytes);
        r.extend_from_slice(payload);
        r
    }

    fn cmmm_fixture(version: u32, records: &[(u64, &str, &[u8])]) -> Vec<u8> {
        let mut data = cmmm_file_header(version, 64);
        for (hash, id, payload) in records {
            data.extend_from_slice(&cmmm_record(version, *hash, id, payload));
        }
        data
    }

    // -- XP Thumbs.db fixture builders -------------------------------------

    fn catalog_bytes(rows: &[(u32, u64, &str)]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&16_u16.to_le_bytes()); // header size
        c.extend_from_slice(&5_u16.to_le_bytes()); // version
        c.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
        c.extend_from_slice(&96_u32.to_le_bytes()); // thumbnail width
        c.extend_from_slice(&96_u32.to_le_bytes()); // thumbnail height
        for (index, filetime, name) in rows {
            let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
            let size = u32::try_from(16 + name_bytes.len() + 2).unwrap();
            c.extend_from_slice(&size.to_le_bytes());
            c.extend_from_slice(&index.to_le_bytes());
            c.extend_from_slice(&filetime.to_le_bytes());
            c.extend_from_slice(&name_bytes);
            c.extend_from_slice(&[0, 0]); // terminator
        }
        c
    }

    /// Build a real OLE/CFB `Thumbs.db` in memory with the `cfb` crate.
    fn thumbs_db(catalog: &[u8], streams: &[(&str, &[u8])]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        comp.create_stream("/Catalog")
            .unwrap()
            .write_all(catalog)
            .unwrap();
        for (name, bytes) in streams {
            comp.create_stream(format!("/{name}"))
                .unwrap()
                .write_all(bytes)
                .unwrap();
        }
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    // -- CMMM tests ----------------------------------------------------------

    #[test]
    fn cmmm_win7_records_parse_with_hash_size_and_digest() {
        let payload_a: &[u8] = b"jpeg-bytes-alpha";
        let payload_b: &[u8] = b"png-bytes-beta";
        let data = cmmm_fixture(
            CMMM_VERSION_WIN7,
            &[
                (0xDEAD_BEEF_1234_5678, "deadbeef12345678", payload_a),
                (0x0000_0000_0000_00AB, "00000000000000ab", payload_b),
            ],
        );
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert_eq!(parsed.format, "cmmm");
        assert!(parsed.parse_errors.is_empty(), "{:?}", parsed.parse_errors);
        assert_eq!(parsed.entries.len(), 2);
        let by_hash = |h: &str| {
            parsed
                .entries
                .iter()
                .find(|e| e.cache_entry_hash.as_deref() == Some(h))
                .unwrap()
        };
        let a = by_hash("deadbeef12345678");
        assert_eq!(a.data_size_bytes, u64::try_from(payload_a.len()).unwrap());
        assert_eq!(
            a.content_sha256.as_deref(),
            Some(sha256_hex(payload_a).as_str())
        );
        assert!(a.index.is_none() && a.original_filename.is_none() && a.modified_iso.is_none());
        let b = by_hash("00000000000000ab");
        assert_eq!(
            b.content_sha256.as_deref(),
            Some(sha256_hex(payload_b).as_str())
        );
    }

    #[test]
    fn cmmm_vista_and_win8_layouts_parse() {
        for version in [CMMM_VERSION_VISTA, 0x20 /* Win10 */] {
            let data = cmmm_fixture(version, &[(0x1122_3344_5566_7788, "id", b"payload")]);
            let parsed = parse_bytes(&data).expect("cmmm magic recognized");
            assert!(
                parsed.parse_errors.is_empty(),
                "v{version}: {:?}",
                parsed.parse_errors
            );
            assert_eq!(parsed.entries.len(), 1, "version {version}");
            assert_eq!(
                parsed.entries[0].cache_entry_hash.as_deref(),
                Some("1122334455667788")
            );
            assert_eq!(
                parsed.entries[0].content_sha256.as_deref(),
                Some(sha256_hex(b"payload").as_str())
            );
        }
    }

    #[test]
    fn cmmm_corrupt_tail_is_noted_not_fatal() {
        let mut data = cmmm_fixture(CMMM_VERSION_WIN7, &[(1, "01", b"x"), (2, "02", b"y")]);
        data.extend_from_slice(b"GARBAGE-NOT-A-RECORD");
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert_eq!(parsed.entries.len(), 2, "good records still surface");
        assert_eq!(parsed.parse_errors.len(), 1);
        assert!(parsed.parse_errors[0].contains("bad record magic"));
    }

    #[test]
    fn cmmm_zero_fill_tail_is_a_clean_stop() {
        let mut data = cmmm_fixture(CMMM_VERSION_WIN7, &[(7, "07", b"z")]);
        data.extend_from_slice(&[0_u8; 256]);
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.parse_errors.is_empty(), "{:?}", parsed.parse_errors);
    }

    #[test]
    fn cmmm_truncated_final_payload_omits_digest() {
        let mut data = cmmm_fixture(CMMM_VERSION_WIN7, &[(9, "09", b"full-payload-here")]);
        data.truncate(data.len() - 5); // chop into the payload
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert_eq!(parsed.entries.len(), 1);
        assert!(parsed.entries[0].content_sha256.is_none());
        assert!(parsed
            .parse_errors
            .iter()
            .any(|e| e.contains("payload truncated")));
    }

    #[test]
    fn cmmm_deallocated_slots_are_skipped() {
        let data = cmmm_fixture(
            CMMM_VERSION_WIN7,
            &[(0, "", b""), (5, "05", b"real"), (0, "", b"")],
        );
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(
            parsed.entries[0].cache_entry_hash.as_deref(),
            Some("0000000000000005")
        );
    }

    #[test]
    fn cmmm_unsupported_version_is_a_noted_stop() {
        let data = cmmm_file_header(0x16, 64);
        let parsed = parse_bytes(&data).expect("cmmm magic recognized");
        assert!(parsed.entries.is_empty());
        assert!(parsed.parse_errors[0].contains("unsupported CMMM version"));
    }

    // -- XP Thumbs.db tests --------------------------------------------------

    #[test]
    fn xp_catalog_rows_map_to_reversed_streams() {
        // Index 1 → stream "1"; index 12 → stream "21".
        let jpeg_a: &[u8] = b"\xFF\xD8fake-jpeg-a";
        let jpeg_b: &[u8] = b"\xFF\xD8fake-jpeg-b";
        let catalog = catalog_bytes(&[(1, FT_2021, "vacation photo.jpg"), (12, 0, "diagram.png")]);
        let data = thumbs_db(&catalog, &[("1", jpeg_a), ("21", jpeg_b)]);
        let parsed = parse_bytes(&data).expect("cfb with Catalog is a cache");
        assert_eq!(parsed.format, "olecfb_xp");
        assert!(parsed.parse_errors.is_empty(), "{:?}", parsed.parse_errors);
        assert_eq!(parsed.entries.len(), 2);

        let one = parsed.entries.iter().find(|e| e.index == Some(1)).unwrap();
        assert_eq!(one.original_filename.as_deref(), Some("vacation photo.jpg"));
        assert_eq!(one.modified_iso.as_deref(), Some("2021-01-01T00:00:00Z"));
        assert_eq!(one.data_size_bytes, u64::try_from(jpeg_a.len()).unwrap());
        assert_eq!(
            one.content_sha256.as_deref(),
            Some(sha256_hex(jpeg_a).as_str())
        );

        let twelve = parsed.entries.iter().find(|e| e.index == Some(12)).unwrap();
        assert_eq!(twelve.original_filename.as_deref(), Some("diagram.png"));
        assert!(twelve.modified_iso.is_none(), "FILETIME 0 means never");
        assert_eq!(
            twelve.content_sha256.as_deref(),
            Some(sha256_hex(jpeg_b).as_str())
        );
    }

    #[test]
    fn xp_standard_thumbnail_header_is_stripped_before_hashing() {
        // 12-byte XP thumbnail header (size marker 12) then a JPEG SOI.
        let image: &[u8] = b"\xFF\xD8\xFF\xE0real-image-bytes";
        let mut stream = Vec::new();
        stream.extend_from_slice(&12_u32.to_le_bytes());
        stream.extend_from_slice(&1_u32.to_le_bytes());
        stream.extend_from_slice(&u32::try_from(image.len()).unwrap().to_le_bytes());
        stream.extend_from_slice(image);
        let catalog = catalog_bytes(&[(1, FT_2021, "a.jpg")]);
        let data = thumbs_db(&catalog, &[("1", &stream)]);
        let parsed = parse_bytes(&data).unwrap();
        assert_eq!(
            parsed.entries[0].content_sha256.as_deref(),
            Some(sha256_hex(image).as_str()),
            "digest must cover the embedded image, not the stream header"
        );
        assert_eq!(
            parsed.entries[0].data_size_bytes,
            u64::try_from(image.len()).unwrap()
        );
    }

    #[test]
    fn xp_missing_thumbnail_stream_is_noted() {
        let catalog = catalog_bytes(&[(3, FT_2021, "gone.jpg")]);
        let data = thumbs_db(&catalog, &[]);
        let parsed = parse_bytes(&data).unwrap();
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].data_size_bytes, 0);
        assert!(parsed.entries[0].content_sha256.is_none());
        assert!(parsed
            .parse_errors
            .iter()
            .any(|e| e.contains("no thumbnail stream for catalog index 3")));
    }

    #[test]
    fn xp_truncated_catalog_stops_cleanly() {
        let mut catalog = catalog_bytes(&[(1, FT_2021, "ok.jpg"), (2, FT_2021, "cut.jpg")]);
        catalog.truncate(catalog.len() - 4); // cut into the last entry
        let data = thumbs_db(&catalog, &[("1", b"\xFF\xD8x")]);
        let parsed = parse_bytes(&data).unwrap();
        assert_eq!(parsed.entries.len(), 1, "first entry still parses");
        assert!(parsed
            .parse_errors
            .iter()
            .any(|e| e.contains("truncated or undersized")));
    }

    #[test]
    fn ole_file_without_catalog_is_not_a_thumbcache() {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        comp.create_stream("/WordDocument")
            .unwrap()
            .write_all(b"not a cache")
            .unwrap();
        comp.flush().unwrap();
        let data = comp.into_inner().into_inner();
        assert!(parse_bytes(&data).is_none());
    }

    // -- Shared / contract tests ---------------------------------------------

    #[test]
    fn bad_magic_is_rejected() {
        assert!(parse_bytes(b"not a cache of any kind").is_none());
        assert!(parse_bytes(b"").is_none());
    }

    #[test]
    fn filetime_conversion_matches_known_vector() {
        assert_eq!(
            filetime_to_iso(FT_2021).as_deref(),
            Some("2021-01-01T00:00:00Z")
        );
        assert_eq!(filetime_to_iso(0), None, "FILETIME 0 means never");
    }

    #[test]
    fn limit_is_enforced_and_ordering_is_deterministic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("thumbcache_96.db");
        // Hashes deliberately out of order to prove the sort.
        let data = cmmm_fixture(
            CMMM_VERSION_WIN7,
            &[(3, "03", b"c"), (1, "01", b"a"), (2, "02", b"b")],
        );
        std::fs::write(&path, &data).unwrap();
        let out = thumbcache_parse(&ThumbcacheParseInput {
            case_id: "test-case".to_string(),
            thumbcache_path: path.clone(),
            limit: 2,
        })
        .expect("parse ok");
        assert_eq!(out.entries_seen, 3);
        assert_eq!(out.entries.len(), 2, "limit trims post-sort");
        assert_eq!(
            out.entries[0].cache_entry_hash.as_deref(),
            Some("0000000000000001")
        );
        assert_eq!(
            out.entries[1].cache_entry_hash.as_deref(),
            Some("0000000000000002")
        );
        // Replay determinism: identical bytes → identical output.
        let replay = thumbcache_parse(&ThumbcacheParseInput {
            case_id: "test-case".to_string(),
            thumbcache_path: path,
            limit: 2,
        })
        .expect("replay ok");
        assert_eq!(
            serde_json::to_string(&out).unwrap(),
            serde_json::to_string(&replay).unwrap()
        );
    }

    #[test]
    fn input_default_limit_applies() {
        let input: ThumbcacheParseInput =
            serde_json::from_str(r#"{"case_id":"c1","thumbcache_path":"/x/Thumbs.db"}"#).unwrap();
        assert_eq!(input.limit, DEFAULT_LIMIT);
    }

    #[test]
    fn path_predicate_matches_cache_names_only() {
        assert!(path_looks_like_thumbcache(Path::new("Thumbs.db")));
        assert!(path_looks_like_thumbcache(Path::new("THUMBS.DB")));
        assert!(path_looks_like_thumbcache(Path::new("thumbcache_1024.db")));
        assert!(path_looks_like_thumbcache(Path::new("iconcache_32.db")));
        assert!(!path_looks_like_thumbcache(Path::new("History.db")));
        assert!(!path_looks_like_thumbcache(Path::new("evil.evtx")));
    }
}
