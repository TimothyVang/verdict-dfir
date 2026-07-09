//! `exif_parse` — read EXIF metadata embedded in an image (JPEG/TIFF/HEIF/PNG/WebP).
//!
//! Cameras, phones, and editing software embed EXIF attributes inside image
//! files: the capturing device (`Make`/`Model`), the editing tool (`Software`),
//! the capture timestamps (`DateTimeOriginal`/`DateTime`), authorship
//! (`Artist`/`Copyright`), and — most valuable to DFIR — the GPS coordinates the
//! shot was taken at. No other product parser surfaces this: `thumbcache_parse`
//! reads the thumbnail cache, not embedded metadata, and the disk/registry tools
//! never open image bodies. Without this, a geotagged or software-fingerprinted
//! image is opaque to the pipeline.
//!
//! This reader is deliberately conservative. It decodes only what the vetted
//! pure-Rust `kamadak-exif` parser exposes as typed fields; it never guesses at
//! raw bytes, and if the input is not a recognizable EXIF container it returns
//! `has_exif = false` with empty vectors rather than erroring or inventing
//! structure. GPS is converted from the stored rational DMS triple to signed
//! decimal degrees using the stored N/S/E/W reference — a mechanical transform,
//! not an inference about where a person was. Output is sorted and deduped, so a
//! `verify_finding` replay reproduces the same bytes.
//!
//! Nothing here is image-specific: any image from any host parses the same way.
//! There are no hard-coded usernames, hostnames, device names, coordinates, or
//! paths — every value in the output is read straight from the artifact bytes.

use std::collections::BTreeSet;
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Upper bound on bytes read from one image. Images are typically a few MB; the
/// cap stops a pathological path from exhausting memory. EXIF lives in the file
/// header, so a truncated read still yields the metadata.
const MAX_BYTES: usize = 128 * 1024 * 1024;
/// Cap on surfaced "other field" entries so a metadata-heavy image can't bloat
/// output. The uncapped total is reported separately as `field_count`.
const MAX_ITEMS: usize = 100;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExifParseInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to an image file (JPEG/TIFF/HEIF/PNG/WebP) to read EXIF from.
    pub artifact_path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExifParseOutput {
    /// True if the file carries a recognizable EXIF block.
    pub has_exif: bool,
    /// `Make` — the capturing device manufacturer, as stored.
    pub camera_make: Option<String>,
    /// `Model` — the capturing device model, as stored.
    pub camera_model: Option<String>,
    /// `Software` — the creating/editing software, as stored.
    pub software: Option<String>,
    /// `DateTimeOriginal` — when the shot was captured, as stored (not UTC-normalized).
    pub datetime_original: Option<String>,
    /// `DateTime` — file change timestamp, as stored (not UTC-normalized).
    pub datetime: Option<String>,
    /// GPS position as signed decimal degrees `(latitude, longitude)`, converted
    /// from the stored DMS rationals and N/S/E/W references.
    pub gps_decimal: Option<(f64, f64)>,
    /// `Artist` — authorship, as stored.
    pub artist: Option<String>,
    /// `Copyright` — copyright string, as stored.
    pub copyright: Option<String>,
    /// Every other present field as a sorted, deduped `"TagName=value"` string
    /// (capped at `MAX_ITEMS`).
    pub other_fields: Vec<String>,
    /// Total count of EXIF fields present — uncapped, unlike `other_fields`.
    pub field_count: usize,
}

impl ExifParseOutput {
    /// The "no EXIF" shape: mirrors `oe_dbx_parse`'s falsy return, never an error.
    const fn empty() -> Self {
        Self {
            has_exif: false,
            camera_make: None,
            camera_model: None,
            software: None,
            datetime_original: None,
            datetime: None,
            gps_decimal: None,
            artist: None,
            copyright: None,
            other_fields: Vec::new(),
            field_count: 0,
        }
    }
}

#[derive(Debug, Error)]
pub enum ExifParseError {
    #[error("artifact not found: {0}")]
    ArtifactNotFound(PathBuf),
    #[error("could not read artifact {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Parse EXIF metadata out of an image file.
///
/// # Errors
/// * [`ExifParseError::ArtifactNotFound`] — `artifact_path` missing.
/// * [`ExifParseError::Read`] — IO error reading the file.
pub fn exif_parse(input: &ExifParseInput) -> Result<ExifParseOutput, ExifParseError> {
    if !input.artifact_path.exists() {
        return Err(ExifParseError::ArtifactNotFound(
            input.artifact_path.clone(),
        ));
    }
    let data = read_capped(&input.artifact_path)?;
    Ok(parse_bytes(&data))
}

fn read_capped(path: &std::path::Path) -> Result<Vec<u8>, ExifParseError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|source| ExifParseError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = Vec::new();
    file.take(MAX_BYTES as u64)
        .read_to_end(&mut buf)
        .map_err(|source| ExifParseError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(buf)
}

/// Tags surfaced as dedicated output fields — excluded from `other_fields` so
/// they are not duplicated.
const SURFACED_TAGS: &[exif::Tag] = &[
    exif::Tag::Make,
    exif::Tag::Model,
    exif::Tag::Software,
    exif::Tag::DateTimeOriginal,
    exif::Tag::DateTime,
    exif::Tag::Artist,
    exif::Tag::Copyright,
    exif::Tag::GPSLatitude,
    exif::Tag::GPSLongitude,
    exif::Tag::GPSLatitudeRef,
    exif::Tag::GPSLongitudeRef,
];

/// Pure parse over the raw bytes — unit-tested without IO.
fn parse_bytes(data: &[u8]) -> ExifParseOutput {
    let reader = exif::Reader::new();
    let mut cursor = std::io::Cursor::new(data);
    let Ok(exif) = reader.read_from_container(&mut cursor) else {
        return ExifParseOutput::empty();
    };

    let mut other: BTreeSet<String> = BTreeSet::new();
    let mut field_count = 0usize;
    for field in exif.fields() {
        field_count += 1;
        if SURFACED_TAGS.contains(&field.tag) {
            continue;
        }
        let value = field.display_value().with_unit(&exif).to_string();
        let value = value.trim();
        if !value.is_empty() {
            other.insert(format!("{}={}", field.tag, value));
        }
    }

    ExifParseOutput {
        has_exif: true,
        camera_make: ascii_field(&exif, exif::Tag::Make),
        camera_model: ascii_field(&exif, exif::Tag::Model),
        software: ascii_field(&exif, exif::Tag::Software),
        datetime_original: ascii_field(&exif, exif::Tag::DateTimeOriginal),
        datetime: ascii_field(&exif, exif::Tag::DateTime),
        gps_decimal: gps_decimal(&exif),
        artist: ascii_field(&exif, exif::Tag::Artist),
        copyright: ascii_field(&exif, exif::Tag::Copyright),
        other_fields: other.into_iter().take(MAX_ITEMS).collect(),
        field_count,
    }
}

/// The clean string value of a primary-IFD field, `None` if absent/empty. Reads
/// `Value::Ascii` bytes directly rather than `display_value()`, which wraps ASCII
/// in literal quotes (`"AA"`) — a quoted value must never land behind a Finding.
/// Non-ASCII types fall back to the display rendering.
fn ascii_field(exif: &exif::Exif, tag: exif::Tag) -> Option<String> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    let value = match field.value {
        exif::Value::Ascii(ref parts) => {
            let bytes: Vec<u8> = parts.iter().flatten().copied().collect();
            String::from_utf8_lossy(&bytes)
                .trim_matches('\0')
                .trim()
                .to_string()
        }
        _ => field
            .display_value()
            .with_unit(exif)
            .to_string()
            .trim()
            .to_string(),
    };
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

/// GPS position as signed decimal degrees, or `None` if lat/lon are not both
/// present as valid DMS rationals.
fn gps_decimal(exif: &exif::Exif) -> Option<(f64, f64)> {
    let lat = dms_to_degrees(exif, exif::Tag::GPSLatitude)?;
    let lon = dms_to_degrees(exif, exif::Tag::GPSLongitude)?;
    let lat = apply_ref(lat, hemisphere_ref(exif, exif::Tag::GPSLatitudeRef), b'S');
    let lon = apply_ref(lon, hemisphere_ref(exif, exif::Tag::GPSLongitudeRef), b'W');
    Some((lat, lon))
}

/// Convert a stored `[degrees, minutes, seconds]` rational triple to a positive
/// decimal-degree magnitude.
fn dms_to_degrees(exif: &exif::Exif, tag: exif::Tag) -> Option<f64> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    match field.value {
        exif::Value::Rational(ref parts) if parts.len() >= 3 => {
            let degrees = parts[0].to_f64();
            let minutes = parts[1].to_f64();
            let seconds = parts[2].to_f64();
            Some(degrees + minutes / 60.0 + seconds / 3600.0)
        }
        _ => None,
    }
}

/// First ASCII byte of a hemisphere reference tag (`'N'`/`'S'`/`'E'`/`'W'`).
fn hemisphere_ref(exif: &exif::Exif, tag: exif::Tag) -> Option<u8> {
    let field = exif.get_field(tag, exif::In::PRIMARY)?;
    match field.value {
        exif::Value::Ascii(ref parts) => parts.first().and_then(|s| s.first()).copied(),
        _ => None,
    }
}

/// Negate the magnitude when the reference marks the negative hemisphere.
fn apply_ref(magnitude: f64, reference: Option<u8>, negative: u8) -> f64 {
    match reference {
        Some(byte) if byte.eq_ignore_ascii_case(&negative) => -magnitude,
        _ => magnitude,
    }
}

#[cfg(test)]
#[allow(clippy::cast_possible_truncation, clippy::float_cmp)]
mod tests {
    use super::*;

    /// A 12-byte little-endian TIFF IFD entry holding a short (<=4 char) ASCII
    /// string stored inline in the value field.
    fn ascii_entry(tag: u16, text: &[u8]) -> Vec<u8> {
        assert!(
            text.len() <= 3,
            "inline ASCII test helper only fits 3 chars + NUL"
        );
        let mut entry = Vec::new();
        entry.extend_from_slice(&tag.to_le_bytes());
        entry.extend_from_slice(&2u16.to_le_bytes()); // type 2 = ASCII
        entry.extend_from_slice(&((text.len() + 1) as u32).to_le_bytes()); // count incl. NUL
        let mut inline = [0u8; 4];
        inline[..text.len()].copy_from_slice(text);
        entry.extend_from_slice(&inline); // NUL-padded inline value
        entry
    }

    /// A 12-byte little-endian TIFF IFD entry holding one SHORT value inline.
    fn short_entry(tag: u16, value: u16) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&tag.to_le_bytes());
        entry.extend_from_slice(&3u16.to_le_bytes()); // type 3 = SHORT
        entry.extend_from_slice(&1u32.to_le_bytes()); // count 1
        let mut inline = [0u8; 4];
        inline[..2].copy_from_slice(&value.to_le_bytes());
        entry.extend_from_slice(&inline);
        entry
    }

    /// Hand-build a minimal little-endian TIFF/EXIF buffer from IFD0 entries.
    /// `entries` must already be tag-ascending (TIFF requires sorted IFDs).
    fn build_tiff(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"II"); // little-endian byte order
        out.extend_from_slice(&0x2Au16.to_le_bytes()); // TIFF magic 42
        out.extend_from_slice(&8u32.to_le_bytes()); // offset to IFD0
        out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for entry in entries {
            out.extend_from_slice(entry);
        }
        out.extend_from_slice(&0u32.to_le_bytes()); // next-IFD offset = 0 (terminator)
        out
    }

    const TAG_MAKE: u16 = 0x010F;
    const TAG_MODEL: u16 = 0x0110;
    const TAG_ORIENTATION: u16 = 0x0112;
    const TAG_RESOLUTION_UNIT: u16 = 0x0128;
    const TAG_SOFTWARE: u16 = 0x0131;

    #[test]
    fn hand_built_tiff_parses_make_model_software() {
        let tiff = build_tiff(&[
            ascii_entry(TAG_MAKE, b"AA"),
            ascii_entry(TAG_MODEL, b"BB"),
            ascii_entry(TAG_SOFTWARE, b"CC"),
        ]);
        let out = parse_bytes(&tiff);
        assert!(out.has_exif);
        assert_eq!(out.camera_make.as_deref(), Some("AA"));
        assert_eq!(out.camera_model.as_deref(), Some("BB"));
        assert_eq!(out.software.as_deref(), Some("CC"));
        assert_eq!(out.field_count, 3);
        assert!(out.gps_decimal.is_none());
    }

    #[test]
    fn non_exif_bytes_return_falsy_shape_without_error() {
        let out = parse_bytes(b"this is not an image and carries no exif at all \x00\x01\x02");
        assert!(!out.has_exif);
        assert!(out.camera_make.is_none());
        assert!(out.other_fields.is_empty());
        assert_eq!(out.field_count, 0);
        assert!(out.gps_decimal.is_none());
    }

    #[test]
    fn empty_buffer_returns_falsy_shape() {
        let out = parse_bytes(&[]);
        assert!(!out.has_exif);
        assert_eq!(out.field_count, 0);
    }

    #[test]
    fn other_fields_are_sorted_deduped_and_deterministic() {
        // Two non-surfaced tags (Orientation, ResolutionUnit) plus a surfaced one
        // (Make). Entries must stay tag-ascending for a valid TIFF IFD.
        let tiff = build_tiff(&[
            ascii_entry(TAG_MAKE, b"AA"),
            short_entry(TAG_ORIENTATION, 1),
            short_entry(TAG_RESOLUTION_UNIT, 2),
        ]);
        let out = parse_bytes(&tiff);
        assert!(out.has_exif);
        // Make is surfaced separately, so it is absent from other_fields.
        assert!(out.other_fields.iter().all(|f| !f.starts_with("Make=")));
        // Vec is sorted.
        let mut sorted = out.other_fields.clone();
        sorted.sort();
        assert_eq!(out.other_fields, sorted);
        // No duplicates.
        let unique: BTreeSet<_> = out.other_fields.iter().cloned().collect();
        assert_eq!(unique.len(), out.other_fields.len());
        // Deterministic replay.
        assert_eq!(parse_bytes(&tiff).other_fields, out.other_fields);
    }

    #[test]
    fn absent_optional_fields_are_none() {
        let tiff = build_tiff(&[short_entry(TAG_ORIENTATION, 1)]);
        let out = parse_bytes(&tiff);
        assert!(out.has_exif);
        assert!(out.camera_make.is_none());
        assert!(out.datetime_original.is_none());
        assert!(out.artist.is_none());
        assert!(out.copyright.is_none());
    }

    #[test]
    fn apply_ref_negates_only_on_matching_hemisphere() {
        assert_eq!(apply_ref(40.0, Some(b'N'), b'S'), 40.0);
        assert_eq!(apply_ref(40.0, Some(b'S'), b'S'), -40.0);
        assert_eq!(apply_ref(40.0, Some(b's'), b'S'), -40.0); // case-insensitive
        assert_eq!(apply_ref(40.0, None, b'S'), 40.0);
        assert_eq!(apply_ref(70.0, Some(b'W'), b'W'), -70.0);
        assert_eq!(apply_ref(70.0, Some(b'E'), b'W'), 70.0);
    }
}
