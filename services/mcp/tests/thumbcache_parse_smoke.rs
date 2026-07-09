//! Integration tests for `thumbcache_parse`.
//!
//! Mirrors the browser-history/registry pattern: error paths, the
//! unknown-field denial the server relies on, the path predicate, plus real
//! fixtures built on the fly — a CMMM cache from raw bytes and an XP
//! `Thumbs.db` written with the `cfb` crate — so both format branches and the
//! JSON output shape are exercised end-to-end without a checked-in binary.

use std::io::Write;
use std::path::PathBuf;

use findevil_mcp::tools::{
    path_looks_like_thumbcache, thumbcache_parse, ThumbcacheParseError, ThumbcacheParseInput,
};
use sha2::{Digest, Sha256};

fn sample_input(path: PathBuf) -> ThumbcacheParseInput {
    ThumbcacheParseInput {
        case_id: "test-case".to_string(),
        thumbcache_path: path,
        limit: 500,
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Minimal Win7-layout CMMM cache: file header + records of
/// (hash, identifier UTF-16LE, payload).
fn cmmm_fixture(records: &[(u64, &str, &[u8])]) -> Vec<u8> {
    const FIRST_ENTRY: usize = 64;
    let mut data = Vec::new();
    data.extend_from_slice(b"CMMM");
    data.extend_from_slice(&0x15_u32.to_le_bytes()); // version: Windows 7
    data.extend_from_slice(&0_u32.to_le_bytes()); // cache type
    data.extend_from_slice(&u32::try_from(FIRST_ENTRY).unwrap().to_le_bytes());
    data.extend_from_slice(&0_u32.to_le_bytes()); // first available entry
    data.extend_from_slice(&0_u32.to_le_bytes()); // entry count
    data.resize(FIRST_ENTRY, 0);
    for (hash, identifier, payload) in records {
        let id_bytes: Vec<u8> = identifier
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        // Win7 record header is 48 bytes.
        let record_size = u32::try_from(48 + id_bytes.len() + payload.len()).unwrap();
        data.extend_from_slice(b"CMMM");
        data.extend_from_slice(&record_size.to_le_bytes());
        data.extend_from_slice(&hash.to_le_bytes());
        data.extend_from_slice(&u32::try_from(id_bytes.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes()); // padding size
        data.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes()); // unknown
        data.extend_from_slice(&0_u64.to_le_bytes()); // data checksum
        data.extend_from_slice(&0_u64.to_le_bytes()); // header checksum
        data.extend_from_slice(&id_bytes);
        data.extend_from_slice(payload);
    }
    data
}

/// XP catalog stream: 16-byte header + rows of (index, FILETIME, name).
fn catalog_bytes(rows: &[(u32, u64, &str)]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&16_u16.to_le_bytes());
    c.extend_from_slice(&5_u16.to_le_bytes());
    c.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
    c.extend_from_slice(&96_u32.to_le_bytes());
    c.extend_from_slice(&96_u32.to_le_bytes());
    for (index, filetime, name) in rows {
        let name_bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let size = u32::try_from(16 + name_bytes.len() + 2).unwrap();
        c.extend_from_slice(&size.to_le_bytes());
        c.extend_from_slice(&index.to_le_bytes());
        c.extend_from_slice(&filetime.to_le_bytes());
        c.extend_from_slice(&name_bytes);
        c.extend_from_slice(&[0, 0]);
    }
    c
}

#[test]
fn thumbcache_parse_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("Thumbs.db"));
    let err = thumbcache_parse(&input).unwrap_err();
    assert!(matches!(err, ThumbcacheParseError::NotFound(_)));
}

#[test]
fn thumbcache_parse_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("Thumbs.db");
    std::fs::create_dir_all(&dir).unwrap();
    let err = thumbcache_parse(&sample_input(dir)).unwrap_err();
    assert!(matches!(err, ThumbcacheParseError::NotRegular(_)));
}

#[test]
fn thumbcache_parse_rejects_unrecognized_magic() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("thumbcache_256.db");
    std::fs::write(&path, b"neither an OLE compound file nor a CMMM cache").unwrap();
    let err = thumbcache_parse(&sample_input(path)).unwrap_err();
    assert!(matches!(err, ThumbcacheParseError::NotThumbcache(_)));
}

#[test]
fn thumbcache_parse_refuses_oversize_file() {
    // A sparse file gives us >512 MiB of metadata length without writing it.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("thumbcache_1024.db");
    let file = std::fs::File::create(&path).unwrap();
    file.set_len(512 * 1024 * 1024 + 1).unwrap();
    drop(file);
    let err = thumbcache_parse(&sample_input(path)).unwrap_err();
    assert!(
        matches!(err, ThumbcacheParseError::TooLarge { .. }),
        "got {err:?}"
    );
}

#[test]
fn thumbcache_input_rejects_unknown_fields() {
    let body = r#"{"case_id":"c1","thumbcache_path":"/x/Thumbs.db","rogue_field":"nope"}"#;
    let err = serde_json::from_str::<ThumbcacheParseInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn path_predicate_matches_cache_names() {
    assert!(path_looks_like_thumbcache(std::path::Path::new(
        "Thumbs.db"
    )));
    assert!(path_looks_like_thumbcache(std::path::Path::new(
        "thumbcache_96.db"
    )));
    assert!(path_looks_like_thumbcache(std::path::Path::new(
        "iconcache_1024.db"
    )));
    assert!(!path_looks_like_thumbcache(std::path::Path::new(
        "places.sqlite"
    )));
}

#[test]
fn thumbcache_parse_cmmm_fixture_end_to_end() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("thumbcache_96.db");
    let payload: &[u8] = b"\xFF\xD8fake-thumbnail-jpeg-bytes";
    std::fs::write(
        &path,
        cmmm_fixture(&[(0xCAFE_F00D_0000_0001, "cafef00d00000001", payload)]),
    )
    .unwrap();

    let out = thumbcache_parse(&sample_input(path.clone())).expect("parse cmmm cache");
    assert_eq!(out.format, "cmmm");
    assert_eq!(out.case_id, "test-case");
    assert_eq!(out.thumbcache_path, path);
    assert_eq!(out.entries_seen, 1);
    assert!(out.parse_errors.is_empty(), "{:?}", out.parse_errors);
    let entry = &out.entries[0];
    assert_eq!(entry.cache_entry_hash.as_deref(), Some("cafef00d00000001"));
    assert_eq!(entry.data_size_bytes, u64::try_from(payload.len()).unwrap());
    assert_eq!(
        entry.content_sha256.as_deref(),
        Some(sha256_hex(payload).as_str())
    );
    assert!(entry.index.is_none());
    assert!(entry.original_filename.is_none());
    assert!(entry.modified_iso.is_none());

    // JSON output shape — the exact keys the agent and audit chain rely on.
    let json = serde_json::to_value(&out).unwrap();
    for key in [
        "case_id",
        "thumbcache_path",
        "format",
        "entries",
        "entries_seen",
        "parse_errors",
    ] {
        assert!(json.get(key).is_some(), "output missing key {key}: {json}");
    }
    let entry_json = &json["entries"][0];
    for key in [
        "index",
        "cache_entry_hash",
        "original_filename",
        "modified_iso",
        "data_size_bytes",
        "content_sha256",
    ] {
        assert!(
            entry_json.get(key).is_some(),
            "entry missing key {key}: {entry_json}"
        );
    }
}

#[test]
fn thumbcache_parse_xp_thumbs_db_end_to_end() {
    // Build a real OLE/CFB Thumbs.db on disk with the cfb crate: a Catalog
    // stream naming two originals, plus thumbnail streams under the
    // reversed-index names (index 1 -> "1", index 12 -> "21").
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Thumbs.db");
    // FILETIME ticks for 2021-01-01T00:00:00Z.
    let ft_2021: u64 = 132_539_328_000_000_000;
    let thumb_a: &[u8] = b"\xFF\xD8thumbnail-bytes-alpha";
    let thumb_b: &[u8] = b"\xFF\xD8thumbnail-bytes-beta";
    {
        let mut comp = cfb::create(&path).expect("create compound file");
        comp.create_stream("/Catalog")
            .unwrap()
            .write_all(&catalog_bytes(&[
                (1, ft_2021, "deleted photo.jpg"),
                (12, ft_2021, "another.png"),
            ]))
            .unwrap();
        comp.create_stream("/1")
            .unwrap()
            .write_all(thumb_a)
            .unwrap();
        comp.create_stream("/21")
            .unwrap()
            .write_all(thumb_b)
            .unwrap();
        comp.flush().unwrap();
    }

    let out = thumbcache_parse(&sample_input(path)).expect("parse xp thumbs.db");
    assert_eq!(out.format, "olecfb_xp");
    assert_eq!(out.entries_seen, 2);
    assert!(out.parse_errors.is_empty(), "{:?}", out.parse_errors);

    // Sorted by index — deterministic ordering.
    assert_eq!(out.entries[0].index, Some(1));
    assert_eq!(out.entries[1].index, Some(12));
    assert_eq!(
        out.entries[0].original_filename.as_deref(),
        Some("deleted photo.jpg")
    );
    assert_eq!(
        out.entries[0].modified_iso.as_deref(),
        Some("2021-01-01T00:00:00Z")
    );
    assert_eq!(
        out.entries[0].content_sha256.as_deref(),
        Some(sha256_hex(thumb_a).as_str())
    );
    assert_eq!(
        out.entries[1].content_sha256.as_deref(),
        Some(sha256_hex(thumb_b).as_str()),
        "index 12 must map to the reversed stream name \"21\""
    );
    assert!(
        out.entries.iter().all(|e| e.cache_entry_hash.is_none()),
        "XP rows carry no CMMM hash"
    );
}

#[test]
fn thumbcache_parse_ole_without_catalog_is_not_a_cache() {
    // A valid compound file that is not a thumbnail cache (e.g. a .doc).
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("Thumbs.db");
    {
        let mut comp = cfb::create(&path).expect("create compound file");
        comp.create_stream("/WordDocument")
            .unwrap()
            .write_all(b"office bytes")
            .unwrap();
        comp.flush().unwrap();
    }
    let err = thumbcache_parse(&sample_input(path)).unwrap_err();
    assert!(matches!(err, ThumbcacheParseError::NotThumbcache(_)));
}

#[test]
fn thumbcache_parse_limit_is_enforced_deterministically() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("thumbcache_32.db");
    std::fs::write(
        &path,
        cmmm_fixture(&[(3, "03", b"c"), (1, "01", b"a"), (2, "02", b"b")]),
    )
    .unwrap();
    let out = thumbcache_parse(&ThumbcacheParseInput {
        case_id: "test-case".to_string(),
        thumbcache_path: path,
        limit: 2,
    })
    .expect("parse ok");
    assert_eq!(out.entries_seen, 3, "seen counts pre-limit");
    assert_eq!(out.entries.len(), 2);
    assert_eq!(
        out.entries[0].cache_entry_hash.as_deref(),
        Some("0000000000000001"),
        "sorted by hash before the limit trims"
    );
}
