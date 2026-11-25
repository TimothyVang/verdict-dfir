//! Integration tests for `usnjrnl_query`.
//!
//! Mirrors the established pattern: error paths, path-extension
//! predicate, serde roundtrip, plus a real-fixture parse if one is
//! present at `fixtures/usnjrnl/$J`. The crate is streaming so
//! synthetic happy-path tests would require constructing a valid
//! USN record byte-for-byte; we leave that to the opt-in fixture.

use std::path::{Path, PathBuf};

use findevil_mcp::{path_looks_like_usnjrnl, usnjrnl_query, UsnJrnlError, UsnJrnlInput};

fn sample_input(path: PathBuf) -> UsnJrnlInput {
    UsnJrnlInput {
        case_id: "test-case".to_string(),
        usnjrnl_path: path,
        since_iso: None,
        until_iso: None,
        reasons: None,
        limit: None,
    }
}

#[test]
fn usnjrnl_query_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.j"));
    let err = usnjrnl_query(&input).unwrap_err();
    assert!(matches!(err, UsnJrnlError::UsnJrnlNotFound(_)));
}

#[test]
fn usnjrnl_query_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let subdir = tmp.path().join("looks-like-a-file.j");
    std::fs::create_dir_all(&subdir).unwrap();
    let input = sample_input(subdir);
    let err = usnjrnl_query(&input).unwrap_err();
    assert!(matches!(err, UsnJrnlError::UsnJrnlNotFound(_)));
}

#[test]
fn usnjrnl_query_handles_empty_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("empty.j");
    std::fs::write(&path, b"").unwrap();
    let input = sample_input(path);
    // Empty file: parser opens fine, iterator yields nothing.
    let out = usnjrnl_query(&input).expect("empty file scans cleanly");
    assert_eq!(out.records_seen, 0);
    assert_eq!(out.row_count, 0);
}

#[test]
fn usnjrnl_query_rejects_invalid_time_filter() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("file.j");
    std::fs::write(&path, b"").unwrap();
    let mut input = sample_input(path);
    input.since_iso = Some("not-a-real-time".to_string());
    let err = usnjrnl_query(&input).unwrap_err();
    assert!(matches!(err, UsnJrnlError::InvalidTimeFilter { .. }));
}

#[test]
fn usnjrnl_query_rejects_invalid_reason_name() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("file.j");
    std::fs::write(&path, b"").unwrap();
    let mut input = sample_input(path);
    input.reasons = Some(vec!["FILE_CREATE".to_string(), "BOGUS_REASON".to_string()]);
    let err = usnjrnl_query(&input).unwrap_err();
    match err {
        UsnJrnlError::InvalidReason(name) => assert_eq!(name, "BOGUS_REASON"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn usnjrnl_query_accepts_known_reasons_case_insensitive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("empty.j");
    std::fs::write(&path, b"").unwrap();
    let mut input = sample_input(path);
    // Mix of cases; all should be accepted.
    input.reasons = Some(vec![
        "file_create".to_string(),
        "FILE_DELETE".to_string(),
        "Rename_New_Name".to_string(),
        "DATA_EXTEND".to_string(),
    ]);
    let out = usnjrnl_query(&input).expect("known reasons should be accepted");
    assert_eq!(out.row_count, 0);
}

#[test]
fn usnjrnl_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "usnjrnl_path": "/case/$J",
        "since_iso": "2026-04-25T00:00:00Z",
        "until_iso": "2026-04-25T23:59:59Z",
        "reasons": ["FILE_CREATE", "FILE_DELETE"],
        "limit": 500
    }"#;
    let inp: UsnJrnlInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.usnjrnl_path, Path::new("/case/$J"));
    assert_eq!(inp.since_iso.as_deref(), Some("2026-04-25T00:00:00Z"));
    assert_eq!(
        inp.reasons.as_deref(),
        Some(&["FILE_CREATE".to_string(), "FILE_DELETE".to_string()][..])
    );
    assert_eq!(inp.limit, Some(500));
}

#[test]
fn usnjrnl_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "usnjrnl_path": "/x/$J",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<UsnJrnlInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn path_looks_like_usnjrnl_cases() {
    assert!(path_looks_like_usnjrnl(Path::new("$J")));
    assert!(path_looks_like_usnjrnl(Path::new("/case/$J")));
    assert!(path_looks_like_usnjrnl(Path::new("usnjrnl.j")));
    assert!(path_looks_like_usnjrnl(Path::new("USNJRNL.J")));
    assert!(path_looks_like_usnjrnl(Path::new("export.j")));
    assert!(path_looks_like_usnjrnl(Path::new("host123.usnjrnl")));
    assert!(!path_looks_like_usnjrnl(Path::new("file.evtx")));
    assert!(!path_looks_like_usnjrnl(Path::new("readme.md")));
    assert!(!path_looks_like_usnjrnl(Path::new("no-extension")));
}

/// Opt-in: when a real USN journal fixture is present at
/// `fixtures/usnjrnl/$J`, parse it and assert structural invariants.
/// CI without the fixture skips silently.
#[test]
fn usnjrnl_query_real_fixture_when_present() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fixture = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join("usnjrnl")
        .join("$J");

    if !fixture.is_file() {
        eprintln!(
            "fixture {} not present — skipping live parse",
            fixture.display()
        );
        return;
    }

    let input = sample_input(fixture);
    let out = usnjrnl_query(&input).expect("real $J must parse");
    assert!(out.records_seen > 0, "non-empty USN journal");
    assert!(out.row_count > 0, "at least one row produced");
    let entry = &out.entries[0];
    assert!(!entry.timestamp_iso.is_empty(), "ISO timestamp set");
    assert!(!entry.filename.is_empty(), "filename set");
}
