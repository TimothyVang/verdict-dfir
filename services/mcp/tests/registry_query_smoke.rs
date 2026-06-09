//! Integration tests for `registry_query`.
//!
//! Mirrors the `prefetch_parse` / `mft_timeline` pattern: error paths,
//! path-extension predicate, serde roundtrip, plus an opt-in real-
//! fixture parse when a hive is present at `fixtures/registry/`.

use std::path::{Path, PathBuf};

use findevil_mcp::{path_looks_like_hive, registry_query, RegistryError, RegistryInput};

fn sample_input(path: PathBuf) -> RegistryInput {
    RegistryInput {
        case_id: "test-case".to_string(),
        hive_path: path,
        key_path: String::new(),
        recursive: false,
        limit: None,
    }
}

#[test]
fn registry_query_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.dat"));
    let err = registry_query(&input).unwrap_err();
    assert!(matches!(err, RegistryError::HiveNotFound(_)));
}

#[test]
fn registry_query_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let subdir = tmp.path().join("looks-like-a-hive.dat");
    std::fs::create_dir_all(&subdir).unwrap();
    let input = sample_input(subdir);
    let err = registry_query(&input).unwrap_err();
    assert!(matches!(err, RegistryError::HiveNotFound(_)));
}

#[test]
fn registry_query_errors_on_garbage_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("garbage.dat");
    std::fs::write(&path, b"not a real registry hive header at all here").unwrap();
    let input = sample_input(path);
    let err = registry_query(&input).unwrap_err();
    // frnsc-hive checks the "regf" magic + base block CRC; garbage
    // surfaces as HiveOpen, not a panic.
    assert!(matches!(err, RegistryError::HiveOpen { .. }));
}

#[test]
fn registry_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "hive_path": "/case/SOFTWARE",
        "key_path": "Microsoft\\Windows\\CurrentVersion\\Run",
        "recursive": true,
        "limit": 100
    }"#;
    let inp: RegistryInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.hive_path, Path::new("/case/SOFTWARE"));
    assert_eq!(inp.key_path, "Microsoft\\Windows\\CurrentVersion\\Run");
    assert!(inp.recursive);
    assert_eq!(inp.limit, Some(100));
}

#[test]
fn registry_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "hive_path": "/x/SOFTWARE",
        "key_path": "",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<RegistryInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn registry_input_recursive_defaults_false() {
    // Verify the default value of `recursive` when omitted.
    let body = r#"{
        "case_id": "c1",
        "hive_path": "/x/SOFTWARE",
        "key_path": ""
    }"#;
    let inp: RegistryInput = serde_json::from_str(body).unwrap();
    assert!(!inp.recursive);
    assert_eq!(inp.limit, None);
}

#[test]
fn path_looks_like_hive_cases() {
    // Canonical hive base names (case-insensitive).
    assert!(path_looks_like_hive(Path::new("SOFTWARE")));
    assert!(path_looks_like_hive(Path::new("software")));
    assert!(path_looks_like_hive(Path::new("/case/SYSTEM")));
    assert!(path_looks_like_hive(Path::new("Security")));
    assert!(path_looks_like_hive(Path::new("SAM")));
    assert!(path_looks_like_hive(Path::new("DEFAULT")));
    assert!(path_looks_like_hive(Path::new("NTUSER.DAT")));
    assert!(path_looks_like_hive(Path::new("ntuser.dat")));
    assert!(path_looks_like_hive(Path::new("UsrClass.dat")));
    // .dat extension on any file (NTUSER.DAT.LOG would not match
    // because .LOG is the extension; that's intentional).
    assert!(path_looks_like_hive(Path::new("backup.dat")));
    // Non-matches.
    assert!(!path_looks_like_hive(Path::new("evil.evtx")));
    assert!(!path_looks_like_hive(Path::new("Security.pf")));
    assert!(!path_looks_like_hive(Path::new("NTUSER.DAT.LOG1")));
    assert!(!path_looks_like_hive(Path::new("readme")));
}

/// Opt-in: when a real hive fixture is present at
/// `fixtures/registry/SOFTWARE`, parse it and assert structural
/// invariants. CI without the fixture skips silently.
#[test]
fn registry_query_real_fixture_when_present() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fixture = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join("registry")
        .join("SOFTWARE");

    if !fixture.is_file() {
        eprintln!(
            "fixture {} not present — skipping live parse",
            fixture.display()
        );
        return;
    }

    // Open the SOFTWARE hive and request the Microsoft\Windows\
    // CurrentVersion\Run key — a near-universal key on any Windows
    // SOFTWARE hive.
    let mut input = sample_input(fixture);
    input.key_path = "Microsoft\\Windows\\CurrentVersion\\Run".to_string();
    let out = registry_query(&input).expect("real SOFTWARE hive must parse");
    assert!(out.keys_visited >= 1, "at least one key visited");
    assert_eq!(
        out.entries.len(),
        1,
        "non-recursive returns exactly the requested key"
    );
    let entry = &out.entries[0];
    assert_eq!(entry.key_path, "Microsoft\\Windows\\CurrentVersion\\Run");
    assert!(out.key_present, "an existing key reports key_present=true");

    // A genuinely-absent key is a normal empty result, NOT an error — the agent
    // must not treat "no autoruns here" as a tool failure.
    input.key_path = "Microsoft\\Windows\\CurrentVersion\\NoSuchKeyXyzzy".to_string();
    let absent = registry_query(&input).expect("absent key path is not an error");
    assert!(!absent.key_present, "absent key reports key_present=false");
    assert!(absent.entries.is_empty(), "absent key yields no entries");
}
