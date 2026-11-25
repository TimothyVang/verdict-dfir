//! Integration tests for `prefetch_parse`.
//!
//! Similar pattern to `evtx_query_smoke`: we exercise error paths,
//! path-extension semantics, and the typed-input schema roundtrip,
//! plus an opt-in real-fixture parse when a `.pf` file is present
//! under `fixtures/prefetch/`. CI without fixtures still passes.

use std::path::{Path, PathBuf};

use findevil_mcp::{path_looks_like_prefetch, prefetch_parse, PrefetchError, PrefetchInput};

fn sample_input(path: PathBuf) -> PrefetchInput {
    PrefetchInput {
        case_id: "test-case".to_string(),
        prefetch_path: path,
    }
}

#[test]
fn prefetch_parse_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.pf"));
    let err = prefetch_parse(&input).unwrap_err();
    assert!(matches!(err, PrefetchError::NotFound(_)));
}

#[test]
fn prefetch_parse_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let subdir = tmp.path().join("looks-like-a-file.pf");
    std::fs::create_dir_all(&subdir).unwrap();
    let input = sample_input(subdir);
    let err = prefetch_parse(&input).unwrap_err();
    // is_file() returns false for directories, so we get NotFound, not Unreadable.
    assert!(matches!(err, PrefetchError::NotFound(_)));
}

#[test]
fn prefetch_parse_errors_on_garbage_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("garbage.pf");
    std::fs::write(&path, b"not a real prefetch header at all here").unwrap();
    let input = sample_input(path);
    let err = prefetch_parse(&input).unwrap_err();
    // Wrong magic — frnsc-prefetch surfaces a parse error.
    assert!(matches!(err, PrefetchError::ParseFailed { .. }));
}

#[test]
fn prefetch_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "prefetch_path": "/tmp/Prefetch/CMD.EXE-D269B812.pf"
    }"#;
    let inp: PrefetchInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(
        inp.prefetch_path,
        Path::new("/tmp/Prefetch/CMD.EXE-D269B812.pf")
    );
}

#[test]
fn prefetch_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "prefetch_path": "/tmp/x.pf",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<PrefetchInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn path_looks_like_prefetch_cases() {
    assert!(path_looks_like_prefetch(Path::new("CMD.EXE-D269B812.pf")));
    assert!(path_looks_like_prefetch(Path::new("/x/Y/Z/Foo.PF"))); // case-insensitive
    assert!(!path_looks_like_prefetch(Path::new("evil.evtx")));
    assert!(!path_looks_like_prefetch(Path::new("no-extension")));
    assert!(!path_looks_like_prefetch(Path::new("dir.pf/file")));
}

/// Opt-in: when a real `.pf` fixture is present at
/// `fixtures/prefetch/CMD.EXE-D269B812.pf`, parse it and assert the
/// output has the structural fields populated. CI without the
/// fixture skips this assertion silently — same pattern as the
/// OTRF EVTX fixture in `evtx_query_smoke`.
#[test]
fn prefetch_parse_real_fixture_when_present() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fixture = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join("prefetch")
        .join("CMD.EXE-D269B812.pf");

    if !fixture.is_file() {
        eprintln!(
            "fixture {} not present — skipping live parse",
            fixture.display()
        );
        return;
    }

    let input = sample_input(fixture);
    let out = prefetch_parse(&input).expect("real fixture must parse");
    assert!(!out.executable_name.is_empty(), "executable name populated");
    assert!(out.version > 0, "version populated");
    // run_count can legitimately be 0 if it's the first run, but the
    // structural fields must at least exist (Vec is empty, not null).
    let _ = out.last_run_times_iso;
    let _ = out.file_references;
    let _ = out.volume_paths;
}
