//! Integration tests for `vol_pslist`.
//!
//! Volatility 3 is a heavyweight Python dependency we don't bundle;
//! tests focus on input validation. Real Volatility runs are gated
//! on `VOLATILITY_BIN` being set + a fixture image present at
//! `fixtures/memory/<name>.mem`.

use std::path::{Path, PathBuf};

use findevil_mcp::{path_looks_like_memory_image, vol_pslist, VolError, VolPslistInput};

fn sample_input(memory_path: PathBuf) -> VolPslistInput {
    VolPslistInput {
        case_id: "test-case".to_string(),
        memory_path,
        pid_filter: None,
        limit: None,
    }
}

#[test]
fn vol_pslist_errors_on_missing_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.mem"));
    let err = vol_pslist(&input).unwrap_err();
    assert!(matches!(err, VolError::MemoryNotFound(_)));
}

#[test]
fn vol_pslist_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("looks-like.mem");
    std::fs::create_dir_all(&path).unwrap();
    let input = sample_input(path);
    let err = vol_pslist(&input).unwrap_err();
    assert!(matches!(err, VolError::MemoryNotRegular(_)));
}

#[test]
fn vol_pslist_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "memory_path": "/case/memory.mem",
        "pid_filter": [4, 1234, 5678],
        "limit": 100
    }"#;
    let inp: VolPslistInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.memory_path, Path::new("/case/memory.mem"));
    assert_eq!(inp.pid_filter, Some(vec![4u32, 1234, 5678]));
    assert_eq!(inp.limit, Some(100));
}

#[test]
fn vol_pslist_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "memory_path": "/x.mem",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<VolPslistInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn path_looks_like_memory_image_cases() {
    assert!(path_looks_like_memory_image(Path::new("memdump.mem")));
    assert!(path_looks_like_memory_image(Path::new("MEM.RAW")));
    assert!(path_looks_like_memory_image(Path::new("/case/x.dmp")));
    assert!(path_looks_like_memory_image(Path::new("vm.vmem")));
    assert!(path_looks_like_memory_image(Path::new("snap.lime")));
    assert!(path_looks_like_memory_image(Path::new("acquired.aff4")));
    assert!(path_looks_like_memory_image(Path::new(
        "base-dc-memory.img"
    )));
    assert!(!path_looks_like_memory_image(Path::new("file.evtx")));
    assert!(!path_looks_like_memory_image(Path::new("notes.txt")));
    assert!(!path_looks_like_memory_image(Path::new("no-extension")));
}

/// Opt-in: when `VOLATILITY_BIN` is set AND a fixture exists at
/// `fixtures/memory/sample.mem`, run a real pslist. CI without
/// these skips silently.
#[test]
fn vol_pslist_real_fixture_when_present() {
    if std::env::var("VOLATILITY_BIN").is_err() {
        eprintln!("VOLATILITY_BIN not set — skipping live scan");
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fixture = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join("memory")
        .join("sample.mem");
    if !fixture.is_file() {
        eprintln!(
            "fixture {} not present — skipping live scan",
            fixture.display()
        );
        return;
    }
    let input = sample_input(fixture);
    let out = vol_pslist(&input).expect("real fixture should scan");
    assert!(out.processes_seen > 0, "non-empty pslist");
    assert!(!out.processes.is_empty(), "at least one process returned");
    let first = &out.processes[0];
    assert!(first.pid > 0 || !first.image_name.is_empty());
}
