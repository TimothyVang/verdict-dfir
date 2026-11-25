//! Integration tests for `vol_psxview`.

use std::path::{Path, PathBuf};

use findevil_mcp::{vol_psxview, VolPsxviewError, VolPsxviewInput};

fn sample_input(memory_path: PathBuf) -> VolPsxviewInput {
    VolPsxviewInput {
        case_id: "test-case".to_string(),
        memory_path,
        pid_filter: None,
        limit: None,
    }
}

#[test]
fn vol_psxview_errors_on_missing_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.mem"));
    let err = vol_psxview(&input).unwrap_err();
    assert!(matches!(err, VolPsxviewError::MemoryNotFound(_)));
}

#[test]
fn vol_psxview_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("looks-like.mem");
    std::fs::create_dir_all(&path).unwrap();
    let input = sample_input(path);
    let err = vol_psxview(&input).unwrap_err();
    assert!(matches!(err, VolPsxviewError::MemoryNotRegular(_)));
}

#[test]
fn vol_psxview_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "memory_path": "/case/memory.img",
        "pid_filter": [4, 4096],
        "limit": 100
    }"#;
    let inp: VolPsxviewInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.memory_path, Path::new("/case/memory.img"));
    assert_eq!(inp.pid_filter, Some(vec![4u32, 4096]));
    assert_eq!(inp.limit, Some(100));
}

#[test]
fn vol_psxview_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "memory_path": "/x.mem",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<VolPsxviewInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn vol_psxview_real_fixture_when_present() {
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
    let out = vol_psxview(&input).expect("real fixture should scan");
    let _ = out.processes;
    let _ = out.processes_seen;
    let _ = out.stderr_tail;
}
