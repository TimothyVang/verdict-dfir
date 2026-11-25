//! Integration tests for `hayabusa_scan`.
//!
//! Hayabusa is a large external binary; we don't bundle it, so the
//! tests focus on input validation + the binary-not-found path.
//! A real Hayabusa run is gated on the `HAYABUSA_BIN` env var being
//! set AND a fixture directory present at `fixtures/evtx/`.

use std::path::{Path, PathBuf};

use findevil_mcp::{hayabusa_scan, HayabusaError, HayabusaInput};

fn sample_input(evtx_dir: PathBuf) -> HayabusaInput {
    HayabusaInput {
        case_id: "test-case".to_string(),
        evtx_dir,
        rule_set: None,
        min_level: None,
        limit: None,
    }
}

#[test]
fn hayabusa_scan_errors_on_missing_evtx_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope"));
    let err = hayabusa_scan(&input).unwrap_err();
    assert!(matches!(err, HayabusaError::EvtxDirNotFound(_)));
}

#[test]
fn hayabusa_scan_errors_on_evtx_path_is_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("looks-like-a-dir");
    std::fs::write(&path, b"actually a file").unwrap();
    let input = sample_input(path);
    let err = hayabusa_scan(&input).unwrap_err();
    assert!(matches!(err, HayabusaError::EvtxDirNotDirectory(_)));
}

#[test]
fn hayabusa_scan_errors_on_missing_rule_set() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let evtx_dir = tmp.path().join("evtx");
    std::fs::create_dir(&evtx_dir).unwrap();
    let mut input = sample_input(evtx_dir);
    input.rule_set = Some(tmp.path().join("nope-rules"));
    let err = hayabusa_scan(&input).unwrap_err();
    assert!(matches!(err, HayabusaError::RuleSetNotFound(_)));
}

#[test]
fn hayabusa_scan_rejects_invalid_min_level() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let evtx_dir = tmp.path().join("evtx");
    std::fs::create_dir(&evtx_dir).unwrap();
    let mut input = sample_input(evtx_dir);
    input.min_level = Some("BANANAS".to_string());
    let err = hayabusa_scan(&input).unwrap_err();
    match err {
        HayabusaError::InvalidMinLevel(level) => assert_eq!(level, "BANANAS"),
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn hayabusa_scan_accepts_valid_min_levels_case_insensitive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let evtx_dir = tmp.path().join("evtx");
    std::fs::create_dir(&evtx_dir).unwrap();

    // Each of these passes input validation. They'll then hit
    // BinaryNotFound (assuming no hayabusa on PATH and no
    // HAYABUSA_BIN set) — that's also acceptable.
    for level in &["informational", "Low", "MEDIUM", "high", "Critical"] {
        let mut input = sample_input(evtx_dir.clone());
        input.min_level = Some((*level).to_string());
        let err = hayabusa_scan(&input).unwrap_err();
        // Should NOT be InvalidMinLevel.
        assert!(
            !matches!(err, HayabusaError::InvalidMinLevel(_)),
            "level {level:?} should be accepted"
        );
    }
}

// NOTE: no test for HayabusaError::BinaryNotFound. The crate has
// #![forbid(unsafe_code)] and Rust 2024 marks std::env::set_var as
// unsafe. We can't reliably scrub PATH from a parallel test without
// either an env-mutation crate or relaxing the forbid. The
// BinaryNotFound path is exercised whenever the test environment
// genuinely lacks Hayabusa, which is the default in CI.

#[test]
fn hayabusa_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "evtx_dir": "/case/Logs",
        "rule_set": "/opt/hayabusa-rules",
        "min_level": "medium",
        "limit": 500
    }"#;
    let inp: HayabusaInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.evtx_dir, Path::new("/case/Logs"));
    assert_eq!(
        inp.rule_set.as_deref(),
        Some(Path::new("/opt/hayabusa-rules"))
    );
    assert_eq!(inp.min_level.as_deref(), Some("medium"));
    assert_eq!(inp.limit, Some(500));
}

#[test]
fn hayabusa_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "evtx_dir": "/x",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<HayabusaInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

/// Opt-in: if `HAYABUSA_BIN` is set AND fixtures/evtx/ exists, run a
/// real scan. CI without these skips silently.
#[test]
fn hayabusa_scan_real_fixture_when_present() {
    if std::env::var("HAYABUSA_BIN").is_err() {
        eprintln!("HAYABUSA_BIN not set — skipping live scan");
        return;
    }
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR");
    let fixture = Path::new(&manifest_dir)
        .join("..")
        .join("..")
        .join("fixtures")
        .join("evtx");
    if !fixture.is_dir() {
        eprintln!(
            "fixture {} not present — skipping live scan",
            fixture.display()
        );
        return;
    }
    let mut input = sample_input(fixture);
    input.min_level = Some("medium".to_string());
    let out = hayabusa_scan(&input).expect("real fixture should scan");
    // Don't assert alert count — depends entirely on what's in the
    // fixture. Just that we got a structurally valid response.
    let _ = out.alerts;
    let _ = out.alerts_seen;
    let _ = out.stderr_tail;
}
