//! Integration tests for `evtx_query`.
//!
//! Unlike `case_open`, we can't cheaply synthesize a valid EVTX
//! file — the format is Microsoft-proprietary and the `evtx` crate
//! parses real-world headers. These tests therefore focus on:
//!
//!   * error paths (missing file, directory-not-file),
//!   * path-extension helper semantics,
//!   * typed-input schema roundtrip via `serde_json` (agent sends
//!     over the wire as JSON; we need to deserialize what it emits),
//!   * when an OTRF fixture is present at
//!     `fixtures/otrf-apt3-mordor/*.evtx`, we run a real parse and
//!     assert the output has non-zero rows. Gated behind a runtime
//!     check so CI without fixtures still passes.

use std::path::{Path, PathBuf};

use findevil_mcp::{evtx_query, path_looks_like_evtx, EvtxError, EvtxQueryInput, EvtxQueryOutput};

fn sample_input(path: PathBuf) -> EvtxQueryInput {
    EvtxQueryInput {
        case_id: "test-case".to_string(),
        evtx_path: path,
        eids: None,
        xpath: None,
        limit: None,
    }
}

#[test]
fn evtx_query_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("nope.evtx"));
    let err = evtx_query(&input).unwrap_err();
    assert!(matches!(err, EvtxError::EvtxNotFound(_)));
}

#[test]
fn evtx_query_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let subdir = tmp.path().join("looks-like-a-file.evtx");
    std::fs::create_dir_all(&subdir).unwrap();
    let input = sample_input(subdir);
    let err = evtx_query(&input).unwrap_err();
    match err {
        EvtxError::EvtxUnreadable { .. } => {}
        other => panic!("expected EvtxUnreadable, got {other:?}"),
    }
}

#[test]
fn evtx_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "evtx_path": "/tmp/Security.evtx",
        "eids": [4624, 4672, 7045],
        "xpath": "*[System[(EventID=4624)]]",
        "limit": 500
    }"#;
    let inp: EvtxQueryInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.evtx_path, Path::new("/tmp/Security.evtx"));
    assert_eq!(inp.eids.as_deref(), Some(&[4624u32, 4672, 7045][..]));
    assert_eq!(inp.limit, Some(500));
}

#[test]
fn evtx_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "evtx_path": "/tmp/x.evtx",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<EvtxQueryInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn path_looks_like_evtx_cases() {
    assert!(path_looks_like_evtx(Path::new("Security.evtx")));
    assert!(path_looks_like_evtx(Path::new("Security.EVTX")));
    assert!(!path_looks_like_evtx(Path::new("Security.evt")));
    assert!(!path_looks_like_evtx(Path::new("no-extension")));
}

/// Opt-in real-fixture test. Requires
/// `fixtures/otrf-apt3-mordor/*.evtx` — fetched by
/// `scripts/fetch-fixtures.sh`. When absent, test is a silent
/// success so CI without fixtures still passes.
#[test]
fn evtx_query_parses_otrf_fixture_if_present() {
    let fixture_dir = Path::new("../../fixtures/otrf-apt3-mordor");
    let Ok(entries) = std::fs::read_dir(fixture_dir) else {
        eprintln!("SKIP: no fixtures/otrf-apt3-mordor dir");
        return;
    };
    let evtx_files: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| path_looks_like_evtx(p))
        .collect();
    if evtx_files.is_empty() {
        eprintln!("SKIP: no .evtx files under fixtures/otrf-apt3-mordor");
        return;
    }

    let target = evtx_files.first().unwrap().clone();
    let inp = sample_input(target);
    let out: EvtxQueryOutput = evtx_query(&inp).expect("parse fixture");
    // OTRF fixtures always have >0 records.
    assert!(
        out.records_seen > 0,
        "expected at least one record, saw {}",
        out.records_seen
    );
    // If the shape extractor found any usable rows, they must look
    // well-formed.
    for row in out.rows.iter().take(5) {
        assert!(row.event_id > 0, "event_id should be positive");
        assert!(!row.channel.is_empty(), "channel should not be empty");
    }
}
