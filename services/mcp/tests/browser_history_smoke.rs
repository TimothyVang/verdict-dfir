//! Integration tests for `browser_history`.
//!
//! Mirrors the registry/prefetch pattern: error paths, the path-extension
//! predicate, serde roundtrip, plus a real Chrome-shaped fixture built on the
//! fly so the parser + timestamp conversion are exercised end-to-end without a
//! checked-in binary.

use std::path::PathBuf;

use findevil_mcp::{
    browser_history, path_looks_like_browser_history, BrowserHistoryError, BrowserHistoryInput,
};
use rusqlite::Connection;

fn sample_input(path: PathBuf) -> BrowserHistoryInput {
    BrowserHistoryInput {
        case_id: "test-case".to_string(),
        history_path: path,
        limit: None,
    }
}

#[test]
fn browser_history_errors_on_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let input = sample_input(tmp.path().join("History"));
    let err = browser_history(&input).unwrap_err();
    assert!(matches!(err, BrowserHistoryError::NotFound(_)));
}

#[test]
fn browser_history_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("History");
    std::fs::create_dir_all(&dir).unwrap();
    let err = browser_history(&sample_input(dir)).unwrap_err();
    assert!(matches!(err, BrowserHistoryError::NotFound(_)));
}

#[test]
fn browser_history_errors_on_garbage_bytes() {
    // A non-SQLite file must surface a typed error, not panic.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    std::fs::write(&path, b"this is definitely not a sqlite database header").unwrap();
    let err = browser_history(&sample_input(path)).unwrap_err();
    assert!(
        matches!(
            err,
            BrowserHistoryError::ParseFailed { .. } | BrowserHistoryError::Unreadable { .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn browser_history_errors_on_unknown_schema() {
    // A valid SQLite DB that is neither Chrome nor Firefox.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("random.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute("CREATE TABLE notes (id INTEGER, body TEXT)", [])
        .unwrap();
    drop(conn);
    let err = browser_history(&sample_input(path)).unwrap_err();
    assert!(matches!(err, BrowserHistoryError::UnknownSchema(_)));
}

#[test]
fn browser_history_input_rejects_unknown_fields() {
    let body = r#"{"case_id":"c1","history_path":"/x/History","rogue_field":"nope"}"#;
    let err = serde_json::from_str::<BrowserHistoryInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn path_predicate_matches_history_dbs() {
    assert!(path_looks_like_browser_history(std::path::Path::new(
        "History"
    )));
    assert!(path_looks_like_browser_history(std::path::Path::new(
        "places.sqlite"
    )));
    assert!(!path_looks_like_browser_history(std::path::Path::new(
        "evil.evtx"
    )));
}

#[test]
fn browser_history_parses_chrome_fixture() {
    // Build a minimal Chrome-shaped History DB and confirm a known visit
    // round-trips with the WebKit-epoch timestamp converted to ISO-8601Z.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("History");
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, last_visit_time INTEGER);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
    )
    .unwrap();
    // (1609459200 + 11644473600) * 1e6 = 13253932800000000 µs since 1601
    // = 2021-01-01T00:00:00Z.
    conn.execute(
        "INSERT INTO urls (url, title, visit_count, last_visit_time) \
             VALUES ('http://evil.example/payload.exe', 'payload', 3, 13253932800000000)",
        [],
    )
    .unwrap();
    drop(conn);

    let out = browser_history(&sample_input(path)).expect("parse chrome history");
    assert_eq!(out.browser_family, "chrome");
    assert_eq!(out.rows.len(), 1);
    let row = &out.rows[0];
    assert_eq!(row.url, "http://evil.example/payload.exe");
    assert_eq!(row.visit_count, 3);
    assert_eq!(
        row.last_visit_time_iso.as_deref(),
        Some("2021-01-01T00:00:00Z")
    );
}

#[test]
fn browser_history_parses_firefox_fixture() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("places.sqlite");
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, last_visit_date INTEGER)",
        [],
    )
    .unwrap();
    // 1609459200000000 µs since 1970 = 2021-01-01T00:00:00Z.
    conn.execute(
        "INSERT INTO moz_places (url, title, visit_count, last_visit_date) \
             VALUES ('https://c2.example/panel', 'panel', 7, 1609459200000000)",
        [],
    )
    .unwrap();
    drop(conn);

    let out = browser_history(&sample_input(path)).expect("parse firefox history");
    assert_eq!(out.browser_family, "firefox");
    assert_eq!(out.rows.len(), 1);
    assert_eq!(
        out.rows[0].last_visit_time_iso.as_deref(),
        Some("2021-01-01T00:00:00Z")
    );
}
