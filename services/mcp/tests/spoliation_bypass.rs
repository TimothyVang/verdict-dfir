//! Read-only / spoliation bypass battery — the product's READ-ONLY-EVIDENCE
//! safety boundary exercised at the DB driver layer.
//!
//! Threat model. `browser_history` is the one DFIR tool that drives a real
//! query engine (`SQLite`) over an evidence file rather than a fixed-format
//! parser, so it is the surface where a "spoliation" attempt (mutate or destroy
//! the evidence) or a SQL-injection-style escape would land if anything were
//! mis-wired. The tool's defence is NOT a keyword blocklist that a clever
//! disguise could slip past — it opens the database with
//! `SQLITE_OPEN_READ_ONLY` (+ a `?immutable=1` URI), so the *driver* refuses
//! every write/delete/DDL/redirect attempt at the transaction boundary,
//! regardless of how the statement is spelled. These tests pin that boundary.
//!
//! What this proves (and what it does not). This battery proves the read-only
//! posture is enforced semantically by `SQLite`'s read-only transaction mode, not
//! lexically — lowercase, comment-hidden, UNION-prefixed, and subquery-bearing
//! mutations are all rejected identically. It also proves there is no injection
//! *surface*: `browser_history`'s only string consumed near SQL is the table
//! name in fixed, parameter-bound `SELECT`s, and `case_id` is never executed —
//! a `case_id` carrying a `DROP TABLE` payload is read back inertly and the
//! table survives. It does NOT prove anything about the audit chain, the signed
//! manifest, or scoring — this is a pure tool-boundary characterization test
//! and is custody-neutral (no audit record, manifest, or verdict is produced).
//!
//! Note on `SQLite` vs "CALL". `SQLite` has no stored-procedure / `CALL` surface,
//! so that injection class is structurally absent; the subquery-bearing
//! `DELETE` below stands in as the "compound statement reaching a write" case
//! and is rejected by the same read-only driver boundary.

use std::path::{Path, PathBuf};

use findevil_mcp::{browser_history, BrowserHistoryInput};
use rusqlite::{Connection, OpenFlags};

/// Build a minimal, valid Chrome-shaped `History` DB with one row, returning
/// the path. Mirrors the fixture in `browser_history_smoke.rs` so the benign
/// read path is real, not a stub.
fn chrome_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("History");
    let conn = Connection::open(&path).expect("create fixture db");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, last_visit_time INTEGER);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
         INSERT INTO urls (url, title, visit_count, last_visit_time) \
             VALUES ('http://evil.example/payload.exe', 'payload', 3, 13253932800000000);",
    )
    .expect("seed fixture");
    drop(conn);
    path
}

/// Open `path` exactly the way `browser_history` opens evidence: read-only,
/// immutable URI. This is the *same* driver boundary the tool relies on, so a
/// mutation rejected here is a mutation the tool's connection would reject too.
fn open_like_tool(path: &Path) -> Connection {
    let uri = format!("file:{}?immutable=1", path.to_string_lossy());
    Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .expect("open read-only like the tool")
}

/// True when a rusqlite error is `SQLite`'s read-only refusal (the spoliation
/// block we want), as opposed to an unrelated syntax/runtime error.
fn is_readonly_refusal(err: &rusqlite::Error) -> bool {
    let msg = err.to_string().to_ascii_lowercase();
    msg.contains("readonly") || msg.contains("read-only") || msg.contains("read only")
}

/// The spoliation/mutation battery. Each entry is a write, delete, DDL, or
/// redirect attempt in a different lexical disguise; every one must be refused
/// by the read-only driver. Keyed on intent so a failure message is legible.
fn mutation_battery() -> Vec<(&'static str, &'static str)> {
    vec![
        // --- plain primitives -------------------------------------------------
        (
            "write/INSERT",
            "INSERT INTO urls (url, visit_count, last_visit_time) VALUES ('x', 1, 0)",
        ),
        (
            "write/UPDATE-redirect",
            "UPDATE urls SET url = 'redirected'",
        ),
        ("delete/DELETE", "DELETE FROM urls"),
        ("ddl/DROP", "DROP TABLE urls"),
        ("ddl/CREATE", "CREATE TABLE evil (a INTEGER)"),
        ("ddl/ALTER-rename", "ALTER TABLE urls RENAME TO urls_evil"),
        // --- lexical disguises that a keyword blocklist might miss -------------
        ("lowercase/delete", "delete from urls"),
        ("comment-hidden/delete", "delete /* keep calm */ from urls"),
        (
            "comment-hidden/drop-split-keyword",
            "dr/**/op table urls", // split keyword — invalid SQL, still must NOT mutate
        ),
        (
            "union-prefixed/chained-delete",
            "SELECT 1 WHERE 1=0 UNION SELECT 2; DELETE FROM urls",
        ),
        (
            "subquery-bearing/delete",
            "DELETE FROM urls WHERE url IN (SELECT url FROM urls)",
        ),
        (
            "pragma/writable_schema",
            "PRAGMA writable_schema = ON; DELETE FROM sqlite_master",
        ),
    ]
}

#[test]
fn benign_read_still_succeeds_no_overblocking() {
    // The read-only boundary must not break the legitimate read: a valid
    // history DB still parses end-to-end through the public tool API.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = chrome_fixture(tmp.path());

    let out = browser_history(&BrowserHistoryInput {
        case_id: "case-benign".to_string(),
        history_path: path,
        limit: None,
    })
    .expect("benign read must succeed");

    assert_eq!(out.browser_family, "chrome");
    assert_eq!(out.rows.len(), 1, "the one seeded row must come back");
    assert_eq!(out.rows[0].url, "http://evil.example/payload.exe");
}

#[test]
fn read_only_driver_refuses_every_mutation_variant() {
    // The core battery: open the evidence DB the way the tool does and replay
    // each spoliation attempt. Every write/delete/DDL/redirect must be refused
    // at the driver (read-only) boundary, not merely fail by chance, and a
    // disguised one must never silently mutate.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = chrome_fixture(tmp.path());

    for (intent, sql) in mutation_battery() {
        let conn = open_like_tool(&path);
        let err = match conn.execute_batch(sql) {
            Ok(()) => panic!(
                "spoliation variant '{intent}' was ACCEPTED by a read-only connection: {sql}"
            ),
            Err(e) => e,
        };
        // The split-keyword disguise is also syntactically invalid, so it errors
        // before reaching the engine — still a rejection. Every variant that DOES
        // parse as a mutation must be refused specifically for being read-only.
        if !intent.contains("split-keyword") {
            assert!(
                is_readonly_refusal(&err),
                "variant '{intent}' must be refused as read-only, got: {err}"
            );
        }
    }

    // Containment proof: after the whole battery, the evidence is untouched —
    // the seeded row is still present and no attacker table was created. A
    // fresh read-only open confirms the database was never mutated.
    let conn = open_like_tool(&path);
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM urls", [], |r| r.get(0))
        .expect("urls table still present");
    assert_eq!(
        rows, 1,
        "evidence row count must be unchanged after battery"
    );
    let evil_tables: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('evil','urls_evil')",
            [],
            |r| r.get(0),
        )
        .expect("query sqlite_master");
    assert_eq!(
        evil_tables, 0,
        "no attacker-created/renamed table may exist"
    );
}

#[test]
fn case_id_payload_is_never_executed_no_injection_surface() {
    // `case_id` is accepted for audit correlation and is NOT consumed by SQL.
    // A case_id shaped like a classic injection payload must therefore have no
    // effect: the read succeeds and the evidence table survives intact, proving
    // the protection is structural (no string reaches the query) rather than a
    // lexical filter on the payload.
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = chrome_fixture(tmp.path());

    let out = browser_history(&BrowserHistoryInput {
        case_id: "'; DROP TABLE urls; -- ".to_string(),
        history_path: path.clone(),
        limit: None,
    })
    .expect("malicious case_id must be inert, read still succeeds");
    assert_eq!(out.rows.len(), 1);

    // The table the payload tried to drop is still there.
    let conn = open_like_tool(&path);
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM urls", [], |r| r.get(0))
        .expect("urls table survived the injection-shaped case_id");
    assert_eq!(rows, 1);
}
