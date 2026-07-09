//! Integration tests for `hashset_lookup`.
//!
//! Mirrors the `browser_history` smoke pattern: library-level error paths and
//! fixtures built on the fly (no checked-in binaries), plus an end-to-end
//! drive through the stdio server registry so schema advertisement, unknown-
//! field denial, and the `_meta` envelope are exercised on the real wire
//! shape. All hash values are synthetic test fixtures (evidence-agnostic).

use std::io::Cursor;
use std::path::PathBuf;

use findevil_mcp::server::run_stdio_server_with_streams;
use findevil_mcp::tools::{
    hashset_lookup, HashsetLookupError, HashsetLookupInput, HashsetRef, LookupDisposition,
    SetDisposition,
};
use rusqlite::Connection;
use serde_json::{json, Value};

/// Synthetic MD5-length hex (32 chars).
const MD5_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
/// Synthetic SHA-256-length hex (64 chars).
const SHA256_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn sample_input(hashes: &[&str], hashset_paths: Vec<HashsetRef>) -> HashsetLookupInput {
    HashsetLookupInput {
        case_id: "test-case".to_string(),
        hashes: hashes.iter().map(ToString::to_string).collect(),
        hashset_paths,
    }
}

const fn bad_set(path: PathBuf) -> HashsetRef {
    HashsetRef {
        path,
        disposition: SetDisposition::KnownBad,
        name: None,
    }
}

/// Drive the real stdio server loop with one request line; return the
/// parsed JSON-RPC response.
fn drive(request: &Value) -> Value {
    let line = format!("{request}\n");
    let mut output: Vec<u8> = Vec::new();
    run_stdio_server_with_streams(Cursor::new(line.into_bytes()), &mut output)
        .expect("server loop");
    serde_json::from_str(String::from_utf8(output).expect("utf-8").trim()).expect("json response")
}

#[test]
fn hashset_lookup_input_rejects_unknown_fields() {
    let body = r#"{"case_id":"c1","hashes":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"rogue_field":1}"#;
    let err = serde_json::from_str::<HashsetLookupInput>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn hashset_ref_rejects_unknown_fields() {
    let body = r#"{"path":"/x/iocs.txt","disposition":"known_bad","rogue":true}"#;
    let err = serde_json::from_str::<HashsetRef>(body).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("rogue") || msg.contains("unknown field"));
}

#[test]
fn hashset_lookup_rejects_invalid_hash() {
    let err = hashset_lookup(&sample_input(&["zz-not-hex"], vec![])).unwrap_err();
    assert!(matches!(
        err,
        HashsetLookupError::InvalidHash { index: 0, .. }
    ));
}

#[test]
fn hashset_lookup_text_fixture_end_to_end() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("iocs.txt");
    std::fs::write(
        &path,
        format!("# comment\n{}\n", MD5_A.to_ascii_uppercase()),
    )
    .unwrap();

    let out =
        hashset_lookup(&sample_input(&[MD5_A, SHA256_C], vec![bad_set(path)])).expect("lookup");
    assert_eq!(out.hashes_checked, 2);
    assert_eq!(out.results[0].hash, MD5_A);
    assert_eq!(out.results[0].disposition, LookupDisposition::KnownBad);
    assert_eq!(out.results[1].disposition, LookupDisposition::Unknown);
    assert_eq!(out.sets_loaded.len(), 1);
    assert!(out.sets_loaded[0].error.is_none());
}

#[test]
fn server_advertises_hashset_lookup_with_read_only_annotations() {
    let resp = drive(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}));
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    let tool = tools
        .iter()
        .find(|t| t["name"] == "hashset_lookup")
        .expect("hashset_lookup advertised");
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert_eq!(tool["annotations"]["destructiveHint"], false);
    assert_eq!(tool["annotations"]["idempotentHint"], true);
    assert_eq!(tool["annotations"]["openWorldHint"], false);
    assert!(tool["inputSchema"].is_object());
}

#[test]
fn server_tools_call_matches_sqlite_fixture() {
    // Generic-schema SQLite fixture, driven through the real registry.
    let tmp = tempfile::tempdir().expect("tempdir");
    let db_path = tmp.path().join("bad.sqlite");
    let conn = Connection::open(&db_path).unwrap();
    conn.execute("CREATE TABLE hashes (hash TEXT)", []).unwrap();
    conn.execute("INSERT INTO hashes (hash) VALUES (?1)", [SHA256_C])
        .unwrap();
    drop(conn);

    let resp = drive(&json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "hashset_lookup",
            "arguments": {
                "case_id": "smoke-case",
                "hashes": [SHA256_C.to_ascii_uppercase(), MD5_A],
                "hashset_paths": [
                    {"path": db_path.to_string_lossy(), "disposition": "known_bad", "name": "smoke-iocs"}
                ]
            }
        }
    }));

    assert!(
        resp.get("error").is_none(),
        "tools/call must succeed: {resp}"
    );
    let text = resp["result"]["content"][0]["text"]
        .as_str()
        .expect("text content");
    let payload: Value = serde_json::from_str(text).expect("payload json");
    assert_eq!(payload["case_id"], "smoke-case");
    assert_eq!(payload["hashes_checked"], 2);
    // Sorted by hash: "aaa…" (unknown) before "ccc…" (known_bad).
    assert_eq!(payload["results"][0]["hash"], MD5_A);
    assert_eq!(payload["results"][0]["disposition"], "unknown");
    assert_eq!(payload["results"][1]["hash"], SHA256_C);
    assert_eq!(payload["results"][1]["disposition"], "known_bad");
    assert_eq!(payload["results"][1]["matched_sets"][0], "smoke-iocs");
    assert_eq!(payload["sets_loaded"][0]["kind"], "sqlite_generic");
    assert_eq!(resp["result"]["_meta"]["tool"], "hashset_lookup");
    assert!(resp["result"]["_meta"]["output_sha256"].is_string());
}

#[test]
fn server_tools_call_denies_unknown_argument_fields() {
    let resp = drive(&json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "hashset_lookup",
            "arguments": {
                "case_id": "smoke-case",
                "hashes": [MD5_A],
                "rogue_field": "nope"
            }
        }
    }));
    assert_eq!(
        resp["error"]["code"], -32602,
        "unknown field must be denied"
    );
    let msg = resp["error"]["message"].as_str().expect("message");
    assert!(msg.contains("rogue_field") || msg.contains("unknown field"));
}

#[test]
fn server_tools_call_rejects_bad_hash_as_invalid_params() {
    let resp = drive(&json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "hashset_lookup",
            "arguments": {"case_id": "smoke-case", "hashes": ["nope"]}
        }
    }));
    assert_eq!(resp["error"]["code"], -32602);
}
