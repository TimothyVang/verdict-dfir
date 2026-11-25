//! Integration tests for `yara_scan`.
//!
//! Mirrors the established pattern: error paths, path-extension
//! predicate, serde roundtrip, plus a real-fixture round-trip
//! that compiles a tiny YARA rule and scans synthetic content.
//! Unlike the other tools, we don't need an external fixture for
//! the happy-path test — yara-x compiles strings, so we ship the
//! rule + target inline.

use std::path::{Path, PathBuf};

use findevil_mcp::{path_looks_like_yara_rules, yara_scan, YaraError, YaraInput};

fn sample_input(target: PathBuf, rules: PathBuf) -> YaraInput {
    YaraInput {
        case_id: "test-case".to_string(),
        target_path: target,
        rules_path: rules,
        recursive: false,
        limit: None,
    }
}

#[test]
fn yara_scan_errors_on_missing_target() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let rules = tmp.path().join("rules.yar");
    std::fs::write(&rules, "rule x { condition: true }").unwrap();
    let input = sample_input(tmp.path().join("nope.bin"), rules);
    let err = yara_scan(&input).unwrap_err();
    assert!(matches!(err, YaraError::TargetNotFound(_)));
}

#[test]
fn yara_scan_errors_on_missing_rules() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("data.bin");
    std::fs::write(&target, b"some bytes").unwrap();
    let input = sample_input(target, tmp.path().join("nope.yar"));
    let err = yara_scan(&input).unwrap_err();
    assert!(matches!(err, YaraError::RulesNotFound(_)));
}

#[test]
fn yara_scan_errors_on_empty_rules_dir() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("data.bin");
    std::fs::write(&target, b"some bytes").unwrap();
    let rules_dir = tmp.path().join("empty-rules");
    std::fs::create_dir(&rules_dir).unwrap();
    let input = sample_input(target, rules_dir);
    let err = yara_scan(&input).unwrap_err();
    assert!(matches!(err, YaraError::NoRulesFiles(_)));
}

#[test]
fn yara_scan_errors_on_compile_failure() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("data.bin");
    std::fs::write(&target, b"some bytes").unwrap();
    let rules = tmp.path().join("bad.yar");
    std::fs::write(&rules, "this is not yara at all").unwrap();
    let input = sample_input(target, rules);
    let err = yara_scan(&input).unwrap_err();
    assert!(matches!(err, YaraError::RulesCompileFailed { .. }));
}

#[test]
fn yara_scan_finds_match_with_pattern_preview() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let target = tmp.path().join("evil.bin");
    std::fs::write(&target, b"AAAA prefix EVIL_MARKER suffix BBBB").unwrap();
    let rules = tmp.path().join("evil.yar");
    std::fs::write(
        &rules,
        r#"
            rule detect_marker : malware family_x {
                strings:
                    $marker = "EVIL_MARKER"
                condition:
                    $marker
            }
        "#,
    )
    .unwrap();
    let input = sample_input(target, rules);
    let out = yara_scan(&input).expect("scan succeeds");

    assert_eq!(out.files_scanned, 1);
    assert_eq!(out.rules_compiled, 1);
    assert_eq!(out.scan_errors, 0);
    assert_eq!(out.matches.len(), 1, "expected one rule match");

    let m = &out.matches[0];
    assert_eq!(m.rule_name, "detect_marker");
    assert_eq!(m.namespace, "evil"); // from rules-file basename
    assert_eq!(
        m.tags.iter().map(String::as_str).collect::<Vec<_>>(),
        vec!["malware", "family_x"]
    );
    assert_eq!(m.pattern_matches.len(), 1);
    let p = &m.pattern_matches[0];
    assert_eq!(p.identifier, "$marker");
    assert_eq!(p.length, b"EVIL_MARKER".len());
    assert_eq!(p.preview_hex, hex::encode(b"EVIL_MARKER"));
    // offset: prefix is 12 bytes ("AAAA prefix ").
    assert_eq!(p.offset, 12);
    // file_path is absolute on this OS.
    assert!(m.file_path.contains("evil.bin"));
}

#[test]
fn yara_scan_recursive_dir_scan() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Keep target tree and rules tree separate so the recursive walk
    // doesn't pick up the rules file itself (which contains the
    // signature string and would self-match).
    let target_root = tmp.path().join("target");
    let nested = target_root.join("a/b/c");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("hit.bin"), b"FOO_TOKEN here").unwrap();
    std::fs::write(target_root.join("a/miss.bin"), b"nothing").unwrap();
    let rules = tmp.path().join("rules.yar");
    std::fs::write(
        &rules,
        r#"rule r { strings: $f = "FOO_TOKEN" condition: $f }"#,
    )
    .unwrap();

    let mut input = sample_input(target_root, rules);
    input.recursive = true;
    let out = yara_scan(&input).expect("scan succeeds");
    assert!(out.files_scanned >= 2, "scanned at least both files");
    // Exactly one match (in nested/hit.bin).
    assert_eq!(out.matches.len(), 1, "match found in nested dir");
    assert!(out.matches[0].file_path.contains("hit.bin"));
}

#[test]
fn yara_scan_limit_caps_match_count() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // Three files, all match.
    for i in 0..3 {
        std::fs::write(tmp.path().join(format!("f{i}.bin")), b"TOKEN").unwrap();
    }
    let rules = tmp.path().join("rules.yar");
    std::fs::write(&rules, r#"rule r { strings: $t = "TOKEN" condition: $t }"#).unwrap();
    let mut input = sample_input(tmp.path().to_path_buf(), rules);
    input.limit = Some(2);
    let out = yara_scan(&input).expect("scan succeeds");
    assert_eq!(out.matches.len(), 2, "limit honored");
}

#[test]
fn yara_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "target_path": "/case/extracted",
        "rules_path": "/case/rules/yara-forge.yar",
        "recursive": true,
        "limit": 50
    }"#;
    let inp: YaraInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.target_path, Path::new("/case/extracted"));
    assert_eq!(inp.rules_path, Path::new("/case/rules/yara-forge.yar"));
    assert!(inp.recursive);
    assert_eq!(inp.limit, Some(50));
}

#[test]
fn yara_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "target_path": "/x",
        "rules_path": "/r.yar",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<YaraInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn path_looks_like_yara_rules_cases() {
    assert!(path_looks_like_yara_rules(Path::new("rules.yar")));
    assert!(path_looks_like_yara_rules(Path::new("rules.YAR"))); // case-insensitive
    assert!(path_looks_like_yara_rules(Path::new("rules.yara")));
    assert!(path_looks_like_yara_rules(Path::new("rules.yarx")));
    assert!(path_looks_like_yara_rules(Path::new("/path/to/sigs.yara")));
    assert!(!path_looks_like_yara_rules(Path::new("rules.txt")));
    assert!(!path_looks_like_yara_rules(Path::new("evtx.evtx")));
    assert!(!path_looks_like_yara_rules(Path::new("no-extension")));
}
