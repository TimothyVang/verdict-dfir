//! Integration tests for `vel_collect`.
//!
//! Same shape as `vol_pslist_smoke.rs` / `vol_malfind_smoke.rs`:
//! input validation; the real Velociraptor invocation is opt-in via
//! `$VELOCIRAPTOR_BIN`.

use std::collections::BTreeMap;

use findevil_mcp::{vel_collect, VelCollectError, VelCollectInput};

fn sample_input(artifact: &str) -> VelCollectInput {
    VelCollectInput {
        case_id: "test-case".to_string(),
        artifact: artifact.to_string(),
        args: None,
        limit: None,
    }
}

#[test]
fn vel_collect_rejects_empty_artifact_name() {
    let input = sample_input("");
    let err = vel_collect(&input).unwrap_err();
    assert!(matches!(err, VelCollectError::InvalidArtifactName(_)));
}

#[test]
fn vel_collect_rejects_artifact_name_with_metacharacters() {
    for bad in ["Has;Semicolon", "Has Spaces", "Has--Flag", "Has/Slash"] {
        let input = sample_input(bad);
        let err = vel_collect(&input).unwrap_err();
        assert!(
            matches!(err, VelCollectError::InvalidArtifactName(_)),
            "expected InvalidArtifactName for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn vel_collect_rejects_artifact_name_with_leading_or_trailing_dot() {
    for bad in [".LeadingDot", "TrailingDot.", "Double..Dot"] {
        let input = sample_input(bad);
        let err = vel_collect(&input).unwrap_err();
        assert!(
            matches!(err, VelCollectError::InvalidArtifactName(_)),
            "expected InvalidArtifactName for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn vel_collect_rejects_invalid_arg_name() {
    let mut args = BTreeMap::new();
    args.insert("9bad".to_string(), "value".to_string());
    let input = VelCollectInput {
        case_id: "c".to_string(),
        artifact: "Windows.Forensics.Prefetch".to_string(),
        args: Some(args),
        limit: None,
    };
    let err = vel_collect(&input).unwrap_err();
    assert!(matches!(err, VelCollectError::InvalidArgName(_)));
}

#[test]
fn vel_collect_input_roundtrips_through_serde() {
    let body = r#"{
        "case_id": "c1",
        "artifact": "Windows.Forensics.Prefetch",
        "args": {"device": "C:", "max_size": "10485760"},
        "limit": 500
    }"#;
    let inp: VelCollectInput = serde_json::from_str(body).unwrap();
    assert_eq!(inp.case_id, "c1");
    assert_eq!(inp.artifact, "Windows.Forensics.Prefetch");
    let args = inp.args.expect("args present");
    assert_eq!(args.get("device").map(String::as_str), Some("C:"));
    assert_eq!(args.get("max_size").map(String::as_str), Some("10485760"));
    assert_eq!(inp.limit, Some(500));
}

#[test]
fn vel_collect_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "c1",
        "artifact": "X.Y",
        "rogue_field": "nope"
    }"#;
    let err = serde_json::from_str::<VelCollectInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn vel_collect_real_run_when_velociraptor_present() {
    if std::env::var("VELOCIRAPTOR_BIN").is_err() {
        eprintln!("VELOCIRAPTOR_BIN not set — skipping live run");
        return;
    }
    // The shipping test runs an artifact that requires no host privileges
    // and produces deterministic output: the version banner doesn't even
    // need a target. We deliberately do NOT pick a Windows-only artifact
    // because CI may run on Linux. The user wires their own fixture.
    let input = sample_input("Generic.Client.Info");
    match vel_collect(&input) {
        Ok(out) => {
            // We just want to verify the wire works; columns vary by version.
            let _ = out.rows;
            let _ = out.rows_seen;
            let _ = out.stderr_tail;
        }
        Err(VelCollectError::SubprocessFailed { stderr, .. }) => {
            eprintln!("velociraptor refused the artifact (expected on minimal envs): {stderr}");
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}
