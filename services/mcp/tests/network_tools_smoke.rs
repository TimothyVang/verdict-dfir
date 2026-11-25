//! Focused smoke tests for network-oriented Rust MCP tools.

use std::path::{Path, PathBuf};

use findevil_mcp::{
    path_looks_like_pcap, path_looks_like_sysmon_evtx, path_looks_like_zeek_log, pcap_triage,
    sysmon_network_query, zeek_summary, PcapTriageError, PcapTriageInput, SysmonNetworkError,
    SysmonNetworkInput, ZeekSummaryInput,
};

#[test]
fn zeek_summary_parses_synthetic_logs() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("conn.log"),
        "#separator \\x09\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\n1.0\tC1\t10.0.0.5\t44444\t8.8.8.8\t53\tudp\tdns\t0.1\t40\t80\tSF\n2.0\tC2\t10.0.0.5\t44445\t1.2.3.4\t443\ttcp\tssl\t1.0\t100\t200\tSF\n",
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("dns.log"),
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\n1.0\tC1\t10.0.0.5\t8.8.8.8\texample.com\n",
    )
    .unwrap();
    let out = zeek_summary(&ZeekSummaryInput {
        case_id: "case".to_string(),
        zeek_path: tmp.path().to_path_buf(),
        limit: None,
    })
    .expect("zeek summary");
    assert_eq!(out.conn_count, 2);
    assert_eq!(out.dns_count, 1);
    assert_eq!(out.top_hosts[0].value, "10.0.0.5");
    assert_eq!(out.top_dns_queries[0].value, "example.com");
}

#[test]
fn network_tools_report_missing_inputs_as_user_errors() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let sysmon_err = sysmon_network_query(&SysmonNetworkInput {
        case_id: "case".to_string(),
        evtx_path: tmp.path().join("missing.evtx"),
        event_ids: None,
        since_iso: None,
        until_iso: None,
        image_contains: None,
        destination_ip: None,
        destination_port: None,
        limit: None,
    })
    .unwrap_err();
    assert!(matches!(sysmon_err, SysmonNetworkError::EvtxNotFound(_)));

    let pcap_err = pcap_triage(&PcapTriageInput {
        case_id: "case".to_string(),
        pcap_path: tmp.path().join("missing.pcap"),
        analyzer: None,
        limit: None,
    })
    .unwrap_err();
    assert!(matches!(pcap_err, PcapTriageError::PcapNotFound(_)));
}

#[test]
fn network_path_helpers_match_expected_extensions() {
    assert!(path_looks_like_sysmon_evtx(Path::new("Sysmon.evtx")));
    assert!(!path_looks_like_sysmon_evtx(Path::new("Security.evtx")));
    assert!(path_looks_like_zeek_log(Path::new("conn.log")));
    assert!(path_looks_like_pcap(Path::new("capture.pcapng")));
    assert!(!path_looks_like_pcap(Path::new("capture.txt")));
}

#[test]
fn pcap_input_rejects_unknown_fields() {
    let body = r#"{
        "case_id": "case",
        "pcap_path": "/tmp/capture.pcap",
        "rogue_field": true
    }"#;
    let err = serde_json::from_str::<PcapTriageInput>(body).unwrap_err();
    assert!(err.to_string().contains("rogue_field") || err.to_string().contains("unknown field"));
}

#[test]
fn sysmon_input_accepts_network_filters() {
    let body = r#"{
        "case_id": "case",
        "evtx_path": "/tmp/Sysmon.evtx",
        "event_ids": [3],
        "destination_ip": "1.2.3.4",
        "destination_port": 443,
        "limit": 10
    }"#;
    let input: SysmonNetworkInput = serde_json::from_str(body).unwrap();
    assert_eq!(input.evtx_path, PathBuf::from("/tmp/Sysmon.evtx"));
    assert_eq!(input.destination_port, Some(443));
}
