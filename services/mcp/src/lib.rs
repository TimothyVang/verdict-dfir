//! Find Evil! typed MCP server — library face.
//!
//! Spec #2 §3 + §6. The crate's binary ([`bin/findevil-mcp`]) wires
//! these modules into a hand-rolled stdio JSON-RPC 2.0 server in
//! [`server`] (see CLAUDE.md "Spec/code divergences" §5 — the spec
//! lists `rmcp 0.16.x` as the framework but we ship a hand-rolled
//! implementation pinned to MCP 2024-11-05 for wire-format
//! stability across rmcp's API churn). The library face lets
//! integration tests + the Python agent's in-process harness
//! exercise tool modules directly without a full subprocess
//! round-trip.
//!
//! Invariants (see `CLAUDE.md`):
//! - No `execute_shell` tool, ever.
//! - Every tool response carries `tool_call_id` (UUID4) + SHA-256
//!   of the raw output bytes.
//! - AGPL/GPL backing tools (Hayabusa, Chainsaw, Volatility3,
//!   Velociraptor, YARA) are invoked via `std::process::Command`,
//!   never linked.

#![forbid(unsafe_code)]

pub mod crypto;
pub mod sanitize;
pub mod server;
pub mod tools;

/// Crate version baked in at compile time — surfaced in the MCP
/// server's capability handshake and in audit logs.
pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
pub(crate) static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Re-exports for test + binary convenience.
pub use crate::crypto::merkle::{verify_inclusion_proof, InclusionProof, MerkleError, MerkleTree};
pub use crate::tools::ausearch::{
    ausearch, path_looks_like_audit_log, AuditRow, AusearchError, AusearchInput, AusearchOutput,
};
pub use crate::tools::browser_history::{
    browser_history, path_looks_like_browser_history, BrowserHistoryError, BrowserHistoryInput,
    BrowserHistoryOutput, BrowserHistoryRow,
};
pub use crate::tools::bulk_extract::{
    build_bulk_args, bulk_extract, compare_offset, image_name_is_dash_leading, parse_feature_line,
    sanitize_stem, scrub_absolute_paths, sort_features, BulkExtractError, BulkExtractInput,
    BulkExtractOutput, BulkFeature, BulkScanner, StagedFeatureFile,
};
pub use crate::tools::case_id::is_valid_case_id;
pub use crate::tools::case_open::{case_open, CaseHandle, CaseOpenError, CaseOpenInput};
pub use crate::tools::cloud_audit::{
    cloud_audit, is_allowed_provider, CloudAuditError, CloudAuditInput, CloudAuditOutput,
    CloudEvent,
};
pub use crate::tools::disk::{
    disk_extract_artifacts, disk_mount, disk_unmount, DiskError, DiskExtractArtifactsInput,
    DiskExtractArtifactsOutput, DiskMode, DiskMountInput, DiskMountOutput, DiskUnmountInput,
    DiskUnmountOutput, ExtractedDiskArtifact, SessionResource,
};
pub use crate::tools::evtx_query::{
    evtx_query, path_looks_like_evtx, EvtxError, EvtxQueryInput, EvtxQueryOutput, EvtxRow,
};
pub use crate::tools::ez_parse::{
    ez_parse, is_allowed_ez_tool, EzParseError, EzParseInput, EzParseOutput,
};
pub use crate::tools::hayabusa_scan::{
    hayabusa_scan, HayabusaAlert, HayabusaError, HayabusaInput, HayabusaOutput,
};
pub use crate::tools::indx_parse::{indx_parse, IndxError, IndxParseInput, IndxParseOutput};
pub use crate::tools::journalctl_query::{
    journalctl_query, path_looks_like_journal, JournalRow, JournalctlQueryError,
    JournalctlQueryInput, JournalctlQueryOutput,
};
pub use crate::tools::login_accounting::{
    login_accounting, path_looks_like_accounting, LoginAccountingError, LoginAccountingInput,
    LoginAccountingOutput, LoginRecord,
};
pub use crate::tools::mac_triage::{
    is_allowed_module, mac_triage, MacTriageError, MacTriageInput, MacTriageOutput,
};
pub use crate::tools::mft_timeline::{
    mft_timeline, path_looks_like_mft, MftEntryRow, MftError, MftInput, MftOutput,
};
pub use crate::tools::nfdump_query::{
    nfdump_query, NfdumpQueryError, NfdumpQueryInput, NfdumpQueryOutput,
};
pub use crate::tools::pcap_triage::{
    path_looks_like_pcap, pcap_triage, PcapTriageError, PcapTriageInput, PcapTriageOutput,
};
pub use crate::tools::plaso_parse::{
    is_allowed_parser, plaso_parse, PlasoParseError, PlasoParseInput, PlasoParseOutput,
};
pub use crate::tools::prefetch_parse::{
    path_looks_like_prefetch, prefetch_parse, PrefetchError, PrefetchInput, PrefetchOutput,
};
pub use crate::tools::registry_query::{
    path_looks_like_hive, registry_query, RegistryEntry, RegistryError, RegistryInput,
    RegistryOutput, RegistryValue,
};
pub use crate::tools::suricata_eve::{
    suricata_eve, SuricataEveError, SuricataEveInput, SuricataEveOutput,
};
pub use crate::tools::sysmon_network_query::{
    path_looks_like_sysmon_evtx, sysmon_network_query, SysmonNetworkError, SysmonNetworkInput,
    SysmonNetworkOutput, SysmonNetworkRow,
};
pub use crate::tools::usnjrnl_query::{
    path_looks_like_usnjrnl, usnjrnl_query, UsnJrnlEntry, UsnJrnlError, UsnJrnlInput, UsnJrnlOutput,
};
pub use crate::tools::vel_collect::{
    vel_collect, VelCollectError, VelCollectInput, VelCollectOutput, VelRow,
};
pub use crate::tools::vol_malfind::{
    vol_malfind, VolInjection, VolMalfindError, VolMalfindInput, VolMalfindOutput,
};
pub use crate::tools::vol_pslist::{
    path_looks_like_memory_image, vol_pslist, VolError, VolProcess, VolPslistInput, VolPslistOutput,
};
pub use crate::tools::vol_psscan::{
    vol_psscan, VolPsscanError, VolPsscanInput, VolPsscanOutput, VolPsscanProcess,
};
pub use crate::tools::vol_psxview::{
    vol_psxview, VolPsxviewError, VolPsxviewInput, VolPsxviewOutput, VolPsxviewRow,
};
pub use crate::tools::vol_run::{
    is_allowed_plugin, vol_run, VolRunError, VolRunInput, VolRunOutput,
};
pub use crate::tools::yara_scan::{
    path_looks_like_yara_rules, yara_scan, YaraError, YaraInput, YaraMatch, YaraOutput,
    YaraPatternMatch,
};
pub use crate::tools::zeek_summary::{
    path_looks_like_zeek_log, zeek_summary, ZeekCount, ZeekSummaryError, ZeekSummaryInput,
    ZeekSummaryOutput,
};
