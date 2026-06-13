//! Typed DFIR tool surface.
//!
//! Each submodule is one MCP tool. Every module exports:
//!   * an `Input` struct (the Pydantic-equivalent JSON shape the
//!     agent sends),
//!   * an output type that implements [`serde::Serialize`],
//!   * an error type `<Name>Error` with `thiserror::Error`,
//!   * an async (or sync) entrypoint function callable from the
//!     hand-rolled stdio JSON-RPC 2.0 dispatcher in
//!     `crate::server` (see CLAUDE.md "Spec/code divergences" §5).
//!
//! Constraints from Spec #2 §3:
//!   * No tool exposes raw shell exec.
//!   * Every tool result is reproducible from the input + on-disk
//!     evidence alone (no network side-effects).
//!   * Every tool is testable in isolation via integration tests
//!     under `services/mcp/tests/`.

pub mod ausearch;
pub mod browser_history;
pub mod case_open;
pub mod cloud_audit;
pub mod disk;
pub mod evtx_query;
pub mod ez_parse;
pub mod hayabusa_scan;
pub mod journalctl_query;
pub mod login_accounting;
pub mod mac_triage;
pub mod mft_timeline;
pub mod pcap_triage;
pub mod plaso_parse;
pub mod prefetch_parse;
pub mod regf;
pub mod registry_query;
pub mod sysmon_network_query;
pub mod usnjrnl_query;
pub mod vel_collect;
pub mod vol_malfind;
pub mod vol_pslist;
pub mod vol_psscan;
pub mod vol_psxview;
pub mod vol_run;
pub mod yara_scan;
pub mod zeek_summary;

/// Convenience re-exports.
pub use ausearch::{
    ausearch, path_looks_like_audit_log, AuditRow, AusearchError, AusearchInput, AusearchOutput,
};
pub use browser_history::{
    browser_history, path_looks_like_browser_history, BrowserHistoryError, BrowserHistoryInput,
    BrowserHistoryOutput, BrowserHistoryRow,
};
pub use case_open::{case_open, CaseHandle, CaseOpenError, CaseOpenInput};
pub use cloud_audit::{
    cloud_audit, is_allowed_provider, CloudAuditError, CloudAuditInput, CloudAuditOutput,
    CloudEvent,
};
pub use disk::{
    disk_extract_artifacts, disk_mount, disk_unmount, DiskError, DiskExtractArtifactsInput,
    DiskExtractArtifactsOutput, DiskMode, DiskMountInput, DiskMountOutput, DiskUnmountInput,
    DiskUnmountOutput, ExtractedDiskArtifact, SessionResource,
};
pub use evtx_query::{
    evtx_query, path_looks_like_evtx, EvtxError, EvtxQueryInput, EvtxQueryOutput, EvtxRow,
};
pub use ez_parse::{ez_parse, is_allowed_ez_tool, EzParseError, EzParseInput, EzParseOutput};
pub use hayabusa_scan::{
    hayabusa_scan, HayabusaAlert, HayabusaError, HayabusaInput, HayabusaOutput,
};
pub use journalctl_query::{
    journalctl_query, path_looks_like_journal, JournalRow, JournalctlQueryError,
    JournalctlQueryInput, JournalctlQueryOutput,
};
pub use login_accounting::{
    login_accounting, path_looks_like_accounting, LoginAccountingError, LoginAccountingInput,
    LoginAccountingOutput, LoginRecord,
};
pub use mac_triage::{
    is_allowed_module, mac_triage, MacTriageError, MacTriageInput, MacTriageOutput,
};
pub use mft_timeline::{
    mft_timeline, path_looks_like_mft, MftEntryRow, MftError, MftInput, MftOutput,
};
pub use pcap_triage::{
    path_looks_like_pcap, pcap_triage, PcapTriageError, PcapTriageInput, PcapTriageOutput,
};
pub use plaso_parse::{
    is_allowed_parser, plaso_parse, PlasoParseError, PlasoParseInput, PlasoParseOutput,
};
pub use prefetch_parse::{
    path_looks_like_prefetch, prefetch_parse, PrefetchError, PrefetchInput, PrefetchOutput,
};
pub use registry_query::{
    path_looks_like_hive, registry_query, RegistryEntry, RegistryError, RegistryInput,
    RegistryOutput, RegistryValue,
};
pub use sysmon_network_query::{
    path_looks_like_sysmon_evtx, sysmon_network_query, SysmonNetworkError, SysmonNetworkInput,
    SysmonNetworkOutput, SysmonNetworkRow,
};
pub use usnjrnl_query::{
    path_looks_like_usnjrnl, usnjrnl_query, UsnJrnlEntry, UsnJrnlError, UsnJrnlInput, UsnJrnlOutput,
};
pub use vel_collect::{vel_collect, VelCollectError, VelCollectInput, VelCollectOutput, VelRow};
pub use vol_malfind::{
    vol_malfind, VolInjection, VolMalfindError, VolMalfindInput, VolMalfindOutput,
};
pub use vol_pslist::{
    path_looks_like_memory_image, vol_pslist, VolError, VolProcess, VolPslistInput, VolPslistOutput,
};
pub use vol_psscan::{
    vol_psscan, VolPsscanError, VolPsscanInput, VolPsscanOutput, VolPsscanProcess,
};
pub use vol_psxview::{
    vol_psxview, VolPsxviewError, VolPsxviewInput, VolPsxviewOutput, VolPsxviewRow,
};
pub use vol_run::{is_allowed_plugin, vol_run, VolRunError, VolRunInput, VolRunOutput};
pub use yara_scan::{
    path_looks_like_yara_rules, yara_scan, YaraError, YaraInput, YaraMatch, YaraOutput,
    YaraPatternMatch,
};
pub use zeek_summary::{
    path_looks_like_zeek_log, zeek_summary, ZeekCount, ZeekSummaryError, ZeekSummaryInput,
    ZeekSummaryOutput,
};
