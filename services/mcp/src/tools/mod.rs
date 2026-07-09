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

pub mod argsafe;
pub mod ausearch;
pub mod bits_parse;
pub mod browser_history;
pub mod bulk_extract;
pub mod case_id;
pub mod case_open;
pub mod cloud_audit;
pub mod disk;
pub mod email_parse;
pub mod evtx_query;
mod ewf_segments;
pub mod exif_parse;
pub mod ez_parse;
pub mod hashset_lookup;
pub mod hayabusa_scan;
pub mod indx_parse;
pub mod journalctl_query;
pub mod login_accounting;
pub mod mac_triage;
pub mod mft_timeline;
pub mod nfdump_query;
pub mod oe_dbx_parse;
pub mod pcap_triage;
pub mod plaso_parse;
pub mod prefetch_parse;
pub mod proc_runner;
pub mod pst_parse;
pub mod regf;
pub mod registry_query;
pub mod srum_parse;
pub mod suricata_eve;
pub mod sysmon_network_query;
pub mod thumbcache_parse;
pub mod usnjrnl_query;
pub mod vel_collect;
pub mod vol_malfind;
pub mod vol_pslist;
pub mod vol_psscan;
pub mod vol_psxview;
pub mod vol_run;
pub mod vss;
pub mod wmi_persist_parse;
pub mod yara_scan;
pub mod zeek_summary;

/// Convenience re-exports.
pub use ausearch::{
    ausearch, path_looks_like_audit_log, AuditRow, AusearchError, AusearchInput, AusearchOutput,
};
pub use bits_parse::{bits_parse, BitsParseError, BitsParseInput, BitsParseOutput};
pub use browser_history::{
    browser_history, path_looks_like_browser_history, BrowserHistoryError, BrowserHistoryInput,
    BrowserHistoryOutput, BrowserHistoryRow,
};
pub use bulk_extract::{
    bulk_extract, BulkExtractError, BulkExtractInput, BulkExtractOutput, BulkFeature, BulkScanner,
    StagedFeatureFile,
};
pub use case_id::is_valid_case_id;
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
pub use email_parse::{email_parse, EmailParseError, EmailParseInput, EmailParseOutput};
pub use evtx_query::{
    evtx_query, path_looks_like_evtx, EvtxError, EvtxQueryInput, EvtxQueryOutput, EvtxRow,
};
pub use exif_parse::{exif_parse, ExifParseError, ExifParseInput, ExifParseOutput};
pub use ez_parse::{ez_parse, is_allowed_ez_tool, EzParseError, EzParseInput, EzParseOutput};
pub use hashset_lookup::{
    hashset_lookup, HashLookupRow, HashsetKind, HashsetLoaded, HashsetLookupError,
    HashsetLookupInput, HashsetLookupOutput, HashsetRef, LookupDisposition, SetDisposition,
};
pub use hayabusa_scan::{
    hayabusa_scan, HayabusaAlert, HayabusaError, HayabusaInput, HayabusaOutput,
};
pub use indx_parse::{indx_parse, IndxError, IndxParseInput, IndxParseOutput};
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
pub use nfdump_query::{nfdump_query, NfdumpQueryError, NfdumpQueryInput, NfdumpQueryOutput};
pub use oe_dbx_parse::{oe_dbx_parse, OeDbxParseError, OeDbxParseInput, OeDbxParseOutput};
pub use pcap_triage::{
    path_looks_like_pcap, pcap_triage, PcapTriageError, PcapTriageInput, PcapTriageOutput,
};
pub use plaso_parse::{
    is_allowed_parser, plaso_parse, PlasoParseError, PlasoParseInput, PlasoParseOutput,
};
pub use prefetch_parse::{
    path_looks_like_prefetch, prefetch_parse, PrefetchError, PrefetchInput, PrefetchOutput,
};
pub use pst_parse::{pst_parse, PstError, PstMessage, PstParseInput, PstParseOutput};
pub use registry_query::{
    path_looks_like_hive, registry_query, RegistryEntry, RegistryError, RegistryInput,
    RegistryOutput, RegistryValue,
};
pub use srum_parse::{
    srum_parse, SrumError, SrumNetworkRow, SrumParseInput, SrumParseOutput, SrumTopTalker,
};
pub use suricata_eve::{suricata_eve, SuricataEveError, SuricataEveInput, SuricataEveOutput};
pub use sysmon_network_query::{
    path_looks_like_sysmon_evtx, sysmon_network_query, SysmonNetworkError, SysmonNetworkInput,
    SysmonNetworkOutput, SysmonNetworkRow,
};
pub use thumbcache_parse::{
    path_looks_like_thumbcache, thumbcache_parse, ThumbcacheEntry, ThumbcacheParseError,
    ThumbcacheParseInput, ThumbcacheParseOutput,
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
pub use vss::{
    vss_list, vss_mount, ShadowStore, VssError, VssListInput, VssListOutput, VssMountInput,
    VssMountOutput,
};
pub use wmi_persist_parse::{
    wmi_persist_parse, WmiPersistParseError, WmiPersistParseInput, WmiPersistParseOutput,
};
pub use yara_scan::{
    path_looks_like_yara_rules, yara_scan, YaraError, YaraInput, YaraMatch, YaraOutput,
    YaraPatternMatch,
};
pub use zeek_summary::{
    path_looks_like_zeek_log, zeek_summary, ZeekCount, ZeekSummaryError, ZeekSummaryInput,
    ZeekSummaryOutput,
};
