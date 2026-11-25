//! Integration tests for services/mcp tool modules.
//!
//! Spec #2 §12 AC scaffolding. Each test writes a synthetic
//! evidence file into a tempdir, overrides `FINDEVIL_HOME`, and
//! exercises one tool end-to-end — asserting the typed return
//! shape, on-disk side effects, and error paths the agent will
//! rely on.

use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard, OnceLock};

use findevil_mcp::{
    case_open, disk_extract_artifacts, disk_mount, disk_unmount, CaseHandle, CaseOpenError,
    CaseOpenInput, DiskExtractArtifactsInput, DiskMode, DiskMountInput, DiskUnmountInput,
};

/// Global lock that serializes env-var manipulation across every
/// test in this file. Cargo runs tests in parallel by default and
/// `std::env::set_var("FINDEVIL_HOME", …)` is a process-global
/// mutation — without this mutex, two tests racing to set their
/// own HOME value will stomp each other's tempdir override.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// RAII guard around `FINDEVIL_HOME` that (1) acquires the global
/// env-lock so parallel tests serialize, and (2) restores the prior
/// value on drop. Hold it for the entire body of a test.
///
/// The `_lock` field is only used for its `Drop` impl; clippy
/// correctly notices it's underscore-prefixed but structurally used
/// — the allow-list below acknowledges the pattern is intentional.
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

/// Points `disk_extract_artifacts` at fake `fls`/`icat` binaries that serve a
/// canned filesystem listing plus per-inode bytes, so the TSK direct-read
/// extraction path (`fls -r -p` enumerate → `icat` extract) is exercised
/// end-to-end without a real disk image. Real `fls`/`icat` reject a synthetic
/// image with "Cannot determine file system type", which is why mock-mode
/// directory fixtures no longer reach the extraction code.
///
/// Install only while a [`HomeGuard`] is held — that guard's env-lock
/// serializes these process-global overrides — and let this drop *before* the
/// `HomeGuard` so the overrides are restored while the lock is still held.
#[cfg(unix)]
struct FakeTsk {
    fls_prev: Option<String>,
    icat_prev: Option<String>,
}

#[cfg(unix)]
impl FakeTsk {
    fn install(dir: &std::path::Path, files: &[(&str, &str, &[u8])]) -> Self {
        let allocated: Vec<(&str, &str, &[u8], bool)> = files
            .iter()
            .map(|(inode, path, bytes)| (*inode, *path, *bytes, true))
            .collect();
        Self::install_with_deleted(dir, &allocated)
    }

    /// Same as [`Self::install`] but each row carries an `allocated` flag, so a
    /// test can stage the anti-forensic shape: a directory whose entries all
    /// come back from `fls` marked deleted (`*`).
    fn install_with_deleted(dir: &std::path::Path, files: &[(&str, &str, &[u8], bool)]) -> Self {
        use std::fmt::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let blobs = dir.join("blobs");
        fs::create_dir_all(&blobs).unwrap();
        let mut listing = String::new();
        for (inode, path, bytes, allocated) in files {
            // fls -p line shape: `r/r <inode>:\t<relative/path>`; a deleted
            // entry gets the `*` marker between the type and the inode.
            let marker = if *allocated { "" } else { "* " };
            writeln!(listing, "r/r {marker}{inode}:\t{path}").unwrap();
            fs::write(blobs.join(format!("{inode}.bin")), bytes).unwrap();
        }
        let fls_txt = dir.join("fls.txt");
        fs::write(&fls_txt, listing).unwrap();

        // fls ignores its args and prints the canned listing; icat extracts the
        // last argument (the inode) from `<image> <inode>` and streams that
        // blob, mirroring how `disk_extract_artifacts` invokes them.
        let fls = dir.join("fake_fls.sh");
        fs::write(&fls, format!("#!/bin/sh\ncat '{}'\n", fls_txt.display())).unwrap();
        let icat = dir.join("fake_icat.sh");
        fs::write(
            &icat,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\ncat '{}'/\"$last\".bin\n",
                blobs.display()
            ),
        )
        .unwrap();
        for script in [&fls, &icat] {
            let mut perm = fs::metadata(script).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(script, perm).unwrap();
        }

        let fls_prev = std::env::var("FINDEVIL_FLS_BIN").ok();
        let icat_prev = std::env::var("FINDEVIL_ICAT_BIN").ok();
        std::env::set_var("FINDEVIL_FLS_BIN", &fls);
        std::env::set_var("FINDEVIL_ICAT_BIN", &icat);
        Self {
            fls_prev,
            icat_prev,
        }
    }
}

#[cfg(unix)]
impl Drop for FakeTsk {
    fn drop(&mut self) {
        let restore = |key: &str, prev: &Option<String>| match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        };
        restore("FINDEVIL_FLS_BIN", &self.fls_prev);
        restore("FINDEVIL_ICAT_BIN", &self.icat_prev);
    }
}

fn write_evidence_image(dir: &std::path::Path, bytes: &[u8]) -> PathBuf {
    let p = dir.join("case.e01");
    fs::write(&p, bytes).expect("write fixture evidence");
    p
}

#[test]
fn case_open_registers_case_and_hashes_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let image = write_evidence_image(tmp.path(), b"hello evidence world");

    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: None,
        label: Some("integration-smoke".to_string()),
    };

    let handle: CaseHandle = case_open(&input).expect("case_open ok");

    // Shape assertions.
    assert_eq!(
        handle.image_size_bytes,
        b"hello evidence world".len() as u64
    );
    assert_eq!(handle.image_hash.len(), 64, "sha256 hex is 64 chars");
    assert!(handle
        .image_hash
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert!(handle.id.len() == 36, "uuid v4 canonical form");
    assert!(handle.case_dir.is_dir(), "case dir created");
    assert!(
        handle.case_dir.starts_with(tmp.path().join("cases")),
        "case dir under FINDEVIL_HOME/cases/"
    );
    assert_eq!(handle.db_path, handle.case_dir.join("evidence.ddb"));

    // Manifest persisted.
    let manifest = handle.case_dir.join("case.json");
    assert!(manifest.is_file(), "case.json written");
    let manifest_text = fs::read_to_string(&manifest).unwrap();
    assert!(
        manifest_text.contains(&handle.image_hash),
        "manifest embeds image_hash"
    );
    assert!(
        manifest_text.contains("integration-smoke"),
        "manifest preserves label"
    );
}

#[test]
fn case_open_rejects_mismatched_expected_hash() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let image = write_evidence_image(tmp.path(), b"mismatched");
    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: Some(
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        ),
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    match err {
        CaseOpenError::ImageHashMismatch { expected, actual } => {
            assert_eq!(expected, "0".repeat(64));
            assert_eq!(actual.len(), 64);
            assert_ne!(actual, expected);
        }
        other => panic!("expected ImageHashMismatch, got {other:?}"),
    }
}

#[test]
fn case_open_errors_on_missing_image() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let input = CaseOpenInput {
        image_path: tmp.path().join("does-not-exist.e01"),
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(matches!(err, CaseOpenError::ImageNotFound(_)));
}

#[test]
fn case_open_errors_on_directory_not_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    let subdir = tmp.path().join("i-am-a-dir");
    fs::create_dir_all(&subdir).unwrap();

    let input = CaseOpenInput {
        image_path: subdir,
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(matches!(err, CaseOpenError::ImageNotRegular(_)));
}

/// The input doc promises "the tool does not follow symlinks" — prove it.
/// A symlink inside the evidence dir pointing at a file *outside* it must
/// be refused, otherwise a crafted evidence drop could pull arbitrary
/// host files (e.g. /etc/shadow) into the hashed chain of custody.
#[cfg(unix)]
#[test]
fn case_open_refuses_symlinked_evidence_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());

    // A real file outside the evidence drop zone...
    let outside = tempfile::tempdir().expect("outside tempdir");
    let target = outside.path().join("host-secret.bin");
    fs::write(&target, b"not-your-evidence").unwrap();

    // ...reached through a symlink placed where evidence would live.
    let link = tmp.path().join("evidence.dd");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let input = CaseOpenInput {
        image_path: link,
        expected_sha256: None,
        label: None,
    };

    let err = case_open(&input).unwrap_err();
    assert!(
        matches!(err, CaseOpenError::ImageNotRegular(_)),
        "symlinked evidence must be refused, got: {err:?}"
    );
}

#[test]
fn case_open_hashes_match_known_vector() {
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"");

    let handle = case_open(&CaseOpenInput {
        image_path: image,
        expected_sha256: Some(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        label: None,
    })
    .expect("empty-file hash matches known vector");
    assert_eq!(
        handle.image_hash,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(handle.image_size_bytes, 0);
}

#[test]
fn case_open_two_calls_produce_distinct_case_ids() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"same-bytes");
    let input = CaseOpenInput {
        image_path: image,
        expected_sha256: None,
        label: None,
    };
    let h1 = case_open(&input).unwrap();
    let h2 = case_open(&input).unwrap();
    assert_ne!(h1.id, h2.id, "case_ids are per-call UUIDs");
    assert_eq!(h1.image_hash, h2.image_hash, "same bytes hash the same");
}

#[test]
#[cfg(unix)]
fn disk_mount_extract_unmount_uses_session_resource_ledger_in_mock_mode() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-ledger".to_string()),
    })
    .expect("case_open ok");

    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("100", "$MFT", b"mft bytes"),
            ("101", "Windows/Prefetch/CMD.EXE-12345678.pf", b"pf"),
            ("102", "Windows/System32/config/SOFTWARE", b"hive"),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");
    assert_eq!(mounted.status, "mounted");
    assert!(mounted.ledger_path.is_file());

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id.clone(),
        mount_id: mounted.mount_id.clone(),
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
    })
    .expect("extract artifacts");
    let classes: Vec<&str> = extracted
        .artifacts
        .iter()
        .map(|a| a.artifact_class.as_str())
        .collect();
    assert!(classes.contains(&"mft"), "classes={classes:?}");
    assert!(classes.contains(&"prefetch"), "classes={classes:?}");
    assert!(classes.contains(&"registry"), "classes={classes:?}");
    assert_eq!(extracted.artifacts_skipped_oversize, 0);
    assert_eq!(extracted.max_artifact_bytes, 1024);
    for artifact in &extracted.artifacts {
        assert!(artifact.extracted_path.is_file());
        assert!(artifact.extracted_path.starts_with(&extracted.output_dir));
    }

    let unmounted = disk_unmount(&DiskUnmountInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        mode: DiskMode::Mock,
    })
    .expect("mock unmount succeeds");
    assert_eq!(unmounted.status, "unmounted");

    let ledger_text = fs::read_to_string(handle.case_dir.join("session_resources.json")).unwrap();
    assert!(ledger_text.contains("disk_mount"));
    assert!(ledger_text.contains("disk_extract_artifacts"));
    assert!(ledger_text.contains("unmounted"));
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_recovers_a_wiped_prefetch_directory() {
    // Anti-forensics shape: every .pf in Windows/Prefetch comes back from `fls`
    // marked deleted. Before this, the extractor dropped all of them, reported
    // artifact_counts.prefetch = 0, and recorded NO limitation — the gap was
    // invisible. Now the resident records are recovered, labelled, and the
    // wipe itself is reported.
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-wiped-prefetch".to_string()),
    })
    .expect("case_open ok");

    // Two recoverable .pf (valid Win10 `MAM\x04` signature), one whose inode was
    // reused by unrelated data, plus a live $MFT for contrast.
    let _tsk = FakeTsk::install_with_deleted(
        tmp.path(),
        &[
            ("100", "$MFT", b"mft bytes", true),
            (
                "101",
                "Windows/Prefetch/SDELETE.EXE-257E3D6D.pf",
                b"MAM\x04sdelete prefetch body",
                false,
            ),
            (
                "102",
                "Windows/Prefetch/CSRSS.EXE-8C04D631.pf",
                b"MAM\x04csrss prefetch body",
                false,
            ),
            (
                "103",
                "Windows/Prefetch/REUSED.EXE-DEADBEEF.pf",
                b"\x00\x00\x00\x00 reallocated cluster",
                false,
            ),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
    })
    .expect("extract artifacts");

    let prefetch: Vec<_> = extracted
        .artifacts
        .iter()
        .filter(|a| a.artifact_class == "prefetch")
        .collect();
    assert_eq!(
        prefetch.len(),
        2,
        "the two signature-valid .pf are recovered, the reallocated one is not: {:?}",
        extracted
            .artifacts
            .iter()
            .map(|a| a.source_path.display().to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        prefetch.iter().all(|a| a.recovered_deleted),
        "recovered rows must be labelled so a reader sees the provenance"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .any(|a| a.artifact_class == "mft" && !a.recovered_deleted),
        "allocated artifacts stay unlabelled"
    );
    let limitations = extracted.analysis_limitations.join(" | ");
    assert!(
        limitations.contains("Prefetch"),
        "the wipe must be reported, not silent: {limitations:?}"
    );
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_skips_oversized_yara_targets() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-oversize".to_string()),
    })
    .expect("case_open ok");

    let small = PathBuf::from("Users/Alice/AppData/Local/Temp/small.bin");
    let large = PathBuf::from("Users/Alice/AppData/Local/Temp/large.bin");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("200", small.to_str().unwrap(), b"small"),
            (
                "201",
                large.to_str().unwrap(),
                b"this file is too large for the smoke max",
            ),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 8,
    })
    .expect("extract artifacts");

    assert_eq!(extracted.artifacts_skipped_oversize, 1);
    assert!(
        extracted
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path == small),
        "small YARA target should still be extracted"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .all(|artifact| artifact.source_path != large),
        "oversized YARA target should not be copied"
    );
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_skips_non_sqlite_history_name_collision() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-browser-history-type-check".to_string()),
    })
    .expect("case_open ok");

    let sqlite_path = tmp.path().join("valid-history.sqlite");
    let conn = rusqlite::Connection::open(&sqlite_path).expect("create sqlite fixture");
    conn.execute_batch(
        "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, \
             visit_count INTEGER, last_visit_time INTEGER);
         CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);",
    )
    .expect("create chrome-shaped schema");
    drop(conn);
    let sqlite_bytes = fs::read(sqlite_path).expect("read sqlite fixture");

    let shell_history = PathBuf::from("aaa/home/analyst/.mc/history");
    let truncated_history = PathBuf::from("aab/browser/History");
    let browser_history = PathBuf::from("zzz/home/analyst/.config/google-chrome/Default/History");
    let _tsk = FakeTsk::install(
        tmp.path(),
        &[
            ("300", shell_history.to_str().unwrap(), b"cd /tmp\nls -la\n"),
            ("302", truncated_history.to_str().unwrap(), b"SQLite"),
            (
                "301",
                browser_history.to_str().unwrap(),
                sqlite_bytes.as_slice(),
            ),
        ],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        // Both false candidates sort before the genuine DB. They must not
        // consume this single accepted-artifact slot.
        limit: 1,
        max_artifact_bytes: 1024 * 1024,
    })
    .expect("extract artifacts");

    assert!(
        extracted
            .artifacts
            .iter()
            .all(|artifact| artifact.source_path != shell_history),
        "plain-text .mc/history is a name collision, not a browser database"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .all(|artifact| artifact.source_path != truncated_history),
        "a truncated SQLite-looking History candidate must be skipped during auto-discovery"
    );
    assert!(
        extracted
            .artifacts
            .iter()
            .any(|artifact| artifact.source_path == browser_history),
        "a genuine SQLite History database must remain available for parsing"
    );
}

/// Offset-aware fake TSK toolchain for **multi-partition** images. A fake
/// `mmls` prints a canned partition table, and fake `fls`/`icat` dispatch on
/// the `-o <sector>` argument — mirroring how real TSK addresses exactly one
/// partition per invocation. Any offset without a canned partition (including
/// a missing `-o` on a full-disk image) fails the way real TSK does, so the
/// engine only sees files on partitions it explicitly asked for.
///
/// Same env-lock discipline as [`FakeTsk`]: install while a [`HomeGuard`] is
/// held, drop before it.
#[cfg(unix)]
struct FakeMultiPartitionTsk {
    saved: Vec<(&'static str, Option<String>)>,
}

/// One fake partition: its `-o` sector offset plus `(inode, path, bytes)`
/// rows.
#[cfg(unix)]
type FakePartition<'a> = (u64, &'a [(&'a str, &'a str, &'a [u8])]);

#[cfg(unix)]
impl FakeMultiPartitionTsk {
    fn install(dir: &std::path::Path, mmls_output: &str, partitions: &[FakePartition<'_>]) -> Self {
        use std::fmt::Write as _;
        use std::os::unix::fs::PermissionsExt;

        let mmls_txt = dir.join("mmls.txt");
        fs::write(&mmls_txt, mmls_output).unwrap();
        let mmls = dir.join("fake_mmls.sh");
        fs::write(&mmls, format!("#!/bin/sh\ncat '{}'\n", mmls_txt.display())).unwrap();

        let mut fls_cases = String::new();
        for (offset, files) in partitions {
            let blobs = dir.join(format!("blobs_{offset}"));
            fs::create_dir_all(&blobs).unwrap();
            let mut listing = String::new();
            for (inode, path, bytes) in *files {
                writeln!(listing, "r/r {inode}:\t{path}").unwrap();
                fs::write(blobs.join(format!("{inode}.bin")), bytes).unwrap();
            }
            let listing_txt = dir.join(format!("fls_{offset}.txt"));
            fs::write(&listing_txt, listing).unwrap();
            writeln!(fls_cases, "  {offset}) cat '{}' ;;", listing_txt.display()).unwrap();
        }

        // Both scripts recover the `-o <sector>` value the engine passed; fls
        // prints that partition's listing, icat streams blob `<offset>/<inode>`.
        let arg_scan = "off=\"\"\nprev=\"\"\nlast=\"\"\n\
                        for a in \"$@\"; do\n\
                        \t[ \"$prev\" = \"-o\" ] && off=\"$a\"\n\
                        \tprev=\"$a\"\n\
                        \tlast=\"$a\"\n\
                        done\n";
        let fls = dir.join("fake_fls.sh");
        fs::write(
            &fls,
            format!(
                "#!/bin/sh\n{arg_scan}case \"$off\" in\n{fls_cases}  *) echo \
                 'Cannot determine file system type' >&2; exit 1 ;;\nesac\n"
            ),
        )
        .unwrap();
        let icat = dir.join("fake_icat.sh");
        fs::write(
            &icat,
            format!(
                "#!/bin/sh\n{arg_scan}[ -n \"$off\" ] || {{ echo 'Cannot determine file \
                 system type' >&2; exit 1; }}\ncat '{}'/blobs_\"$off\"/\"$last\".bin\n",
                dir.display()
            ),
        )
        .unwrap();

        for script in [&mmls, &fls, &icat] {
            let mut perm = fs::metadata(script).unwrap().permissions();
            perm.set_mode(0o755);
            fs::set_permissions(script, perm).unwrap();
        }

        let mut saved = Vec::new();
        for (key, script) in [
            ("FINDEVIL_MMLS_BIN", &mmls),
            ("FINDEVIL_FLS_BIN", &fls),
            ("FINDEVIL_ICAT_BIN", &icat),
        ] {
            saved.push((key, std::env::var(key).ok()));
            std::env::set_var(key, script);
        }
        Self { saved }
    }
}

#[cfg(unix)]
impl Drop for FakeMultiPartitionTsk {
    fn drop(&mut self) {
        for (key, prev) in &self.saved {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
    }
}

#[test]
#[cfg(unix)]
fn disk_extract_artifacts_reads_every_filesystem_partition() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let _home = HomeGuard::set(tmp.path());
    let image = write_evidence_image(tmp.path(), b"fake full-disk image bytes");
    let handle = case_open(&CaseOpenInput {
        image_path: image.clone(),
        expected_sha256: None,
        label: Some("disk-multi-partition".to_string()),
    })
    .expect("case_open ok");

    // Real layout of cfreds_2015_data_leakage_pc.dd (verified with mmls on the
    // fixture host): a 100 MB NTFS "System Reserved" boot partition at sector
    // 2048 *ahead of* the ~19.9 GB NTFS OS volume at sector 206848. Every
    // registry/evtx/prefetch artifact lives on the second partition.
    let mmls_output = "DOS Partition Table\n\
                       Offset Sector: 0\n\
                       Units are in 512-byte sectors\n\
                       \n\
                       \u{20}     Slot      Start        End          Length       Description\n\
                       000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)\n\
                       001:  -------   0000000000   0000002047   0000002048   Unallocated\n\
                       002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)\n\
                       003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)\n\
                       004:  -------   0041940992   0041943039   0000002048   Unallocated\n";

    let boot_files: &[(&str, &str, &[u8])] = &[("100", "$MFT", b"boot volume mft")];
    let os_files: &[(&str, &str, &[u8])] = &[
        ("200", "$MFT", b"os volume mft"),
        ("201", "Windows/System32/config/SYSTEM", b"system hive"),
        (
            "202",
            "Windows/System32/winevt/Logs/Security.evtx",
            b"security log",
        ),
        ("203", "Windows/Prefetch/CMD.EXE-4A81B364.pf", b"prefetch"),
    ];
    let _tsk = FakeMultiPartitionTsk::install(
        tmp.path(),
        mmls_output,
        &[(2048, boot_files), (206_848, os_files)],
    );

    let mounted = disk_mount(&DiskMountInput {
        case_id: handle.id.clone(),
        image_path: image,
        mount_point: None,
        mode: DiskMode::Mock,
    })
    .expect("mock mount succeeds");

    let extracted = disk_extract_artifacts(&DiskExtractArtifactsInput {
        case_id: handle.id,
        mount_id: mounted.mount_id,
        artifact_kinds: vec![],
        limit: 20,
        max_artifact_bytes: 1024,
    })
    .expect("extract artifacts");

    // The OS volume — the SECOND filesystem partition — must be enumerated.
    // The original bug listed only the first (boot) partition, so extraction
    // saw 256 boot-volume MFT records and zero registry/evtx/prefetch.
    let sources: Vec<String> = extracted
        .artifacts
        .iter()
        .map(|a| a.source_path.to_string_lossy().to_string())
        .collect();
    assert!(
        sources.contains(&"Windows/System32/config/SYSTEM".to_string()),
        "registry hive on the OS volume must be extracted; sources={sources:?}"
    );
    assert!(
        sources.contains(&"Windows/System32/winevt/Logs/Security.evtx".to_string()),
        "event log on the OS volume must be extracted; sources={sources:?}"
    );
    assert!(
        sources.contains(&"Windows/Prefetch/CMD.EXE-4A81B364.pf".to_string()),
        "prefetch on the OS volume must be extracted; sources={sources:?}"
    );

    // Both volumes carry a `$MFT`; both must be extracted without either
    // silently overwriting the other, and the preferred (largest = OS) volume
    // keeps the flat `<class>/<rel_path>` layout downstream tooling knows.
    let mfts: Vec<_> = extracted
        .artifacts
        .iter()
        .filter(|a| a.artifact_class == "mft")
        .collect();
    assert_eq!(mfts.len(), 2, "one $MFT per NTFS volume; got {mfts:?}");
    let flat = mfts
        .iter()
        .find(|a| a.extracted_path.ends_with("mft/$MFT"))
        .expect("preferred-volume $MFT keeps the flat layout");
    assert_eq!(
        fs::read(&flat.extracted_path).unwrap(),
        b"os volume mft",
        "flat $MFT must come from the OS volume, not the boot partition"
    );
    let namespaced = mfts
        .iter()
        .find(|a| a.extracted_path.ends_with("mft/vol2048/$MFT"))
        .expect("secondary-partition $MFT is namespaced by its sector offset");
    assert_eq!(
        fs::read(&namespaced.extracted_path).unwrap(),
        b"boot volume mft"
    );
}
