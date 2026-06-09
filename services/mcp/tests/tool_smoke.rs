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
        use std::fmt::Write as _;
        use std::os::unix::fs::PermissionsExt;
        let blobs = dir.join("blobs");
        fs::create_dir_all(&blobs).unwrap();
        let mut listing = String::new();
        for (inode, path, bytes) in files {
            // fls -p line shape: `r/r <inode>:\t<relative/path>`.
            writeln!(listing, "r/r {inode}:\t{path}").unwrap();
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
