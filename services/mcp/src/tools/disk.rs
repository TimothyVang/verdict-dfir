//! Disk image mount/extract helpers.
//!
//! These tools intentionally expose a narrow typed surface rather than a
//! generic shell runner. Real mounting is best-effort on Unix/SIFT via fixed
//! tool invocations; tests and Windows use the explicit `mock` mode so normal
//! CI never needs FUSE, libewf, or administrator privileges.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use super::ewf_segments::{is_first_ewf_segment, segment_paths_for_image};

const LEDGER_NAME: &str = "session_resources.json";
const STDERR_TAIL_BYTES: usize = 4096;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
/// Command sentinel recorded for a mount that performs no FUSE/loop operation:
/// The Sleuth Kit reads the image directly, so `disk_extract_artifacts` (which
/// already reads off the recorded `image_path` via `fls`/`icat`) needs no live
/// mount. It is distinct from the `mock` sentinel so extraction still takes the
/// real-TSK path, and lets `disk_unmount` skip a teardown that never mounted
/// anything.
const DIRECT_TSK_COMMAND: &str = "direct-tsk";

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DiskMode {
    Auto,
    Mock,
}

impl Default for DiskMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Mft,
    UsnJrnl,
    Prefetch,
    Registry,
    Evtx,
    YaraTarget,
    Amcache,
    Srum,
    Lnk,
    Jumplist,
    ScheduledTask,
    Recyclebin,
    RegTxlog,
    BrowserDb,
    LegacyEvt,
    IeHistory,
    Thumbnail,
    LinuxAccount,
    LinuxLog,
    LinuxShellHistory,
    LinuxSsh,
    LinuxCron,
    MacosUnifiedlog,
    MacosActivity,
    MacosLaunchd,
    MacosFsevents,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskMountInput {
    pub case_id: String,
    pub image_path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mount_point: Option<PathBuf>,
    #[serde(default)]
    pub mode: DiskMode,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskExtractArtifactsInput {
    pub case_id: String,
    pub mount_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifact_kinds: Vec<ArtifactKind>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default = "default_max_artifact_bytes")]
    pub max_artifact_bytes: u64,
    /// Also recover deleted-but-metadata-intact files (unallocated dirents
    /// whose inode still resolves). Entries whose inode was reallocated to a
    /// live file are always skipped — extracting them would return the reusing
    /// file's bytes. Recovered files stage under `<class>/__deleted__/<inode>/`
    /// and never crowd allocated files out of the class budget.
    #[serde(default = "default_true")]
    pub recover_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiskUnmountInput {
    pub case_id: String,
    pub mount_id: String,
    #[serde(default)]
    pub mode: DiskMode,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskMountOutput {
    pub case_id: String,
    pub mount_id: String,
    pub status: String,
    pub image_path: PathBuf,
    pub mount_point: PathBuf,
    pub fs_root: PathBuf,
    pub ledger_path: PathBuf,
    pub command: Vec<String>,
    pub stderr_tail: String,
    pub note: String,
    /// Every filesystem partition enumerated from the image's `mmls` table (empty
    /// for a bare volume image with no table, in mock mode, or when mmls is
    /// unavailable). The tool mounts/extracts the primary (largest) volume; this
    /// list makes any additional volumes visible so multi-volume disks are not
    /// silently reduced to one. Defaults keep older ledgers deserializing.
    #[serde(default)]
    pub partitions: Vec<MmlsPartition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExtractedDiskArtifact {
    pub artifact_class: String,
    pub source_path: PathBuf,
    pub extracted_path: PathBuf,
    pub size_bytes: u64,
    /// True when this artifact was recovered from a deleted (unallocated)
    /// directory entry rather than a live file. Default keeps pre-existing
    /// ledgers deserializing.
    #[serde(default)]
    pub recovered_deleted: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskExtractArtifactsOutput {
    pub case_id: String,
    pub mount_id: String,
    pub extract_id: String,
    pub output_dir: PathBuf,
    pub artifacts: Vec<ExtractedDiskArtifact>,
    pub artifacts_seen: usize,
    pub artifacts_skipped_oversize: usize,
    pub max_artifact_bytes: u64,
    /// Deleted entries observed in the filesystem listing (including ones
    /// skipped as reallocated). Defaults keep pre-existing recorded outputs
    /// deserializing.
    #[serde(default)]
    pub deleted_entries_seen: usize,
    /// Deleted entries whose content was recovered and staged.
    #[serde(default)]
    pub deleted_recovered: usize,
    /// Deleted entries skipped because their inode was reused by a live file.
    #[serde(default)]
    pub deleted_skipped_realloc: usize,
    /// Deleted entries selected for recovery whose content was unreadable or
    /// empty.
    #[serde(default)]
    pub deleted_recovery_failed: usize,
    pub ledger_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DiskUnmountOutput {
    pub case_id: String,
    pub mount_id: String,
    pub status: String,
    pub ledger_path: PathBuf,
    pub command: Vec<String>,
    pub stderr_tail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionResource {
    pub id: String,
    pub resource_type: String,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
    pub image_path: Option<PathBuf>,
    pub mount_point: Option<PathBuf>,
    pub fs_root: Option<PathBuf>,
    pub parent_id: Option<String>,
    pub output_dir: Option<PathBuf>,
    pub artifacts: Vec<ExtractedDiskArtifact>,
    pub command: Vec<String>,
    pub note: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct SessionLedger {
    resources: Vec<SessionResource>,
}

#[derive(Debug, Error)]
pub enum DiskError {
    #[error("case not found: {0}")]
    CaseNotFound(String),
    #[error("invalid case_id (must match [A-Za-z0-9_-]+, no path separators or '.'/'..'): {0}")]
    InvalidCaseId(String),
    #[error("evidence image not found: {0}")]
    ImageNotFound(PathBuf),
    #[error("mount resource not found: {0}")]
    MountNotFound(String),
    #[error("mount resource is not mounted: {0}")]
    MountNotMounted(String),
    #[error("mount root not found: {0}")]
    MountRootNotFound(PathBuf),
    #[error("unsupported on this platform without mode=mock")]
    UnsupportedPlatform,
    #[error("subprocess failed ({status}): {stderr_tail}")]
    SubprocessFailed { status: String, stderr_tail: String },
    #[error("{0}")]
    EwfSegmentSet(String),
    #[error("io error at {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("cannot serialize session resource ledger: {0}")]
    Serialize(#[from] serde_json::Error),
}

pub fn disk_mount(input: &DiskMountInput) -> Result<DiskMountOutput, DiskError> {
    let case_dir = case_dir(&input.case_id)?;
    if !input.image_path.is_file() {
        return Err(DiskError::ImageNotFound(input.image_path.clone()));
    }
    let ledger_path = case_dir.join(LEDGER_NAME);
    let mount_id = format!("disk-mount-{}", Uuid::new_v4());
    let mount_point = input
        .mount_point
        .clone()
        .unwrap_or_else(|| case_dir.join("mounts").join(&mount_id));
    create_dir(&mount_point)?;
    let image_paths = match input.mode {
        DiskMode::Mock => vec![input.image_path.clone()],
        DiskMode::Auto => segment_paths_for_image(&input.image_path)
            .map_err(|err| DiskError::EwfSegmentSet(err.to_string()))?,
    };

    let (status, fs_root, command, stderr_tail, note) = match input.mode {
        DiskMode::Mock => (
            "mounted".to_string(),
            mount_point.clone(),
            vec!["mock".to_string(), "disk_mount".to_string()],
            String::new(),
            "mock mount registered; no privileged filesystem operation ran".to_string(),
        ),
        DiskMode::Auto => auto_mount(&image_paths, &mount_point)?,
    };

    // Best-effort full partition table so multi-volume disks are visible; never
    // gates the mount (empty in mock mode / bare volume / no mmls).
    let partitions = match input.mode {
        DiskMode::Mock => Vec::new(),
        DiskMode::Auto => enumerate_partitions(&image_paths),
    };

    let now = now_iso();
    let resource = SessionResource {
        id: mount_id.clone(),
        resource_type: "disk_mount".to_string(),
        status: status.clone(),
        created_at: now.clone(),
        updated_at: now,
        image_path: Some(input.image_path.clone()),
        mount_point: Some(mount_point.clone()),
        fs_root: Some(fs_root.clone()),
        parent_id: None,
        output_dir: None,
        artifacts: vec![],
        command: command.clone(),
        note: note.clone(),
    };
    upsert_resource(&ledger_path, resource)?;

    Ok(DiskMountOutput {
        case_id: input.case_id.clone(),
        mount_id,
        status,
        image_path: input.image_path.clone(),
        mount_point,
        fs_root,
        ledger_path,
        command,
        stderr_tail,
        note,
        partitions,
    })
}

pub fn disk_extract_artifacts(
    input: &DiskExtractArtifactsInput,
) -> Result<DiskExtractArtifactsOutput, DiskError> {
    let case_dir = case_dir(&input.case_id)?;
    let ledger_path = case_dir.join(LEDGER_NAME);
    let mut ledger = read_ledger(&ledger_path)?;
    let mount = ledger
        .resources
        .iter()
        .find(|r| r.id == input.mount_id && r.resource_type == "disk_mount")
        .cloned()
        .ok_or_else(|| DiskError::MountNotFound(input.mount_id.clone()))?;
    if mount.status != "mounted" {
        return Err(DiskError::MountNotMounted(input.mount_id.clone()));
    }
    // Read artifacts straight from the image with The Sleuth Kit (fls/icat)
    // instead of walking a live mount: libtsk reads EWF + raw images directly,
    // so extraction is stateless and survives --sift mode's per-tool SSH
    // sessions (a FUSE mount's daemon does not). The filesystem mount, if any,
    // is irrelevant here — only the image path disk_mount recorded matters.
    let image_path = mount
        .image_path
        .ok_or_else(|| DiskError::MountNotMounted(input.mount_id.clone()))?;
    if !image_path.is_file() {
        return Err(DiskError::ImageNotFound(image_path));
    }
    let image_paths = segment_paths_for_image(&image_path)
        .map_err(|err| DiskError::EwfSegmentSet(err.to_string()))?;

    let extract_id = format!("disk-extract-{}", Uuid::new_v4());
    let output_dir = case_dir.join("extracted").join("disk").join(&extract_id);
    create_dir(&output_dir)?;
    let wanted = wanted_kinds(&input.artifact_kinds);

    let sector_offset = primary_partition_sector_offset(&image_paths);

    // Enumerate every file once and keep the wanted classes. Selection then
    // allocates the `limit` *fairly across classes* (round-robin) so a
    // voluminous class — hundreds of prefetch or evtx files — can't starve the
    // others, and within each class the highest-signal artifacts are drawn
    // first (for evtx, the canonical Windows logs ahead of the long
    // Microsoft-Windows-*/Operational tail). A single global priority sort
    // would otherwise let prefetch consume the whole budget and extract zero
    // event logs — the richest finding source on a disk.
    //
    // The Sleuth Kit reads the image directly (real images, and the faked
    // fls/icat in tests). A `mock` mount whose "image" is the synthetic
    // evidence the end-to-end smoke and Windows use is not a real filesystem,
    // so TSK can't enumerate it; that case falls back to walking the directory
    // tree disk_mount staged at fs_root. Auto mounts never fall back — a real
    // image TSK can't read is a genuine error to surface, not silently skip.
    let mock_root: Option<PathBuf> = (mount.command.first().map(String::as_str) == Some("mock"))
        .then(|| mount.fs_root.clone())
        .flatten();
    let (listed, via_walk) = match tsk_list(&image_paths, sector_offset) {
        Ok(files) if !files.is_empty() => (files, false),
        tsk_result => match &mock_root {
            Some(root) => (mock_list(root)?, true),
            None => (tsk_result?, false),
        },
    };
    let (candidates, deleted_entries_seen, deleted_skipped_realloc) =
        build_candidates(listed, &wanted, input.recover_deleted);
    let selected = select_artifacts(candidates, input.limit);

    let mut artifacts = Vec::new();
    let mut stats = ExtractStats::default();
    for candidate in &selected {
        match (via_walk, &mock_root) {
            (true, Some(root)) => mock_extract(
                root,
                &candidate.path,
                candidate.class,
                &output_dir,
                input.max_artifact_bytes,
                &mut artifacts,
                &mut stats,
            )?,
            _ => tsk_extract(
                &image_paths,
                sector_offset,
                candidate,
                &output_dir,
                input.max_artifact_bytes,
                &mut artifacts,
                &mut stats,
            )?,
        }
    }

    let now = now_iso();
    ledger.resources.push(SessionResource {
        id: extract_id.clone(),
        resource_type: "disk_extract_artifacts".to_string(),
        status: "extracted".to_string(),
        created_at: now.clone(),
        updated_at: now,
        image_path: Some(image_path),
        mount_point: mount.mount_point,
        fs_root: mount.fs_root,
        parent_id: Some(input.mount_id.clone()),
        output_dir: Some(output_dir.clone()),
        artifacts: artifacts.clone(),
        command: vec!["fls".to_string(), "icat".to_string()],
        note: "extracted disk artifacts directly from the image via The Sleuth Kit".to_string(),
    });
    write_ledger(&ledger_path, &ledger)?;

    Ok(DiskExtractArtifactsOutput {
        case_id: input.case_id.clone(),
        mount_id: input.mount_id.clone(),
        extract_id,
        output_dir,
        artifacts_seen: artifacts.len(),
        artifacts_skipped_oversize: stats.skipped_oversize,
        max_artifact_bytes: input.max_artifact_bytes,
        deleted_entries_seen,
        deleted_recovered: stats.deleted_recovered,
        deleted_skipped_realloc,
        deleted_recovery_failed: stats.deleted_recovery_failed,
        artifacts,
        ledger_path,
    })
}

pub fn disk_unmount(input: &DiskUnmountInput) -> Result<DiskUnmountOutput, DiskError> {
    let case_dir = case_dir(&input.case_id)?;
    let ledger_path = case_dir.join(LEDGER_NAME);
    let mut ledger = read_ledger(&ledger_path)?;
    let idx = ledger
        .resources
        .iter()
        .position(|r| r.id == input.mount_id && r.resource_type == "disk_mount")
        .ok_or_else(|| DiskError::MountNotFound(input.mount_id.clone()))?;
    let mount_point = ledger.resources[idx]
        .mount_point
        .clone()
        .ok_or_else(|| DiskError::MountNotMounted(input.mount_id.clone()))?;
    // fs_root tells the teardown which layout this is: a nested EWF+NTFS mount
    // (fs_root == <mp>/fs), an EWF container only (fs_root == <mp>/ewf), or a
    // raw image mounted at the mount point. Default to the mount point for
    // older ledger rows that predate fs_root.
    let fs_root = ledger.resources[idx]
        .fs_root
        .clone()
        .unwrap_or_else(|| mount_point.clone());

    // A direct-TSK mount never ran a FUSE/loop mount, so there is nothing to
    // release: an `umount` would just fail on an unmounted path. Mark it
    // unmounted without a privileged teardown.
    let is_direct_tsk =
        ledger.resources[idx].command.first().map(String::as_str) == Some(DIRECT_TSK_COMMAND);
    let (status, command, stderr_tail) = if is_direct_tsk {
        (
            "unmounted".to_string(),
            vec![DIRECT_TSK_COMMAND.to_string(), "disk_unmount".to_string()],
            String::new(),
        )
    } else {
        match input.mode {
            DiskMode::Mock => (
                "unmounted".to_string(),
                vec!["mock".to_string(), "disk_unmount".to_string()],
                String::new(),
            ),
            DiskMode::Auto => auto_unmount(&mount_point, &fs_root)?,
        }
    };
    ledger.resources[idx].status.clone_from(&status);
    ledger.resources[idx].updated_at = now_iso();
    ledger.resources[idx].command.clone_from(&command);
    write_ledger(&ledger_path, &ledger)?;

    Ok(DiskUnmountOutput {
        case_id: input.case_id.clone(),
        mount_id: input.mount_id.clone(),
        status,
        ledger_path,
        command,
        stderr_tail,
    })
}

fn auto_mount(
    image_paths: &[PathBuf],
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    if cfg!(windows) {
        return Err(DiskError::UnsupportedPlatform);
    }
    let image_path = image_paths
        .first()
        .ok_or_else(|| DiskError::ImageNotFound(PathBuf::from("<empty image set>")))?;
    if is_first_ewf_segment(image_path) {
        return auto_mount_ewf(image_paths, mount_point);
    }
    auto_mount_raw(image_path, mount_point)
}

fn auto_mount_ewf(
    image_paths: &[PathBuf],
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let bin = std::env::var("EWF_MOUNT_BIN").unwrap_or_else(|_| "ewfmount".to_string());
    // ewfmount (FUSE E01 -> raw) is only a convenience: The Sleuth Kit reads EWF
    // images directly, and disk_extract_artifacts already reads artifacts off the
    // recorded image_path via fls/icat, never off this mount. When ewfmount is
    // unavailable — notably the GIFT-PPA libewf/Plaso apt conflict that evicts
    // ewf-tools — register a direct-TSK mount so the disk lane keeps working
    // instead of hard-failing the whole Case. Extraction reads the same image
    // bytes either way, so custody replay is unaffected.
    let image_path = image_paths
        .first()
        .ok_or_else(|| DiskError::ImageNotFound(PathBuf::from("<empty image set>")))?;
    if !ewfmount_available(&bin) {
        return Ok(direct_tsk_mount(
            image_path,
            &format!("{bin} not found; reading the EWF image directly with The Sleuth Kit"),
        ));
    }
    let ewf_dir = mount_point.join("ewf");
    create_dir(&ewf_dir)?;
    let mut args: Vec<String> = image_paths
        .iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect();
    args.push(ewf_dir.to_string_lossy().to_string());
    // ewfmount must run as root: /etc/fuse.conf has no `user_allow_other`, so a
    // user-owned FUSE device is unreadable by the (root) loop/mount syscalls.
    let result = run_sudo_fixed(&bin, &args)?;
    if !result.0 {
        // A PATH-present ewfmount can still be unreachable under sudo's
        // secure_path ("sudo: ewfmount: command not found"); fall through to the
        // direct-TSK read rather than failing the Case.
        if is_missing_binary(&result.2) {
            let _ = fs::remove_dir(&ewf_dir);
            return Ok(direct_tsk_mount(image_path, &result.2));
        }
        return Err(DiskError::SubprocessFailed {
            status: result.1,
            stderr_tail: result.2,
        });
    }
    let ewf_cmd: Vec<String> = vec!["sudo".to_string(), "-n".to_string(), bin]
        .into_iter()
        .chain(args)
        .collect();
    let ewf_stderr = result.2;

    // ewfmount exposes the combined image as a single raw device named `ewf1`.
    // The NTFS volume inside still has to be loop-mounted before any files are
    // reachable. Use the kernel `ntfs3` driver (ntfs-3g refuses volumes whose
    // recorded size exceeds the image — common for acquired partitions) at
    // offset 0 for a bare volume image, or the first-partition offset for a full
    // disk. If it can't be mounted, fall back to custody-only on the container —
    // never worse than mounting nothing.
    let ewf_raw = ewf_dir.join("ewf1");
    let fs_dir = mount_point.join("fs");
    create_dir(&fs_dir)?;
    if let Ok((fs_cmd, fs_stderr)) = mount_ntfs_ro(&ewf_raw, &fs_dir) {
        let mut command = ewf_cmd;
        command.push("&&".to_string());
        command.extend(fs_cmd);
        Ok((
            "mounted".to_string(),
            fs_dir,
            command,
            fs_stderr,
            "mounted EWF container + NTFS filesystem read-only".to_string(),
        ))
    } else {
        let _ = fs::remove_dir(&fs_dir);
        Ok((
            "mounted".to_string(),
            ewf_dir,
            ewf_cmd,
            ewf_stderr,
            "mounted EWF container read-only; NTFS volume could not be mounted (custody-only)"
                .to_string(),
        ))
    }
}

/// Register a mount that performs no FUSE/loop operation. The returned tuple has
/// the same shape as a real EWF/raw mount, but `status = "mounted"`,
/// `fs_root = image_path` (the raw image itself), and the [`DIRECT_TSK_COMMAND`]
/// sentinel so `disk_extract_artifacts` reads directly with The Sleuth Kit and
/// `disk_unmount` skips a no-op teardown. Preserves the whole disk lane when
/// `ewfmount` is unavailable — the extracted bytes are identical (same
/// `fls`/`icat` off the same image + #147 largest-partition offset), so the
/// audit chain replays to the same `output_sha256`.
fn direct_tsk_mount(
    image_path: &Path,
    reason: &str,
) -> (String, PathBuf, Vec<String>, String, String) {
    (
        "mounted".to_string(),
        image_path.to_path_buf(),
        vec![DIRECT_TSK_COMMAND.to_string()],
        String::new(),
        format!("registered direct Sleuth Kit read of the image (no FUSE/loop mount): {reason}"),
    )
}

/// Whether `bin` (`ewfmount`) can be spawned at all. A failure to spawn
/// (`ErrorKind::NotFound`, i.e. the binary is not on PATH) means the direct-TSK
/// fallback must be used; any other outcome — it ran, or errored for another
/// reason — is treated as available. Probing with `-h` never mounts anything.
fn ewfmount_available(bin: &str) -> bool {
    match Command::new(bin).arg("-h").output() {
        Ok(_) => true,
        Err(err) => err.kind() != io::ErrorKind::NotFound,
    }
}

/// Whether a subprocess `stderr` tail indicates the binary itself was missing
/// (as opposed to a genuine mount failure). Covers `sudo`'s
/// "sudo: ewfmount: command not found" and exec-wrapper "executable file not
/// found" phrasings.
fn is_missing_binary(stderr: &str) -> bool {
    let lower = stderr.to_ascii_lowercase();
    lower.contains("command not found") || lower.contains("executable file not found")
}

/// Loop-mount an NTFS volume read-only with the kernel `ntfs3` driver, under
/// sudo (the EWF device is root-owned). Tries offset 0 (bare volume image) then
/// the primary (largest) filesystem-partition offset from `mmls` (full disk
/// image).
fn mount_ntfs_ro(device: &Path, mount_point: &Path) -> Result<(Vec<String>, String), DiskError> {
    let mount_bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let mut offsets = vec![0u64];
    if let Some(offset) = primary_partition_byte_offset_sudo(device) {
        offsets.push(offset);
    }
    let mut last_status = String::new();
    let mut last_stderr = String::new();
    for offset in offsets {
        let opts = if offset == 0 {
            "ro,loop".to_string()
        } else {
            format!("ro,loop,offset={offset}")
        };
        let args = vec![
            "-t".to_string(),
            "ntfs3".to_string(),
            "-o".to_string(),
            opts,
            device.to_string_lossy().to_string(),
            mount_point.to_string_lossy().to_string(),
        ];
        let result = run_sudo_fixed(&mount_bin, &args)?;
        if result.0 {
            let command: Vec<String> = vec!["sudo".to_string(), "-n".to_string(), mount_bin]
                .into_iter()
                .chain(args)
                .collect();
            return Ok((command, result.2));
        }
        last_status = result.1;
        last_stderr = result.2;
    }
    Err(DiskError::SubprocessFailed {
        status: last_status,
        stderr_tail: last_stderr,
    })
}

/// `mmls` primary- (largest-) filesystem-partition byte offset, run under sudo
/// because the EWF device is root-owned. None when the image is a bare volume
/// (no table).
fn primary_partition_byte_offset_sudo(image_path: &Path) -> Option<u64> {
    let output = Command::new("sudo")
        .args(["-n", "mmls"])
        .arg(image_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_mmls_primary_partition_offset(&String::from_utf8_lossy(&output.stdout))
}

/// Enumerate every filesystem partition in the image for the mount output. Tries
/// a plain `mmls` first, then `sudo -n mmls` (the EWF device is root-owned),
/// mirroring the offset helpers. Returns an empty vec for a bare volume image,
/// when mmls is unavailable, or on any error — enumeration is best-effort and
/// never fails the mount.
fn enumerate_partitions(image_paths: &[PathBuf]) -> Vec<MmlsPartition> {
    let run = |cmd: &mut Command| -> Option<String> {
        let output = cmd.output().ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).into_owned())
    };
    let mut direct = Command::new("mmls");
    append_image_args(&mut direct, image_paths);
    let mut sudo = Command::new("sudo");
    sudo.args(["-n", "mmls"]);
    append_image_args(&mut sudo, image_paths);
    let text = run(&mut direct).or_else(|| run(&mut sudo));
    text.map(|t| parse_mmls_partitions(&t)).unwrap_or_default()
}

fn auto_mount_raw(
    image_path: &Path,
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let args = vec![
        "-o".to_string(),
        "ro,loop".to_string(),
        image_path.to_string_lossy().to_string(),
        mount_point.to_string_lossy().to_string(),
    ];
    let result = run_fixed(&bin, &args)?;
    if result.0 {
        return Ok((
            "mounted".to_string(),
            mount_point.to_path_buf(),
            std::iter::once(bin).chain(args).collect(),
            result.2,
            "mounted raw image read-only with loop device".to_string(),
        ));
    }

    let direct_status = result.1;
    let direct_stderr = result.2;
    let image_paths = vec![image_path.to_path_buf()];
    if let Some(offset) = primary_partition_byte_offset(&image_paths) {
        let offset_args = vec![
            "-o".to_string(),
            format!("ro,loop,offset={offset}"),
            image_path.to_string_lossy().to_string(),
            mount_point.to_string_lossy().to_string(),
        ];
        let offset_result = run_fixed(&bin, &offset_args)?;
        if offset_result.0 {
            return Ok((
                "mounted".to_string(),
                mount_point.to_path_buf(),
                std::iter::once(bin).chain(offset_args).collect(),
                offset_result.2,
                format!("mounted primary filesystem partition read-only with loop offset {offset}"),
            ));
        }
        if bin == "mount" {
            let sudo_result = run_sudo_fixed(&bin, &offset_args)?;
            if sudo_result.0 {
                return Ok((
                    "mounted".to_string(),
                    mount_point.to_path_buf(),
                    std::iter::once("sudo".to_string())
                        .chain(std::iter::once("-n".to_string()))
                        .chain(std::iter::once(bin))
                        .chain(offset_args)
                        .collect(),
                    sudo_result.2,
                    format!(
                        "mounted primary filesystem partition read-only with sudo loop offset {offset}"
                    ),
                ));
            }
        }
        return Err(DiskError::SubprocessFailed {
            status: offset_result.1,
            stderr_tail: format!(
                "direct mount failed ({direct_status}): {direct_stderr}\n\
                 offset mount failed: {}",
                offset_result.2
            ),
        });
    }

    if bin == "mount" {
        let sudo_result = run_sudo_fixed(&bin, &args)?;
        if sudo_result.0 {
            return Ok((
                "mounted".to_string(),
                mount_point.to_path_buf(),
                std::iter::once("sudo".to_string())
                    .chain(std::iter::once("-n".to_string()))
                    .chain(std::iter::once(bin))
                    .chain(args)
                    .collect(),
                sudo_result.2,
                "mounted raw image read-only with sudo loop device".to_string(),
            ));
        }
        return Err(DiskError::SubprocessFailed {
            status: sudo_result.1,
            stderr_tail: format!(
                "direct mount failed ({direct_status}): {direct_stderr}\n\
                 sudo mount failed: {}",
                sudo_result.2
            ),
        });
    }

    Err(DiskError::SubprocessFailed {
        status: direct_status,
        stderr_tail: direct_stderr,
    })
}

fn primary_partition_byte_offset(image_paths: &[PathBuf]) -> Option<u64> {
    let mut command = Command::new("mmls");
    append_image_args(&mut command, image_paths);
    let output = command.output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_mmls_primary_partition_offset(&String::from_utf8_lossy(&output.stdout))
}

/// Byte offset of the **primary** filesystem partition — the largest-by-length
/// filesystem partition `mmls` reports, not merely the first one.
///
/// On a full Windows disk image the *first* filesystem partition is the small
/// "System Reserved" boot volume (a few hundred MB, ~a hundred files). The OS
/// volume that actually holds `Windows/System32/winevt/Logs`, the registry
/// hives, and user data is a separate, much larger partition further down the
/// table. Selecting the first partition therefore points `fls`/`icat` and the
/// loop mount at the boot stub and extracts almost nothing. Selecting by size
/// keys on a general disk-layout property (fully evidence-agnostic) and lands
/// on the OS/data volume instead. Returns `None` for a bare volume image (no
/// partition table), where TSK and the loop mount read at offset 0.
/// One filesystem partition enumerated from an `mmls` partition table. Byte and
/// sector offsets are derived from the reported start sector (512-byte sectors,
/// the mmls default the tool relies on elsewhere). Surfaced so a multi-volume
/// disk (e.g. a separate data volume, or a FAT/exFAT/ext partition beside the
/// primary NTFS OS volume) is visible rather than silently reduced to the single
/// largest volume — a precondition for honest per-filesystem coverage claims.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MmlsPartition {
    /// mmls slot index (the leading `NNN:` column), e.g. 2 for `002:`.
    pub slot: u32,
    /// Start sector as reported by mmls.
    pub start_sector: u64,
    /// Length in sectors as reported by mmls.
    pub length_sectors: u64,
    /// Byte offset of the partition (`start_sector * 512`).
    pub byte_offset: u64,
    /// Free-text filesystem description from mmls (e.g. `NTFS / exFAT (0x07)`).
    pub description: String,
}

/// Enumerate **every** filesystem partition an `mmls` listing reports, in table
/// order. Metadata and unallocated rows are skipped; only rows whose description
/// matches a known filesystem ([`matches_filesystem_description`]) are kept. Pure
/// over the text so it is unit-tested without invoking mmls. Deterministic: the
/// order follows the mmls table, which is stable for a given image.
fn parse_mmls_partitions(output: &str) -> Vec<MmlsPartition> {
    let mut partitions = Vec::new();
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("meta")
            || lower.contains("unallocated")
            || !matches_filesystem_description(&lower)
        {
            continue;
        }
        // The leading `NNN:` slot index (before the CHS `000:000` column). Take
        // the first token, strip a trailing colon, parse as the slot number.
        let slot = line
            .split_whitespace()
            .next()
            .and_then(|tok| tok.strip_suffix(':'))
            .and_then(|n| n.parse::<u32>().ok());
        // The columns after the slot labels are Start, End, Length (decimal
        // sector counts), then the free-text description. Collect the decimal
        // fields in order; the index ("002:") and CHS-style slot ("000:000")
        // carry colons, so they never parse as all-digit.
        let mut nums = line
            .split_whitespace()
            .filter(|field| !field.is_empty() && field.chars().all(|c| c.is_ascii_digit()))
            .filter_map(|field| field.parse::<u64>().ok());
        let (Some(start), Some(_end), Some(length)) = (nums.next(), nums.next(), nums.next())
        else {
            continue;
        };
        let Some(byte_offset) = start.checked_mul(512) else {
            continue;
        };
        // Description is the trailing free text after the three decimal columns.
        let description = mmls_description(line);
        partitions.push(MmlsPartition {
            slot: slot.unwrap_or_default(),
            start_sector: start,
            length_sectors: length,
            byte_offset,
            description,
        });
    }
    partitions
}

/// The free-text filesystem description trailing an mmls row (everything after
/// the Start/End/Length decimal columns), trimmed. Empty if the shape is off.
fn mmls_description(line: &str) -> String {
    // Find the third all-decimal token (Length) and take the remainder.
    let mut seen_decimals = 0usize;
    let mut idx_after = None;
    for (i, tok) in line.split_whitespace().enumerate() {
        if !tok.is_empty() && tok.chars().all(|c| c.is_ascii_digit()) {
            seen_decimals += 1;
            if seen_decimals == 3 {
                idx_after = Some(i);
                break;
            }
        }
    }
    idx_after.map_or_else(String::new, |i| {
        line.split_whitespace()
            .skip(i + 1)
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// Byte offset of the **primary** filesystem partition — the largest-by-length
/// filesystem partition, reusing the full enumeration so selection and the
/// surfaced partition table can never disagree.
fn parse_mmls_primary_partition_offset(output: &str) -> Option<u64> {
    parse_mmls_partitions(output)
        .into_iter()
        .max_by_key(|p| p.length_sectors)
        .map(|p| p.byte_offset)
}

fn matches_filesystem_description(line: &str) -> bool {
    line.contains("ntfs")
        || line.contains("exfat")
        || line.contains("fat")
        || line.contains("linux")
        || line.contains("hfs")
        || line.contains("apfs")
}

/// Plan the teardown commands for a mount, newest layer first. Pure so the
/// ordering (the nested NTFS loop is released before the EWF container) is
/// unit-tested without touching real mounts. Both EWF and NTFS mounts are
/// root-owned (`sudo ewfmount` / `sudo mount`), so `umount` releases both —
/// `auto_unmount` retries each step under sudo.
fn unmount_steps(
    mount_point: &Path,
    fs_root: &Path,
    umount_bin: &str,
) -> Vec<(String, Vec<String>)> {
    let ewf_dir = mount_point.join("ewf");
    let fs_dir = mount_point.join("fs");
    if fs_root == fs_dir {
        // EWF container with a nested NTFS loop mount: drop the loop first, then
        // release the EWF container it sits on.
        vec![
            (
                umount_bin.to_string(),
                vec![fs_dir.to_string_lossy().to_string()],
            ),
            (
                umount_bin.to_string(),
                vec![ewf_dir.to_string_lossy().to_string()],
            ),
        ]
    } else if fs_root == ewf_dir {
        // EWF container only (filesystem could not be mounted).
        vec![(
            umount_bin.to_string(),
            vec![ewf_dir.to_string_lossy().to_string()],
        )]
    } else {
        // Raw image mounted directly at the mount point.
        vec![(
            umount_bin.to_string(),
            vec![mount_point.to_string_lossy().to_string()],
        )]
    }
}

fn auto_unmount(
    mount_point: &Path,
    fs_root: &Path,
) -> Result<(String, Vec<String>, String), DiskError> {
    if cfg!(windows) {
        return Err(DiskError::UnsupportedPlatform);
    }
    let umount_bin = std::env::var("FINDEVIL_UMOUNT_BIN").unwrap_or_else(|_| "umount".to_string());
    let steps = unmount_steps(mount_point, fs_root, &umount_bin);

    let mut commands: Vec<String> = Vec::new();
    let mut stderr_tail = String::new();
    for (idx, (bin, args)) in steps.iter().enumerate() {
        if idx > 0 {
            commands.push("&&".to_string());
        }
        let result = run_fixed(bin, args)?;
        if result.0 {
            commands.push(bin.clone());
            commands.extend(args.iter().cloned());
            stderr_tail = result.2;
            continue;
        }
        // Privileged mounts need sudo -n; harmless for fusermount on own mounts.
        let sudo_result = run_sudo_fixed(bin, args)?;
        if sudo_result.0 {
            commands.push("sudo".to_string());
            commands.push("-n".to_string());
            commands.push(bin.clone());
            commands.extend(args.iter().cloned());
            stderr_tail = sudo_result.2;
            continue;
        }
        return Err(DiskError::SubprocessFailed {
            status: sudo_result.1,
            stderr_tail: format!(
                "{bin} failed ({}): {}\nsudo {bin} failed: {}",
                result.1, result.2, sudo_result.2
            ),
        });
    }
    Ok(("unmounted".to_string(), commands, stderr_tail))
}

fn run_sudo_fixed(bin: &str, args: &[String]) -> Result<(bool, String, String), DiskError> {
    let mut sudo_args = vec!["-n".to_string(), bin.to_string()];
    sudo_args.extend(args.iter().cloned());
    run_fixed("sudo", &sudo_args)
}

fn run_fixed(bin: &str, args: &[String]) -> Result<(bool, String, String), DiskError> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .map_err(|source| DiskError::Io {
            path: PathBuf::from(bin),
            source,
        })?;
    Ok((
        output.status.success(),
        output.status.to_string(),
        tail_utf8_lossy(&output.stderr),
    ))
}

fn append_image_args(command: &mut Command, image_paths: &[PathBuf]) {
    for path in image_paths {
        command.arg(path);
    }
}

/// Sector offset of the primary (largest) filesystem partition for
/// `fls`/`icat -o`, or None for a bare volume image (TSK reads it at offset 0).
/// mmls reports the start
/// sector; the byte helper multiplies by 512, so divide it back to sectors.
fn primary_partition_sector_offset(image_paths: &[PathBuf]) -> Option<u64> {
    primary_partition_byte_offset(image_paths).map(|bytes| bytes / 512)
}

/// One `fls -r -p` listing entry. `deleted` marks an unallocated directory
/// entry whose metadata address is still readable — recoverable via the same
/// `icat`-by-inode path as live files. `realloc` marks a deleted entry whose
/// inode has been reused by a live file; extracting it would return the
/// reusing file's content, so extraction must skip it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FlsEntry {
    inode: String,
    path: String,
    deleted: bool,
    realloc: bool,
}

/// One classified extraction candidate flowing from listing to selection.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Candidate {
    class: &'static str,
    inode: String,
    path: String,
    deleted: bool,
}

/// Enumerate every regular file in the image via `fls -r -p` — live files and
/// deleted-but-addressable entries alike. Reads the image directly (no mount).
fn tsk_list(
    image_paths: &[PathBuf],
    sector_offset: Option<u64>,
) -> Result<Vec<FlsEntry>, DiskError> {
    let bin = std::env::var("FINDEVIL_FLS_BIN").unwrap_or_else(|_| "fls".to_string());
    let mut command = Command::new(&bin);
    command.args(["-r", "-p"]);
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    append_image_args(&mut command, image_paths);
    let output = command.output().map_err(|source| DiskError::Io {
        path: PathBuf::from(&bin),
        source,
    })?;
    if !output.status.success() {
        return Err(DiskError::SubprocessFailed {
            status: output.status.to_string(),
            stderr_tail: tail_utf8_lossy(&output.stderr),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(parse_fls_line)
        .collect())
}

/// Recursively list regular files under a mock mount's `fs_root`, returning
/// entries shaped exactly like [`tsk_list`] so they flow through the same
/// classifier + fair-share selector. The inode slot is a placeholder — mock
/// extraction copies by relative path, not inode — and a directory walk has no
/// deleted-file concept, so `deleted` is always false.
fn mock_list(fs_root: &Path) -> Result<Vec<FlsEntry>, DiskError> {
    let mut out = Vec::new();
    mock_walk(fs_root, fs_root, &mut out)?;
    Ok(out)
}

fn mock_walk(root: &Path, dir: &Path, out: &mut Vec<FlsEntry>) -> Result<(), DiskError> {
    for entry in fs::read_dir(dir).map_err(|source| DiskError::Io {
        path: dir.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| DiskError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        let ft = entry.file_type().map_err(|source| DiskError::Io {
            path: path.clone(),
            source,
        })?;
        if ft.is_dir() {
            mock_walk(root, &path, out)?;
        } else if ft.is_file() {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(FlsEntry {
                    inode: "-".to_string(),
                    path: rel.to_string_lossy().replace('\\', "/"),
                    deleted: false,
                    realloc: false,
                });
            }
        }
    }
    Ok(())
}

/// Copy a mock artifact from `fs_root`/`rel_path` to the output dir, mirroring
/// [`tsk_extract`]'s output record so the ledger and caller see identical
/// shapes whether the mount was mock or real.
fn mock_extract(
    fs_root: &Path,
    rel_path: &str,
    class: &str,
    output_dir: &Path,
    max_artifact_bytes: u64,
    out: &mut Vec<ExtractedDiskArtifact>,
    stats: &mut ExtractStats,
) -> Result<(), DiskError> {
    let src = safe_join(fs_root, rel_path);
    let size = fs::metadata(&src)
        .map_err(|source| DiskError::Io {
            path: src.clone(),
            source,
        })?
        .len();
    if size > max_artifact_bytes {
        stats.skipped_oversize += 1;
        return Ok(());
    }
    let dest = safe_join(&output_dir.join(class), rel_path);
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    fs::copy(&src, &dest).map_err(|source| DiskError::Io {
        path: dest.clone(),
        source,
    })?;
    out.push(ExtractedDiskArtifact {
        artifact_class: class.to_string(),
        source_path: PathBuf::from(rel_path),
        extracted_path: dest,
        size_bytes: size,
        recovered_deleted: false,
    });
    Ok(())
}

/// Parse one `fls -p` line into an [`FlsEntry`]. Live files look like
/// `r/r 380861-128-4:\tWindows/System32/config/SYSTEM`; deleted entries carry
/// a `*` marker (`r/r * 999-128-1:\t...`) and often lose their name-type
/// (`-/r * 999:\t...`). Returns None for directories, non-files, and deleted
/// entries whose name-type is unknown while still allocated.
fn parse_fls_line(line: &str) -> Option<FlsEntry> {
    let (kind, rest) = line.split_once(char::is_whitespace)?;
    let mut rest = rest.trim_start();
    let deleted = rest.strip_prefix('*').is_some_and(|stripped| {
        rest = stripped.trim_start();
        true
    });
    // Deleted dirents frequently list as `-/r` (name-type lost, meta-type
    // still a regular file); accept that shape only for deleted entries so
    // live unknowns stay excluded.
    if !(kind.starts_with("r/r") || (deleted && kind.starts_with("-/r"))) {
        return None;
    }
    let (inode, path) = rest.split_once(':')?;
    let mut inode = inode.trim();
    // fls appends `(realloc)` when the deleted entry's inode was reused by a
    // live file — icat on it would return the *new* file's bytes.
    let realloc = inode.strip_suffix("(realloc)").is_some_and(|stripped| {
        inode = stripped.trim_end();
        true
    });
    let path = path.trim();
    if inode.is_empty() || path.is_empty() {
        return None;
    }
    // The inode is handed to `icat` argv and used as an output path component;
    // TSK prints only digits and dashes (`380861-128-4`), so reject anything
    // else a hostile listing line could smuggle in.
    if !inode.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return None;
    }
    Some(FlsEntry {
        inode: inode.to_string(),
        path: path.to_string(),
        deleted,
        realloc,
    })
}

/// Extract order: forensically critical classes first, broad yara targets last,
/// so the `limit` never crowds out registry/MFT/prefetch.
fn class_priority(class: &str) -> u8 {
    match class {
        "mft" => 0,
        "registry" => 1,
        "prefetch" => 2,
        "usnjrnl" => 3,
        "evtx" => 4,
        // Decoded execution / persistence / anti-forensic inputs — high value,
        // drawn after the filesystem/registry/EVTX core but before the generic
        // yara content sweep.
        "amcache" => 5,
        "srum" => 6,
        "lnk" => 7,
        "jumplist" => 8,
        "scheduled_task" => 9,
        "recyclebin" => 10,
        "reg_txlog" => 11,
        "browser_db" => 12,
        "legacy_evt" => 13,
        "ie_history" => 14,
        "thumbnail" => 15,
        // Linux + macOS auto-extracted classes.
        "linux_account" => 16,
        "linux_log" => 17,
        "linux_shell_history" => 18,
        "linux_ssh" => 19,
        "linux_cron" => 20,
        "macos_unifiedlog" => 21,
        "macos_activity" => 22,
        "macos_launchd" => 23,
        "macos_fsevents" => 24,
        // Generic content sweep is always last.
        "yara_target" => 50,
        _ => 99,
    }
}

/// Draw order *within* a class (lower = extracted first). Only evtx is
/// sub-ranked: a Windows disk carries hundreds of low-signal
/// `Microsoft-Windows-*/Operational` logs that sort alphabetically *ahead* of
/// `Security.evtx`/`System.evtx`, so without this the canonical logs that
/// Sigma/hayabusa rules actually fire on would be the ones crowded out of the
/// budget. Tier 0 = the core four (Security/System/Sysmon/PowerShell); tier 1 =
/// other named high-signal logs (Application, forwarded/rotated security,
/// task-scheduler, defender, winrm, wmi, terminal-services, applocker); tier 2
/// = the per-provider operational tail.
fn artifact_subrank(class: &str, rel_path: &str) -> u8 {
    if class != "evtx" {
        return 0;
    }
    let lower = rel_path.replace('\\', "/").to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or("");
    if name == "security.evtx"
        || name == "system.evtx"
        || name.contains("sysmon")
        || name.contains("powershell")
    {
        0
    } else if name == "application.evtx"
        || name == "forwardedevents.evtx"
        || name.starts_with("archive-security")
        || name.contains("taskscheduler")
        || name.contains("windows defender")
        || name.contains("winrm")
        || name.contains("wmi-activity")
        || name.contains("terminalservices")
        || name.contains("applocker")
        || !name.starts_with("microsoft-windows-")
    {
        1
    } else {
        2
    }
}

/// Classify listing entries into wanted-class extraction candidates, dropping
/// reallocated deleted entries (extraction would return the reusing live
/// file's bytes) and — when recovery is opted out — deleted entries entirely.
/// Returns `(candidates, deleted_entries_seen, deleted_skipped_realloc)` so
/// the output counters stay honest even when nothing is recovered.
fn build_candidates(
    listed: Vec<FlsEntry>,
    wanted: &BTreeMap<&'static str, bool>,
    recover_deleted: bool,
) -> (Vec<Candidate>, usize, usize) {
    let deleted_entries_seen = listed.iter().filter(|entry| entry.deleted).count();
    let deleted_skipped_realloc = listed
        .iter()
        .filter(|entry| entry.deleted && entry.realloc)
        .count();
    let candidates = listed
        .into_iter()
        .filter(|entry| !entry.realloc && (recover_deleted || !entry.deleted))
        .filter_map(|entry| {
            let class = classify_artifact_path(&entry.path)?;
            wanted
                .get(class)
                .copied()
                .unwrap_or(false)
                .then_some(Candidate {
                    class,
                    inode: entry.inode,
                    path: entry.path,
                    deleted: entry.deleted,
                })
        })
        .collect();
    (candidates, deleted_entries_seen, deleted_skipped_realloc)
}

/// Choose up to `limit` artifacts to extract, allocating the budget *fairly
/// across classes* so no single voluminous class starves the rest. Classes are
/// visited in [`class_priority`] order and drawn round-robin: every class with
/// candidates gets a turn each pass, and a class that drains early hands its
/// unused budget to the others. Within a class, [`artifact_subrank`], then
/// allocated-before-deleted, then path order decides which artifacts win the
/// class's share — recovered-deleted entries never crowd out live ones. Pure
/// (no I/O) so the allocation is unit-testable.
fn select_artifacts(candidates: Vec<Candidate>, limit: usize) -> Vec<Candidate> {
    let mut buckets: BTreeMap<u8, Vec<Candidate>> = BTreeMap::new();
    for candidate in candidates {
        buckets
            .entry(class_priority(candidate.class))
            .or_default()
            .push(candidate);
    }
    let mut queues: Vec<VecDeque<Candidate>> = buckets
        .into_values()
        .map(|mut bucket| {
            bucket.sort_by(|a, b| {
                artifact_subrank(a.class, &a.path)
                    .cmp(&artifact_subrank(b.class, &b.path))
                    .then_with(|| a.deleted.cmp(&b.deleted))
                    .then_with(|| a.path.cmp(&b.path))
            });
            VecDeque::from(bucket)
        })
        .collect();

    let mut selected = Vec::new();
    while selected.len() < limit && queues.iter().any(|queue| !queue.is_empty()) {
        for queue in &mut queues {
            if selected.len() >= limit {
                break;
            }
            if let Some(item) = queue.pop_front() {
                selected.push(item);
            }
        }
    }
    selected
}

/// Per-extract counters shared by [`tsk_extract`] and [`mock_extract`].
#[derive(Debug, Default)]
struct ExtractStats {
    skipped_oversize: usize,
    deleted_recovered: usize,
    deleted_recovery_failed: usize,
}

/// `icat` one inode out of the image, streaming to disk (no in-memory
/// buffering) and enforcing the size cap. Live files land under
/// `output_dir/<class>/<rel_path>`; recovered-deleted entries under
/// `output_dir/<class>/__deleted__/<inode>/<rel_path>` so recovered content is
/// unmistakable in the ledger and report, and same-path collisions cannot
/// overwrite a live artifact. A failed `icat` (unreadable inode) is skipped,
/// not fatal; a zero-byte recovered-deleted file counts as a failed recovery.
#[allow(clippy::too_many_arguments)]
fn tsk_extract(
    image_paths: &[PathBuf],
    sector_offset: Option<u64>,
    candidate: &Candidate,
    output_dir: &Path,
    max_artifact_bytes: u64,
    out: &mut Vec<ExtractedDiskArtifact>,
    stats: &mut ExtractStats,
) -> Result<(), DiskError> {
    let class_dir = output_dir.join(candidate.class);
    let base = if candidate.deleted {
        safe_join(&class_dir.join("__deleted__"), &candidate.inode)
    } else {
        class_dir
    };
    let dest = safe_join(&base, &candidate.path);
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    let bin = std::env::var("FINDEVIL_ICAT_BIN").unwrap_or_else(|_| "icat".to_string());
    let mut command = Command::new(&bin);
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    append_image_args(&mut command, image_paths);
    command.arg(&candidate.inode);
    let file = fs::File::create(&dest).map_err(|source| DiskError::Io {
        path: dest.clone(),
        source,
    })?;
    let icat_status = command
        .stdout(file)
        .status()
        .map_err(|source| DiskError::Io {
            path: PathBuf::from(&bin),
            source,
        })?;
    if !icat_status.success() {
        let _ = fs::remove_file(&dest);
        if candidate.deleted {
            stats.deleted_recovery_failed += 1;
        }
        return Ok(());
    }
    let size = fs::metadata(&dest)
        .map_err(|source| DiskError::Io {
            path: dest.clone(),
            source,
        })?
        .len();
    if candidate.deleted && size == 0 {
        // The dirent parsed but the content run is gone — nothing recovered.
        let _ = fs::remove_file(&dest);
        stats.deleted_recovery_failed += 1;
        return Ok(());
    }
    if size > max_artifact_bytes {
        let _ = fs::remove_file(&dest);
        stats.skipped_oversize += 1;
        return Ok(());
    }
    if candidate.deleted {
        stats.deleted_recovered += 1;
    }
    out.push(ExtractedDiskArtifact {
        artifact_class: candidate.class.to_string(),
        source_path: PathBuf::from(&candidate.path),
        extracted_path: dest,
        size_bytes: size,
        recovered_deleted: candidate.deleted,
    });
    Ok(())
}

/// Join an image-internal path under `base`, keeping only normal components so a
/// hostile image filename can't escape the output directory.
fn safe_join(base: &Path, rel: &str) -> PathBuf {
    let mut dest = base.to_path_buf();
    for part in rel.replace('\\', "/").split('/') {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        dest.push(part);
    }
    dest
}

/// Map a carved file path to a forensic class. Order matters: OS-specific
/// classes are tried before the generic Windows content sweep, so a macOS
/// `Library/...` path or a Linux `/var/log/...` path wins over the `users/`
/// catch-all. Split per-OS to keep each branch's complexity bounded.
fn classify_artifact_path(rel: &str) -> Option<&'static str> {
    let rel = rel.replace('\\', "/").to_ascii_lowercase();
    let name = rel.rsplit('/').next().unwrap_or(rel.as_str());
    classify_windows_specific(name, &rel)
        .or_else(|| classify_linux(name, &rel))
        .or_else(|| classify_macos(name, &rel))
        .or_else(|| classify_windows_generic(&rel))
}

/// Windows filesystem + registry + decoded execution/persistence/anti-forensic
/// inputs. These feed the typed downstream wrappers (`ez_parse`, `plaso_parse`).
fn classify_windows_specific(name: &str, rel: &str) -> Option<&'static str> {
    if name == "$mft" || name == "mft" {
        Some("mft")
    } else if name == "$j" || rel.contains("$usnjrnl") || has_extension(name, "usn") {
        Some("usnjrnl")
    } else if has_extension(name, "pf") {
        Some("prefetch")
    } else if name == "amcache.hve" {
        Some("amcache")
    } else if name == "srudb.dat" {
        Some("srum")
    } else if matches!(
        name,
        "software" | "system" | "sam" | "security" | "ntuser.dat" | "usrclass.dat"
    ) {
        Some("registry")
    } else if has_extension(name, "log1") || has_extension(name, "log2") {
        // NTFS registry transaction logs (dirty-hive replay), e.g. SYSTEM.LOG1.
        Some("reg_txlog")
    } else if has_extension(name, "evtx") {
        Some("evtx")
    } else if has_extension(name, "lnk") {
        Some("lnk")
    } else if name.ends_with(".automaticdestinations-ms")
        || name.ends_with(".customdestinations-ms")
    {
        Some("jumplist")
    } else if (name.starts_with("$i") && rel.contains("$recycle.bin"))
        || (name == "info2" && (rel.starts_with("recycler/") || rel.contains("/recycler/")))
    {
        Some("recyclebin")
    } else if has_extension(name, "evt") {
        Some("legacy_evt")
    } else if name == "index.dat"
        && (rel.contains("/history.ie5/") || rel.contains("/temporary internet files/"))
    {
        Some("ie_history")
    } else if name == "thumbs.db"
        || name.ends_with(".thumbcache")
        || ((name.starts_with("thumbcache_") || name.starts_with("iconcache_"))
            && has_extension(name, "db"))
    {
        // XP Thumbs.db plus the Vista+ Explorer caches (thumbcache_####.db /
        // iconcache_####.db); the bare `.thumbcache` extension is kept for
        // pre-existing fixtures.
        Some("thumbnail")
    } else if rel.contains("/system32/tasks/") || rel.starts_with("windows/system32/tasks/") {
        Some("scheduled_task")
    } else if matches!(
        name,
        "history" | "places.sqlite" | "web data" | "cookies" | "login data"
    ) {
        Some("browser_db")
    } else {
        None
    }
}

/// Linux host classes. `matches_filesystem_description` already accepts
/// linux/ext, so TSK reads these — this makes them auto-extract.
fn classify_linux(name: &str, rel: &str) -> Option<&'static str> {
    if (rel.starts_with("etc/") || rel.contains("/etc/"))
        && matches!(name, "passwd" | "shadow" | "group" | "sudoers")
    {
        Some("linux_account")
    } else if rel.starts_with("var/log/") || rel.contains("/var/log/") {
        Some("linux_log")
    } else if matches!(name, ".bash_history" | ".zsh_history" | ".python_history") {
        Some("linux_shell_history")
    } else if rel.contains("/.ssh/authorized_keys")
        || rel.contains("/.ssh/known_hosts")
        || rel.starts_with(".ssh/authorized_keys")
    {
        Some("linux_ssh")
    } else if rel.contains("var/spool/cron")
        || rel.starts_with("etc/cron")
        || rel.contains("/etc/cron")
    {
        Some("linux_cron")
    } else {
        None
    }
}

/// macOS host classes.
fn classify_macos(name: &str, rel: &str) -> Option<&'static str> {
    if has_extension(name, "tracev3") {
        Some("macos_unifiedlog")
    } else if matches!(name, "knowledgec.db" | "tcc.db")
        || name.starts_with("com.apple.launchservices.quarantineevents")
    {
        Some("macos_activity")
    } else if rel.contains("library/launchagents/") || rel.contains("library/launchdaemons/") {
        Some("macos_launchd")
    } else if rel.contains(".fseventsd/") {
        Some("macos_fsevents")
    } else {
        None
    }
}

/// Generic Windows content sweep — the yara catch-all. Kept last so specific
/// OS classes always win over the profile/`programdata` directory match.
/// `documents and settings/` is the pre-Vista (XP/2003) equivalent of
/// `users/`; without it the whole user-profile tree on an XP-era image is
/// invisible to the content sweep, so both live and recovered-deleted profile
/// files go unclassified.
fn classify_windows_generic(rel: &str) -> Option<&'static str> {
    if rel.starts_with("users/")
        || rel.contains("/users/")
        || rel.starts_with("documents and settings/")
        || rel.contains("/documents and settings/")
        || rel.starts_with("programdata/")
        || rel.contains("/programdata/")
        || rel.starts_with("windows/temp/")
        || rel.contains("/windows/temp/")
    {
        Some("yara_target")
    } else {
        None
    }
}

fn wanted_kinds(kinds: &[ArtifactKind]) -> BTreeMap<&'static str, bool> {
    let mut wanted = BTreeMap::new();
    let classes: Vec<&'static str> = if kinds.is_empty() {
        vec![
            "mft",
            "usnjrnl",
            "prefetch",
            "registry",
            "evtx",
            "yara_target",
            "amcache",
            "srum",
            "lnk",
            "jumplist",
            "scheduled_task",
            "recyclebin",
            "reg_txlog",
            "browser_db",
            "legacy_evt",
            "ie_history",
            "thumbnail",
            "linux_account",
            "linux_log",
            "linux_shell_history",
            "linux_ssh",
            "linux_cron",
            "macos_unifiedlog",
            "macos_activity",
            "macos_launchd",
            "macos_fsevents",
        ]
    } else {
        kinds
            .iter()
            .map(|k| match k {
                ArtifactKind::Mft => "mft",
                ArtifactKind::UsnJrnl => "usnjrnl",
                ArtifactKind::Prefetch => "prefetch",
                ArtifactKind::Registry => "registry",
                ArtifactKind::Evtx => "evtx",
                ArtifactKind::YaraTarget => "yara_target",
                ArtifactKind::Amcache => "amcache",
                ArtifactKind::Srum => "srum",
                ArtifactKind::Lnk => "lnk",
                ArtifactKind::Jumplist => "jumplist",
                ArtifactKind::ScheduledTask => "scheduled_task",
                ArtifactKind::Recyclebin => "recyclebin",
                ArtifactKind::RegTxlog => "reg_txlog",
                ArtifactKind::BrowserDb => "browser_db",
                ArtifactKind::LegacyEvt => "legacy_evt",
                ArtifactKind::IeHistory => "ie_history",
                ArtifactKind::Thumbnail => "thumbnail",
                ArtifactKind::LinuxAccount => "linux_account",
                ArtifactKind::LinuxLog => "linux_log",
                ArtifactKind::LinuxShellHistory => "linux_shell_history",
                ArtifactKind::LinuxSsh => "linux_ssh",
                ArtifactKind::LinuxCron => "linux_cron",
                ArtifactKind::MacosUnifiedlog => "macos_unifiedlog",
                ArtifactKind::MacosActivity => "macos_activity",
                ArtifactKind::MacosLaunchd => "macos_launchd",
                ArtifactKind::MacosFsevents => "macos_fsevents",
            })
            .collect()
    };
    for class in classes {
        wanted.insert(class, true);
    }
    wanted
}

pub(crate) fn case_dir(case_id: &str) -> Result<PathBuf, DiskError> {
    if !super::case_id::is_valid_case_id(case_id) {
        return Err(DiskError::InvalidCaseId(case_id.to_string()));
    }
    let dir = findevil_home()?.join("cases").join(case_id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(DiskError::CaseNotFound(case_id.to_string()))
    }
}

fn findevil_home() -> Result<PathBuf, DiskError> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Ok(PathBuf::from(h).join(".findevil"));
        }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return Ok(PathBuf::from(p).join(".findevil"));
        }
    }
    Err(DiskError::CaseNotFound("FINDEVIL_HOME".to_string()))
}

fn read_ledger(path: &Path) -> Result<SessionLedger, DiskError> {
    if !path.exists() {
        return Ok(SessionLedger::default());
    }
    let text = fs::read_to_string(path).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    serde_json::from_str(&text).map_err(DiskError::Serialize)
}

fn write_ledger(path: &Path, ledger: &SessionLedger) -> Result<(), DiskError> {
    let text = serde_json::to_string_pretty(ledger)?;
    fs::write(path, text).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn upsert_resource(path: &Path, resource: SessionResource) -> Result<(), DiskError> {
    let mut ledger = read_ledger(path)?;
    ledger.resources.retain(|r| r.id != resource.id);
    ledger.resources.push(resource);
    write_ledger(path, &ledger)
}

fn create_dir(path: &Path) -> Result<(), DiskError> {
    fs::create_dir_all(path).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

const fn default_limit() -> usize {
    500
}

const fn default_max_artifact_bytes() -> u64 {
    DEFAULT_MAX_ARTIFACT_BYTES
}

const fn default_true() -> bool {
    true
}

fn has_extension(name: &str, ext: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|actual| actual.eq_ignore_ascii_case(ext))
}

fn tail_utf8_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

#[cfg(test)]
mod tests {
    use super::{
        artifact_subrank, case_dir, class_priority, classify_artifact_path, direct_tsk_mount,
        ewfmount_available, is_missing_binary, mock_list, parse_fls_line, parse_mmls_partitions,
        parse_mmls_primary_partition_offset, safe_join, select_artifacts, unmount_steps,
        wanted_kinds, Candidate, DiskError, FlsEntry, DIRECT_TSK_COMMAND,
    };
    use std::path::Path;

    #[test]
    fn safe_join_strips_traversal_and_stays_under_base() {
        let base = Path::new("/cases/abc/extracted");
        // A `..`-laden relative path must not escape the base: every `..`,
        // `.`, and empty segment is dropped, so the result is always a
        // descendant of base. This is the only write-side path guard.
        for rel in [
            "../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/abs/looking/path",
            "./a/../../../b",
            "../",
            "..",
        ] {
            let joined = safe_join(base, rel);
            assert!(joined.starts_with(base), "{rel:?} escaped base: {joined:?}");
            assert!(
                !joined.components().any(|c| c.as_os_str() == ".."),
                "{rel:?} left a .. component: {joined:?}"
            );
        }
    }

    #[test]
    fn safe_join_keeps_legitimate_nested_paths() {
        let base = Path::new("/cases/abc/extracted");
        let joined = safe_join(base, "registry/Windows/System32/config/SOFTWARE");
        assert_eq!(
            joined,
            Path::new("/cases/abc/extracted/registry/Windows/System32/config/SOFTWARE")
        );
    }

    #[test]
    fn mock_list_walks_tree_and_keeps_relative_paths() {
        // The mock disk-extract path (tests + Windows, no TSK) walks fs_root.
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path();
        std::fs::create_dir_all(root.join("Windows/Prefetch")).unwrap();
        std::fs::create_dir_all(root.join("Windows/System32/config")).unwrap();
        std::fs::write(root.join("$MFT"), b"mft").unwrap();
        std::fs::write(root.join("Windows/Prefetch/CMD.EXE-1.pf"), b"pf").unwrap();
        std::fs::write(root.join("Windows/System32/config/SOFTWARE"), b"hive").unwrap();

        let mut listed = mock_list(root).expect("walk");
        listed.sort_by(|a, b| a.path.cmp(&b.path));
        assert!(
            listed.iter().all(|entry| !entry.deleted && !entry.realloc),
            "a directory walk has no deleted-file concept"
        );
        let paths: Vec<&str> = listed.iter().map(|entry| entry.path.as_str()).collect();
        assert!(paths.contains(&"$MFT"), "{paths:?}");
        assert!(
            paths.contains(&"Windows/Prefetch/CMD.EXE-1.pf"),
            "{paths:?}"
        );
        assert!(
            paths.contains(&"Windows/System32/config/SOFTWARE"),
            "{paths:?}"
        );
        // Every listed entry classifies into a forensic class via the same
        // classifier the TSK path uses.
        let classes: std::collections::BTreeSet<_> = listed
            .iter()
            .filter_map(|entry| classify_artifact_path(&entry.path))
            .collect();
        assert!(classes.contains("mft"));
        assert!(classes.contains("prefetch"));
        assert!(classes.contains("registry"));
    }

    #[test]
    fn classify_artifact_path_matches_thumbnail_caches() {
        assert_eq!(
            classify_artifact_path("Documents and Settings/Suspect User/My Documents/Thumbs.db"),
            Some("thumbnail")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.thumbcache"
            ),
            Some("thumbnail")
        );
        // Real Vista+ Explorer caches are thumbcache_####.db / iconcache_*.db —
        // the shapes that actually exist on disk.
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/thumbcache_1024.db"
            ),
            Some("thumbnail")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/iconcache_32.db"
            ),
            Some("thumbnail")
        );
    }

    #[test]
    fn parse_fls_line_extracts_inode_and_path_for_live_files() {
        assert_eq!(
            parse_fls_line("r/r 380861-128-4:\tWindows/System32/config/SYSTEM"),
            Some(FlsEntry {
                inode: "380861-128-4".to_string(),
                path: "Windows/System32/config/SYSTEM".to_string(),
                deleted: false,
                realloc: false,
            })
        );
    }

    #[test]
    fn parse_fls_line_skips_dirs_and_blanks() {
        assert_eq!(parse_fls_line("d/d 282867-144-5:\tUsers"), None);
        assert_eq!(parse_fls_line(""), None);
        // Live entries with unknown name-type stay excluded — only deleted
        // entries are allowed the `-/r` shape.
        assert_eq!(parse_fls_line("-/r 555-128-1:\tWindows/x.pf"), None);
    }

    #[test]
    fn parse_fls_line_keeps_deleted_entries_with_markers() {
        assert_eq!(
            parse_fls_line("r/r * 999-128-1:\tWindows/Prefetch/x.pf"),
            Some(FlsEntry {
                inode: "999-128-1".to_string(),
                path: "Windows/Prefetch/x.pf".to_string(),
                deleted: true,
                realloc: false,
            })
        );
        // Deleted entries that lost their name-type still parse.
        assert_eq!(
            parse_fls_line("-/r * 555-128-1:\tDocuments and Settings/user/evil.doc"),
            Some(FlsEntry {
                inode: "555-128-1".to_string(),
                path: "Documents and Settings/user/evil.doc".to_string(),
                deleted: true,
                realloc: false,
            })
        );
        // A reallocated inode is flagged so extraction can skip it — icat
        // would return the reusing live file's content.
        assert_eq!(
            parse_fls_line("r/r * 2036-128-3(realloc):\tWINDOWS/system32/mal.dll"),
            Some(FlsEntry {
                inode: "2036-128-3".to_string(),
                path: "WINDOWS/system32/mal.dll".to_string(),
                deleted: true,
                realloc: true,
            })
        );
    }

    #[test]
    fn parse_fls_line_rejects_non_tsk_inode_tokens() {
        // The inode is passed to icat argv and used as an output path
        // component; anything but digits/dashes is hostile-listing noise.
        assert_eq!(parse_fls_line("r/r ../escape:\tWindows/x.pf"), None);
        assert_eq!(parse_fls_line("r/r abc-def:\tWindows/x.pf"), None);
    }

    #[test]
    fn classify_artifact_path_matches_forensic_classes() {
        assert_eq!(
            classify_artifact_path("Windows/System32/config/SYSTEM"),
            Some("registry")
        );
        assert_eq!(
            classify_artifact_path("Windows/Prefetch/CMD.EXE-1234.pf"),
            Some("prefetch")
        );
        assert_eq!(classify_artifact_path("$MFT"), Some("mft"));
        assert_eq!(
            classify_artifact_path("Users/bob/NTUSER.DAT"),
            Some("registry")
        );
        assert_eq!(
            classify_artifact_path("Users/bob/Desktop/evil.txt"),
            Some("yara_target")
        );
        // XP/2003 profile path (the pre-Vista `Users/` equivalent) must also
        // reach the content sweep — live and recovered-deleted alike.
        assert_eq!(
            classify_artifact_path("Documents and Settings/analyst/Local Settings/Temp/x.exe"),
            Some("yara_target")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/kernel32.dll"),
            None
        );
    }

    #[test]
    fn classify_artifact_path_matches_extended_classes() {
        // Windows decoded-execution / persistence / anti-forensic inputs the
        // carve list must hand to the downstream typed wrappers (ez_parse,
        // plaso_parse). Without these the extractor never produces an
        // Amcache.hve / SRUDB.dat / LNK / JumpList / Tasks XML to parse.
        assert_eq!(
            classify_artifact_path("Windows/appcompat/Programs/Amcache.hve"),
            Some("amcache")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/sru/SRUDB.dat"),
            Some("srum")
        );
        assert_eq!(
            classify_artifact_path("Users/bob/AppData/Roaming/Microsoft/Windows/Recent/evil.lnk"),
            Some("lnk")
        );
        assert_eq!(
            classify_artifact_path("RECYCLER/S-1-5-21-1000/INFO2"),
            Some("recyclebin")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/config/SecEvent.Evt"),
            Some("legacy_evt")
        );
        assert_eq!(
            classify_artifact_path(
                "Documents and Settings/Suspect User/Local Settings/History/History.IE5/index.dat"
            ),
            Some("ie_history")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Roaming/Microsoft/Windows/Recent/\
                 AutomaticDestinations/1b4dd67f29cb1962.automaticDestinations-ms"
            ),
            Some("jumplist")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/Tasks/EvilPersist"),
            Some("scheduled_task")
        );
        assert_eq!(
            classify_artifact_path("$Recycle.Bin/S-1-5-21-1004/$IABC123.txt"),
            Some("recyclebin")
        );
        assert_eq!(
            classify_artifact_path("Windows/System32/config/SYSTEM.LOG1"),
            Some("reg_txlog")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History"
            ),
            Some("browser_db")
        );
        // A bare SYSTEM hive still classifies as registry, not reg_txlog.
        assert_eq!(
            classify_artifact_path("Windows/System32/config/SYSTEM"),
            Some("registry")
        );

        // Linux: OS-aware auto-classification. matches_filesystem_description
        // already accepts linux/ext, so TSK reads these — now they auto-extract.
        assert_eq!(classify_artifact_path("etc/passwd"), Some("linux_account"));
        assert_eq!(
            classify_artifact_path("var/log/auth.log"),
            Some("linux_log")
        );
        assert_eq!(
            classify_artifact_path("home/bob/.bash_history"),
            Some("linux_shell_history")
        );
        assert_eq!(
            classify_artifact_path("home/bob/.ssh/authorized_keys"),
            Some("linux_ssh")
        );
        assert_eq!(
            classify_artifact_path("var/spool/cron/crontabs/root"),
            Some("linux_cron")
        );

        // macOS
        assert_eq!(
            classify_artifact_path("private/var/db/diagnostics/Persist/0000.tracev3"),
            Some("macos_unifiedlog")
        );
        assert_eq!(
            classify_artifact_path("Users/bob/Library/Application Support/Knowledge/knowledgeC.db"),
            Some("macos_activity")
        );
        assert_eq!(
            classify_artifact_path("Library/LaunchDaemons/com.evil.plist"),
            Some("macos_launchd")
        );
        assert_eq!(
            classify_artifact_path(".fseventsd/0000000000abcd12"),
            Some("macos_fsevents")
        );
    }

    #[test]
    fn wanted_kinds_default_includes_extended_classes() {
        // Default extraction (empty artifact_kinds) must carve the new classes,
        // or the downstream wrappers never receive disk-image input.
        let wanted = wanted_kinds(&[]);
        for class in [
            "mft",
            "registry",
            "amcache",
            "srum",
            "lnk",
            "jumplist",
            "scheduled_task",
            "recyclebin",
            "reg_txlog",
            "browser_db",
            "legacy_evt",
            "ie_history",
            "thumbnail",
            "linux_log",
            "macos_unifiedlog",
        ] {
            assert!(wanted.contains_key(class), "default set missing {class}");
        }
    }

    #[test]
    fn class_priority_orders_high_value_before_yara() {
        assert!(class_priority("mft") < class_priority("registry"));
        assert!(class_priority("registry") < class_priority("prefetch"));
        assert!(class_priority("prefetch") < class_priority("yara_target"));
    }

    #[test]
    fn artifact_subrank_surfaces_canonical_evtx_before_operational_tail() {
        let logs = "Windows/System32/winevt/Logs";
        // The core logs Sigma/hayabusa fire on hardest rank ahead of the long
        // Microsoft-Windows-*/Operational tail that sorts first alphabetically.
        assert!(
            artifact_subrank("evtx", &format!("{logs}/Security.evtx"))
                < artifact_subrank(
                    "evtx",
                    &format!("{logs}/Microsoft-Windows-Kernel-WHEA%4Operational.evtx")
                )
        );
        assert!(
            artifact_subrank("evtx", &format!("{logs}/System.evtx"))
                < artifact_subrank(
                    "evtx",
                    &format!("{logs}/Microsoft-Windows-Bits-Client%4Operational.evtx")
                )
        );
        // Sysmon / PowerShell match by substring regardless of provider prefix.
        assert_eq!(
            artifact_subrank(
                "evtx",
                &format!("{logs}/Microsoft-Windows-Sysmon%4Operational.evtx")
            ),
            0
        );
        // Non-evtx classes are never sub-ranked.
        assert_eq!(
            artifact_subrank("prefetch", "Windows/Prefetch/CMD.EXE-1.pf"),
            0
        );
    }

    #[test]
    fn select_artifacts_gives_every_class_a_fair_share() {
        // A budget far smaller than one voluminous class must still reach the
        // others: 400 prefetch + 600 operational evtx + 1 mft, limit 50 -> all
        // three classes represented (the old global-priority sort extracted
        // zero evtx), and the canonical Security.evtx wins evtx's share over
        // the operational tail.
        fn live(class: &'static str, inode: &str, path: String) -> Candidate {
            Candidate {
                class,
                inode: inode.to_string(),
                path,
                deleted: false,
            }
        }
        let mut candidates: Vec<Candidate> = Vec::new();
        for i in 0..400 {
            candidates.push(live("prefetch", &format!("{i}"), {
                format!("Windows/Prefetch/A{i:04}.pf")
            }));
        }
        for i in 0..600 {
            candidates.push(live(
                "evtx",
                &format!("e{i}"),
                format!(
                    "Windows/System32/winevt/Logs/Microsoft-Windows-Zzz{i:04}%4Operational.evtx"
                ),
            ));
        }
        candidates.push(live(
            "evtx",
            "sec",
            "Windows/System32/winevt/Logs/Security.evtx".to_string(),
        ));
        candidates.push(live("mft", "mft", "$MFT".to_string()));

        let selected = select_artifacts(candidates, 50);
        assert_eq!(selected.len(), 50);
        let classes: std::collections::HashSet<&str> = selected.iter().map(|c| c.class).collect();
        assert!(classes.contains("prefetch"), "prefetch starved");
        assert!(classes.contains("evtx"), "evtx starved (the original bug)");
        assert!(classes.contains("mft"), "mft missing");
        assert!(
            selected.iter().any(|c| c.path.ends_with("/Security.evtx")),
            "canonical Security.evtx must win evtx's fair share"
        );
    }

    #[test]
    fn select_artifacts_draws_allocated_before_deleted_within_a_class() {
        // With a class budget of 2, the two live prefetch files must win over
        // the alphabetically-earlier deleted one: recovered-deleted entries
        // never crowd allocated evidence out of the budget.
        let candidates = vec![
            Candidate {
                class: "prefetch",
                inode: "9".to_string(),
                path: "Windows/Prefetch/AAA-DELETED.pf".to_string(),
                deleted: true,
            },
            Candidate {
                class: "prefetch",
                inode: "1".to_string(),
                path: "Windows/Prefetch/LIVE1.pf".to_string(),
                deleted: false,
            },
            Candidate {
                class: "prefetch",
                inode: "2".to_string(),
                path: "Windows/Prefetch/LIVE2.pf".to_string(),
                deleted: false,
            },
        ];
        let selected = select_artifacts(candidates, 2);
        assert_eq!(selected.len(), 2);
        assert!(
            selected.iter().all(|c| !c.deleted),
            "deleted entry crowded out a live file: {selected:?}"
        );
    }

    #[test]
    fn select_artifacts_caps_at_limit_and_handles_empty() {
        assert!(select_artifacts(Vec::new(), 10).is_empty());
        let candidates = vec![
            Candidate {
                class: "mft",
                inode: "1".to_string(),
                path: "$MFT".to_string(),
                deleted: false,
            },
            Candidate {
                class: "prefetch",
                inode: "2".to_string(),
                path: "Windows/Prefetch/X.pf".to_string(),
                deleted: false,
            },
        ];
        assert_eq!(select_artifacts(candidates.clone(), 1).len(), 1);
        assert_eq!(select_artifacts(candidates, 5).len(), 2); // limit above supply
    }

    #[test]
    fn unmount_steps_ewf_plus_ntfs_releases_loop_then_container() {
        let mp = Path::new("/m");
        let fs_dir = mp.join("fs");
        let ewf_dir = mp.join("ewf");
        let steps = unmount_steps(mp, &fs_dir, "umount");
        assert_eq!(
            steps,
            vec![
                (
                    "umount".to_string(),
                    vec![fs_dir.to_string_lossy().to_string()]
                ),
                (
                    "umount".to_string(),
                    vec![ewf_dir.to_string_lossy().to_string()]
                ),
            ]
        );
    }

    #[test]
    fn unmount_steps_ewf_only_releases_container() {
        let mp = Path::new("/m");
        let ewf_dir = mp.join("ewf");
        let steps = unmount_steps(mp, &ewf_dir, "umount");
        assert_eq!(
            steps,
            vec![(
                "umount".to_string(),
                vec![ewf_dir.to_string_lossy().to_string()]
            )]
        );
    }

    #[test]
    fn unmount_steps_raw_umounts_the_mount_point() {
        let mp = Path::new("/m");
        let steps = unmount_steps(mp, mp, "umount");
        assert_eq!(
            steps,
            vec![("umount".to_string(), vec![mp.to_string_lossy().to_string()])]
        );
    }

    #[test]
    fn direct_tsk_mount_registers_a_mounted_read_off_the_image() {
        // The ewfmount-less fallback must register a resource disk_extract can
        // consume: status "mounted", fs_root == the image itself, and a sentinel
        // command that is neither "mock" (which would force the walk path) nor a
        // real mount command (which disk_unmount would try to tear down).
        let image = Path::new("/evidence/host-c-drive.E01");
        let (status, fs_root, command, stderr_tail, note) =
            direct_tsk_mount(image, "ewfmount gone");
        assert_eq!(status, "mounted");
        assert_eq!(fs_root, image);
        assert_eq!(command, vec![DIRECT_TSK_COMMAND.to_string()]);
        assert_ne!(command.first().map(String::as_str), Some("mock"));
        assert!(stderr_tail.is_empty());
        assert!(note.contains("no FUSE/loop mount"), "note was: {note}");
    }

    #[test]
    fn ewfmount_available_is_false_for_a_missing_binary() {
        // A binary that cannot be spawned (ENOENT) is the exact condition that
        // must trigger the direct-TSK fallback.
        assert!(!ewfmount_available(
            "findevil-definitely-not-a-real-binary-zzz"
        ));
    }

    #[test]
    fn is_missing_binary_matches_command_not_found_variants() {
        // The reported live failure was literally this line.
        assert!(is_missing_binary("sudo: ewfmount: command not found"));
        assert!(is_missing_binary("ewfmount: command not found"));
        assert!(is_missing_binary(
            "exec: \"ewfmount\": executable file not found in $PATH"
        ));
        // A genuine mount failure must NOT be mistaken for a missing binary —
        // that stays a surfaced error, not a silent fallback.
        assert!(!is_missing_binary(
            "ewfmount: unable to open file(s): permission denied"
        ));
        assert!(!is_missing_binary(""));
    }

    #[test]
    fn mmls_parser_returns_sole_filesystem_partition_offset() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000062   0000000063   Unallocated
002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
";

        assert_eq!(parse_mmls_primary_partition_offset(output), Some(63 * 512));
    }

    #[test]
    fn mmls_parser_ignores_metadata_and_unallocated_rows() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
";

        assert_eq!(parse_mmls_primary_partition_offset(output), None);
    }

    /// Regression: on a full Windows disk image the first filesystem partition
    /// is the tiny "System Reserved" boot volume; the OS/C: volume that holds
    /// the event logs and registry is a separate, much larger partition. The
    /// parser must select the largest (offset 718848), not the first (2048) —
    /// selecting the first walked only ~166 files and extracted zero EVTX.
    #[test]
    fn mmls_parser_selects_largest_partition_not_the_system_reserved_stub() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)
003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)
004:  -------   0023590912   0023592959   0000002048   Unallocated
";

        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(718_848 * 512)
        );
    }

    /// The largest filesystem partition wins even when it is listed before the
    /// smaller ones, so ordering never masks the size comparison.
    #[test]
    fn mmls_parser_selects_largest_partition_regardless_of_order() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
002:  000:000   0000002048   0020000000   0019997953   NTFS / exFAT (0x07)
003:  000:001   0020002048   0020718847   0000716800   NTFS / exFAT (0x07)
";

        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(2048 * 512)
        );
    }

    #[test]
    fn mmls_enumerates_every_filesystem_partition_in_table_order() {
        // A full Windows disk: System Reserved stub + the large C: volume + a
        // separate FAT data volume. All three are filesystems; the Meta and
        // Unallocated rows must be excluded. Enumeration keeps every volume so a
        // multi-volume disk is not silently reduced to just the primary.
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000718847   0000716800   NTFS / exFAT (0x07)
003:  000:001   0000718848   0023590911   0022872064   NTFS / exFAT (0x07)
004:  000:002   0023590912   0025590911   0002000000   FAT32 (0x0c)
";
        let parts = parse_mmls_partitions(output);
        assert_eq!(
            parts.len(),
            3,
            "three filesystem partitions, no meta/unalloc"
        );
        assert_eq!(parts[0].slot, 2);
        assert_eq!(parts[0].start_sector, 2048);
        assert_eq!(parts[0].byte_offset, 2048 * 512);
        assert_eq!(parts[1].slot, 3);
        assert_eq!(parts[1].length_sectors, 22_872_064);
        assert_eq!(parts[1].byte_offset, 718_848 * 512);
        assert_eq!(parts[2].slot, 4);
        assert!(parts[2].description.to_lowercase().contains("fat32"));
        // The primary selector agrees with the enumeration: largest = slot 3.
        assert_eq!(
            parse_mmls_primary_partition_offset(output),
            Some(718_848 * 512)
        );
    }

    #[test]
    fn mmls_enumeration_empty_for_bare_volume_no_table() {
        // A bare volume image (no partition table) yields no partitions; callers
        // fall back to reading at offset 0.
        let output = r"Cannot determine partition type
";
        assert!(parse_mmls_partitions(output).is_empty());
    }

    #[test]
    fn case_dir_rejects_traversal_case_id_before_join() {
        match case_dir("../../etc") {
            Err(DiskError::InvalidCaseId(id)) => assert_eq!(id, "../../etc"),
            other => panic!("expected InvalidCaseId, got {other:?}"),
        }
        match case_dir("a/b") {
            Err(DiskError::InvalidCaseId(_)) => {}
            other => panic!("expected InvalidCaseId for slash, got {other:?}"),
        }
        match case_dir("..") {
            Err(DiskError::InvalidCaseId(_)) => {}
            other => panic!("expected InvalidCaseId for .., got {other:?}"),
        }
    }
}
