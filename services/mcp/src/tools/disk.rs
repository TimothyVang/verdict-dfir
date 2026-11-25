//! Disk image mount/extract helpers.
//!
//! These tools intentionally expose a narrow typed surface rather than a
//! generic shell runner. Real mounting is best-effort on Unix/SIFT via fixed
//! tool invocations; tests and Windows use the explicit `mock` mode so normal
//! CI never needs FUSE, libewf, or administrator privileges.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const LEDGER_NAME: &str = "session_resources.json";
const STDERR_TAIL_BYTES: usize = 4096;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

/// Hard cap on deleted-but-resident artifacts recovered per extraction, so a
/// filesystem holding tens of thousands of unallocated MFT records can never
/// swamp the class budget (or the icat call count) with carved candidates.
const MAX_RECOVERED_DELETED: usize = 256;

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
    WebLog,
    WebrootScript,
    MailStore,
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
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExtractedDiskArtifact {
    pub artifact_class: String,
    pub source_path: PathBuf,
    pub extracted_path: PathBuf,
    pub size_bytes: u64,
    /// True when this artifact was carved out of a *deleted* directory entry
    /// whose MFT record was still resident, rather than read from a live file.
    /// The bytes are genuine (the signature check below rejects reallocated
    /// clusters), but the provenance is different and a reader must see it:
    /// a recovered artifact can be a stale copy and its parent directory
    /// listing no longer vouches for it. `serde(default)` so a ledger written
    /// before this field still deserializes.
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
    /// How many of `artifacts` were carved from deleted-but-resident entries.
    #[serde(default)]
    pub artifacts_recovered_deleted: usize,
    pub max_artifact_bytes: u64,
    /// Scoped gaps the extraction itself observed — today: a Prefetch directory
    /// that exists but yields zero *allocated* files. The caller folds these
    /// into the case's analysis limitations. An extraction that silently
    /// returns nothing for a wiped directory is indistinguishable from one that
    /// found nothing to wipe, which is the bug this field closes.
    #[serde(default)]
    pub analysis_limitations: Vec<String>,
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

    let (status, fs_root, command, stderr_tail, note) = match input.mode {
        DiskMode::Mock => (
            "mounted".to_string(),
            mount_point.clone(),
            vec!["mock".to_string(), "disk_mount".to_string()],
            String::new(),
            "mock mount registered; no privileged filesystem operation ran".to_string(),
        ),
        DiskMode::Auto => auto_mount(&input.image_path, &mount_point)?,
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

    let extract_id = format!("disk-extract-{}", Uuid::new_v4());
    let output_dir = case_dir.join("extracted").join("disk").join(&extract_id);
    create_dir(&output_dir)?;
    let wanted = wanted_kinds(&input.artifact_kinds);

    // Enumerate EVERY filesystem partition mmls reports, not just the first: a
    // Windows disk typically carries a ~100 MB NTFS "System Reserved" boot
    // partition *ahead of* the OS volume, and reading only the first partition
    // extracted 256 boot-volume MFT records and zero registry/evtx/prefetch —
    // every artifact of interest lives on the volume the engine never opened.
    // Partitions come back in preference order (largest first) so the
    // fair-share budget favours the real OS volume; an empty list means a bare
    // volume image that TSK reads at offset 0.
    let partitions = filesystem_partitions(&image_path);
    let sector_offsets: Vec<Option<u64>> = if partitions.is_empty() {
        vec![None]
    } else {
        partitions.iter().map(|p| Some(p.start_sector)).collect()
    };

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
    let (listed, via_walk) = list_image_files(&image_path, &sector_offsets, mock_root.as_deref())?;
    let candidates = classify_candidates(listed.clone(), &wanted);
    let recovered_candidates = candidates.iter().filter(|c| c.recovered_deleted).count();
    // A wiped Prefetch directory must be REPORTED, not silently no-op'd: the
    // count below is what a reader needs to tell "this host never ran the
    // program" from "the evidence of it running was destroyed".
    let mut analysis_limitations: Vec<String> = Vec::new();
    if wanted.get("prefetch").copied().unwrap_or(false) {
        if let Some(limitation) = prefetch_wipe_limitation(&listed, recovered_candidates) {
            analysis_limitations.push(limitation);
        }
    }
    let ordered_candidates = order_artifacts(candidates);

    let mut artifacts = Vec::new();
    let mut artifacts_skipped_oversize = 0;
    for candidate in ordered_candidates {
        if artifacts.len() >= input.limit {
            break;
        }
        match (via_walk, &mock_root) {
            (true, Some(root)) => mock_extract(
                root,
                &candidate.rel_path,
                candidate.class,
                &output_dir,
                input.max_artifact_bytes,
                &mut artifacts,
                &mut artifacts_skipped_oversize,
            )?,
            _ => tsk_extract(
                &image_path,
                &candidate,
                &output_dir,
                input.max_artifact_bytes,
                &mut artifacts,
                &mut artifacts_skipped_oversize,
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
        artifacts_skipped_oversize,
        artifacts_recovered_deleted: artifacts.iter().filter(|a| a.recovered_deleted).count(),
        max_artifact_bytes: input.max_artifact_bytes,
        analysis_limitations,
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

    let (status, command, stderr_tail) = match input.mode {
        DiskMode::Mock => (
            "unmounted".to_string(),
            vec!["mock".to_string(), "disk_unmount".to_string()],
            String::new(),
        ),
        DiskMode::Auto => auto_unmount(&mount_point, &fs_root)?,
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
    image_path: &Path,
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    if cfg!(windows) {
        return Err(DiskError::UnsupportedPlatform);
    }
    if is_ewf_image(image_path) {
        return auto_mount_ewf(image_path, mount_point);
    }
    auto_mount_raw(image_path, mount_point)
}

fn is_ewf_image(image_path: &Path) -> bool {
    let ext = image_path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    ext == "e01" || ext == "ex01"
}

fn auto_mount_ewf(
    image_path: &Path,
    mount_point: &Path,
) -> Result<(String, PathBuf, Vec<String>, String, String), DiskError> {
    let ewf_dir = mount_point.join("ewf");
    create_dir(&ewf_dir)?;
    let bin = std::env::var("EWF_MOUNT_BIN").unwrap_or_else(|_| "ewfmount".to_string());
    let args = vec![
        image_path.to_string_lossy().to_string(),
        ewf_dir.to_string_lossy().to_string(),
    ];
    // ewfmount must run as root: /etc/fuse.conf has no `user_allow_other`, so a
    // user-owned FUSE device is unreadable by the (root) loop/mount syscalls.
    let result = run_sudo_fixed(&bin, &args)?;
    if !result.0 {
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

/// Loop-mount an NTFS volume read-only with the kernel `ntfs3` driver, under
/// sudo (the EWF device is root-owned). Tries offset 0 (bare volume image),
/// then every filesystem-partition offset from `mmls` in preference order
/// (largest first), so a full disk image mounts its OS volume rather than the
/// ~100 MB System Reserved boot partition that precedes it.
fn mount_ntfs_ro(device: &Path, mount_point: &Path) -> Result<(Vec<String>, String), DiskError> {
    let mount_bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let mut offsets = vec![0u64];
    offsets.extend(filesystem_partition_byte_offsets_sudo(device));
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

/// Byte offsets of every filesystem partition in preference order, run under
/// sudo because the EWF device is root-owned. The binary stays the fixed
/// `mmls` (no env override) — a user-controlled path must not run under sudo.
/// Empty when the image is a bare volume (no partition table).
fn filesystem_partition_byte_offsets_sudo(image_path: &Path) -> Vec<u64> {
    let Ok(output) = Command::new("sudo")
        .args(["-n", "mmls"])
        .arg(image_path)
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    partition_byte_offsets(order_partitions_by_preference(
        parse_mmls_filesystem_partitions(&String::from_utf8_lossy(&output.stdout)),
    ))
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
    let offsets = filesystem_partition_byte_offsets(image_path);
    if !offsets.is_empty() {
        // Try every filesystem partition in preference order (largest first —
        // the OS volume) so a full disk image whose preferred partition can't
        // be mounted still falls back to the next one.
        let mut last_status = String::new();
        let mut failures: Vec<String> = Vec::new();
        for offset in &offsets {
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
                    format!("mounted filesystem partition read-only with loop offset {offset}"),
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
                            "mounted filesystem partition read-only with sudo loop offset {offset}"
                        ),
                    ));
                }
            }
            last_status = offset_result.1;
            failures.push(format!("offset {offset} mount failed: {}", offset_result.2));
        }
        return Err(DiskError::SubprocessFailed {
            status: last_status,
            stderr_tail: format!(
                "direct mount failed ({direct_status}): {direct_stderr}\n{}",
                failures.join("\n")
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

/// One filesystem partition row from `mmls`: start and length in 512-byte
/// sectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MmlsPartition {
    start_sector: u64,
    length_sectors: u64,
}

/// Run `mmls` (override: `FINDEVIL_MMLS_BIN`, mirroring `FINDEVIL_FLS_BIN` /
/// `FINDEVIL_ICAT_BIN`) and return the image's filesystem partitions in
/// preference order (largest first). Empty for a bare volume image — no
/// partition table, TSK reads it at offset 0.
fn filesystem_partitions(image_path: &Path) -> Vec<MmlsPartition> {
    let bin = std::env::var("FINDEVIL_MMLS_BIN").unwrap_or_else(|_| "mmls".to_string());
    let Ok(output) = Command::new(bin).arg(image_path).output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    order_partitions_by_preference(parse_mmls_filesystem_partitions(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Byte offsets (sector * 512) of every filesystem partition in preference
/// order, for `mount -o loop,offset=`. Empty for a bare volume image.
fn filesystem_partition_byte_offsets(image_path: &Path) -> Vec<u64> {
    partition_byte_offsets(filesystem_partitions(image_path))
}

fn partition_byte_offsets(partitions: Vec<MmlsPartition>) -> Vec<u64> {
    partitions
        .into_iter()
        .filter_map(|p| p.start_sector.checked_mul(512))
        .collect()
}

/// Parse every filesystem partition row from `mmls` output, in table order.
/// Meta / unallocated rows and rows whose description names no known
/// filesystem are filtered out, exactly as the old first-match parser did —
/// but EVERY matching row is returned. A Windows disk image typically carries
/// a ~100 MB "System Reserved" NTFS boot partition ahead of the OS volume;
/// stopping at the first match made the engine read the boot partition and
/// miss every registry/evtx/prefetch artifact on the disk.
fn parse_mmls_filesystem_partitions(output: &str) -> Vec<MmlsPartition> {
    let mut partitions = Vec::new();
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("meta")
            || lower.contains("unallocated")
            || !matches_filesystem_description(&lower)
        {
            continue;
        }
        // Row shape: `002:  000:000  <start>  <end>  <length>  NTFS / exFAT
        // (0x07)`. The slot fields contain `:` and the description contains
        // non-digits, so the first three all-digit fields are start, end,
        // length.
        let mut numbers = line
            .split_whitespace()
            .filter(|field| field.chars().all(|c| c.is_ascii_digit()))
            .filter_map(|field| field.parse::<u64>().ok());
        let (Some(start_sector), Some(_end), Some(length_sectors)) =
            (numbers.next(), numbers.next(), numbers.next())
        else {
            continue;
        };
        partitions.push(MmlsPartition {
            start_sector,
            length_sectors,
        });
    }
    partitions
}

/// Order partitions for extraction/mount preference: largest first, ties by
/// lower start sector. On a real multi-partition disk the OS volume dwarfs the
/// boot / System Reserved / recovery partitions (tens of GB vs ~100 MB), so
/// largest-first points the artifact budget and the mount at the volume that
/// actually holds the registry/evtx/prefetch tree — without OS-specific
/// content probing that would not generalize to Linux or macOS disks.
fn order_partitions_by_preference(mut partitions: Vec<MmlsPartition>) -> Vec<MmlsPartition> {
    partitions.sort_by(|a, b| {
        b.length_sectors
            .cmp(&a.length_sectors)
            .then_with(|| a.start_sector.cmp(&b.start_sector))
    });
    partitions
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

/// One row off a filesystem listing, before classification.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ListedFile {
    partition_rank: usize,
    sector_offset: Option<u64>,
    inode: String,
    rel_path: String,
    /// False when `fls` marked the directory entry deleted (`*`). The inode is
    /// still real — [`classify_candidates`] decides which classes are worth
    /// recovering from it.
    allocated: bool,
}

/// One parsed `fls -p` row: a regular file with a usable inode.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FlsRow {
    inode: String,
    rel_path: String,
    allocated: bool,
}

/// List every live file across the image's filesystem partitions (one
/// [`tsk_list`] per sector offset), tagging each row with its partition rank
/// and `-o` offset. One unreadable partition must not lose the readable ones:
/// a listing failure is surfaced only when *no* partition lists anything.
/// When TSK lists nothing and `mock_root` is present (mock mounts only), falls
/// back to walking that staged directory tree; the returned flag says whether
/// the walk fallback was taken.
fn list_image_files(
    image_path: &Path,
    sector_offsets: &[Option<u64>],
    mock_root: Option<&Path>,
) -> Result<(Vec<ListedFile>, bool), DiskError> {
    let mut tsk_files: Vec<ListedFile> = Vec::new();
    let mut list_error: Option<DiskError> = None;
    for (rank, offset) in sector_offsets.iter().enumerate() {
        match tsk_list(image_path, *offset) {
            Ok(files) => tsk_files.extend(files.into_iter().map(|row| ListedFile {
                partition_rank: rank,
                sector_offset: *offset,
                inode: row.inode,
                rel_path: row.rel_path,
                allocated: row.allocated,
            })),
            Err(err) => list_error = list_error.or(Some(err)),
        }
    }
    if !tsk_files.is_empty() {
        return Ok((tsk_files, false));
    }
    match (mock_root, list_error) {
        (Some(root), _) => Ok((
            mock_list(root)?
                .into_iter()
                .map(|(inode, rel_path)| ListedFile {
                    partition_rank: 0,
                    sector_offset: None,
                    inode,
                    rel_path,
                    // A staged mock tree has no unallocated entries.
                    allocated: true,
                })
                .collect(),
            true,
        )),
        (None, Some(err)) => Err(err),
        (None, None) => Ok((Vec::new(), false)),
    }
}

/// Classes whose *deleted* entries are worth recovering when the class has no
/// allocated files left at all. Prefetch only, deliberately: a .pf is a small
/// file whose MFT record usually stays resident after an SDelete-style wipe, and
/// it is the artifact class an attacker who wipes the directory is trying to
/// erase. A deleted registry hive or event log is a large, fragmented, usually
/// unrecoverable partial — carving those would fill the ledger with garbage that
/// still fails to parse.
const RECOVER_DELETED_CLASSES: &[&str] = &["prefetch"];

/// True when this class's deleted entries may be recovered.
fn class_recovers_deleted(class: &str) -> bool {
    RECOVER_DELETED_CLASSES.contains(&class)
}

/// Keep only listed files that classify into a wanted forensic class, carrying
/// each file's partition tag through to extraction.
///
/// Deleted entries are normally dropped. The one exception is a
/// [`RECOVER_DELETED_CLASSES`] class with **zero allocated files anywhere in the
/// listing** — the anti-forensic shape, where the lane would otherwise no-op
/// silently. Recovery is deliberately a fallback and not a general expansion:
/// when live files of that class exist the normal lane already reports on them,
/// and pulling hundreds of extra carved candidates would take the shared
/// extraction budget away from other classes for marginal gain. Recovered rows
/// are capped at [`MAX_RECOVERED_DELETED`] and labelled `recovered_deleted` so
/// the provenance travels with the artifact.
fn classify_candidates(
    listed: Vec<ListedFile>,
    wanted: &BTreeMap<&'static str, bool>,
) -> Vec<ArtifactCandidate> {
    let allocated_classes: BTreeSet<&'static str> = listed
        .iter()
        .filter(|row| row.allocated)
        .filter_map(|row| classify_artifact_path(&row.rel_path))
        .collect();
    let mut recovered = 0usize;
    let mut out = Vec::new();
    for row in listed {
        let Some(class) = classify_artifact_path(&row.rel_path) else {
            continue;
        };
        if !wanted.get(class).copied().unwrap_or(false) {
            continue;
        }
        if !row.allocated {
            if !class_recovers_deleted(class)
                || allocated_classes.contains(class)
                || recovered >= MAX_RECOVERED_DELETED
            {
                continue;
            }
            recovered += 1;
        }
        out.push(ArtifactCandidate {
            class,
            inode: row.inode,
            rel_path: row.rel_path,
            sector_offset: row.sector_offset,
            partition_rank: row.partition_rank,
            recovered_deleted: !row.allocated,
        });
    }
    out
}

/// Report a Prefetch directory that exists in the listing but yields ZERO
/// allocated files — the SDelete/anti-forensics shape. Pure so the message is
/// unit-testable. Returning None (intact or absent directory) keeps a normal
/// host's output free of noise.
fn prefetch_wipe_limitation(listed: &[ListedFile], recovered: usize) -> Option<String> {
    let (mut total, mut allocated) = (0usize, 0usize);
    for row in listed {
        if classify_artifact_path(&row.rel_path) == Some("prefetch") {
            total += 1;
            if row.allocated {
                allocated += 1;
            }
        }
    }
    if total == 0 || allocated > 0 {
        return None;
    }
    Some(format!(
        "Windows Prefetch directory holds {total} entries and ZERO are allocated — every .pf file \
         is deleted, which is what secure-deletion / anti-forensic wiping (e.g. SDelete) looks \
         like. {recovered} entry/entries were recovered from still-resident MFT records and \
         carry a valid prefetch signature; the remainder could not be recovered. Execution \
         history from Prefetch is INCOMPLETE for this host — absence of a program here is not \
         evidence it never ran."
    ))
}

/// Minimum content signature a *recovered* (deleted) artifact must carry before
/// it is kept. Only recovered rows are checked: an allocated file that fails a
/// signature test is a real artifact worth surfacing (truncated, corrupt), while
/// a carved blob that fails is almost always a cluster the filesystem has since
/// reallocated to something else. Classes with no signature defined pass.
///
/// Prefetch: Win8/10 files are MAM-compressed (`MAM\x04`); Win XP/Vista/7 files
/// are uncompressed with `SCCA` at offset 4.
fn recovered_content_matches(class: &str, path: &Path) -> Result<bool, DiskError> {
    if class != "prefetch" {
        return Ok(true);
    }
    let head = read_head(path, 8)?;
    if head.len() < 8 {
        return Ok(false);
    }
    Ok(&head[0..4] == b"MAM\x04" || &head[4..8] == b"SCCA")
}

/// Read at most `n` leading bytes of a file (no whole-file buffering).
fn read_head(path: &Path, n: usize) -> Result<Vec<u8>, DiskError> {
    use std::io::Read as _;
    let mut file = fs::File::open(path).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut buf = vec![0u8; n];
    let read = file.read(&mut buf).map_err(|source| DiskError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    buf.truncate(read);
    Ok(buf)
}

/// Enumerate every regular file in the image via `fls -r -p`, returning one
/// [`FlsRow`] each (allocated and deleted-but-resident alike). Reads the image
/// directly (no mount).
fn tsk_list(image_path: &Path, sector_offset: Option<u64>) -> Result<Vec<FlsRow>, DiskError> {
    let bin = std::env::var("FINDEVIL_FLS_BIN").unwrap_or_else(|_| "fls".to_string());
    let mut command = Command::new(&bin);
    command.args(["-r", "-p"]);
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    command.arg(image_path);
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
/// `(placeholder_inode, relative_path)` pairs shaped exactly like [`tsk_list`]
/// so they flow through the same classifier + fair-share selector. The inode
/// slot is a placeholder — mock extraction copies by relative path, not inode.
fn mock_list(fs_root: &Path) -> Result<Vec<(String, String)>, DiskError> {
    let mut out = Vec::new();
    mock_walk(fs_root, fs_root, &mut out)?;
    Ok(out)
}

fn mock_walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) -> Result<(), DiskError> {
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
                out.push(("-".to_string(), rel.to_string_lossy().replace('\\', "/")));
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
    skipped_oversize: &mut usize,
) -> Result<(), DiskError> {
    let src = safe_join(fs_root, rel_path);
    let size = fs::metadata(&src)
        .map_err(|source| DiskError::Io {
            path: src.clone(),
            source,
        })?
        .len();
    if size > max_artifact_bytes {
        *skipped_oversize += 1;
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
    if !extracted_artifact_type_matches(class, &dest)? {
        fs::remove_file(&dest).map_err(|source| DiskError::Io { path: dest, source })?;
        return Ok(());
    }
    out.push(ExtractedDiskArtifact {
        artifact_class: class.to_string(),
        source_path: PathBuf::from(rel_path),
        extracted_path: dest,
        size_bytes: size,
        recovered_deleted: false,
    });
    Ok(())
}

/// Parse one `fls -p` line into an [`FlsRow`]. Lines look like
/// `r/r 380861-128-4:\tWindows/System32/config/SYSTEM`, and a deleted entry
/// carries a `*` marker: `-/r * 32749-128-4:\tWindows/Prefetch/X.pf`.
///
/// The type field is `<name-type>/<metadata-type>`. For a *deleted* entry the
/// directory-entry side is frequently gone (`-/r`) while the MFT metadata still
/// says "regular file" — on a wiped Prefetch directory that is the majority
/// shape, so accepting only `r/r` would still miss most of it. A deleted row is
/// therefore kept when EITHER side says `r`; the caller decides which classes
/// are worth recovering.
///
/// Returns None for directories, non-files, and `r/-`-style rows whose metadata
/// is gone (inode 0) — those have no data runs left to `icat`.
fn parse_fls_line(line: &str) -> Option<FlsRow> {
    let (kind, rest) = line.split_once(char::is_whitespace)?;
    let (name_type, meta_type) = kind.split_once('/')?;
    if name_type != "r" && meta_type != "r" {
        return None;
    }
    let rest = rest.trim_start();
    let (allocated, rest) = rest
        .strip_prefix('*')
        .map_or((true, rest), |after| (false, after.trim_start()));
    let (inode, path) = rest.split_once(':')?;
    let inode = inode.trim();
    let path = path.trim();
    if inode.is_empty() || path.is_empty() {
        return None;
    }
    // TSK prints a BARE `0` when the metadata record itself is unavailable;
    // there is nothing to extract from it and `icat 0` would just fail.
    //
    // Compare the WHOLE address, never just its leading entry number: NTFS
    // numbers the Master File Table's own record zero, so `$MFT` legitimately
    // addresses `0-128-<id>` on every NTFS volume. Keying on the entry number
    // silently dropped `$MFT` from every image listing (REG-2) — the highest
    // priority artifact class on the disk, and the one the MFT timeline lane
    // is built on.
    if inode == "0" {
        return None;
    }
    Some(FlsRow {
        inode: inode.to_string(),
        rel_path: path.to_string(),
        allocated,
    })
}

/// One extraction candidate: a classified file inside a specific filesystem
/// partition of the image. `sector_offset` is the `fls`/`icat -o` value that
/// reaches that partition (None = bare volume image or mock walk);
/// `partition_rank` is the partition's preference order (0 = the preferred,
/// largest volume) and breaks within-class ties so the OS volume's copy of a
/// path beats a boot partition's copy to the extraction budget.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactCandidate {
    class: &'static str,
    inode: String,
    rel_path: String,
    sector_offset: Option<u64>,
    partition_rank: usize,
    /// Carved from a deleted directory entry whose MFT record was still
    /// resident. Gates the extra content-signature check and travels onto the
    /// emitted [`ExtractedDiskArtifact`].
    recovered_deleted: bool,
}

/// The artifact classes an investigation is actually built on: every typed,
/// parser-backed class. [`select_artifacts`] allocates the extraction budget to
/// these FIRST, and anything not named here draws only from what they leave.
///
/// This is a property, not a preference. A flat round-robin gives every class
/// an equal turn, so the untyped content sweep drew as much budget as `$MFT`
/// (measured: `yara_target` took 225 of alihadi-01-webserver's 411 extracted
/// artifacts and 152 of m57-jean's 500), and each newly wired lane shrank every
/// existing class's share on any image whose candidates outrun the budget.
///
/// Listing a class here is the deliberate, reviewed act that lets it share the
/// core budget — and that re-divides the share of everything already in it, so
/// the goldens need re-running. A lane added WITHOUT touching this list lands in
/// the supplementary tier, where it provably cannot shrink what the existing
/// lanes extract.
const CORE_ARTIFACT_CLASSES: &[&str] = &[
    "mft",
    "usnjrnl",
    "prefetch",
    "registry",
    "reg_txlog",
    "evtx",
    "legacy_evt",
    "amcache",
    "srum",
    "lnk",
    "jumplist",
    "scheduled_task",
    "recyclebin",
    "browser_db",
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
    "web_log",
    "webroot_script",
    "mail_store",
];

/// Budget tier: 0 for a [`CORE_ARTIFACT_CLASSES`] member, 1 for everything else
/// (today only the generic `yara_target` sweep, plus any future lane whose
/// author has not claimed core budget for it). [`select_artifacts`] drains the
/// tiers in order; classes *within* a tier share that tier round-robin, so no
/// class starves its neighbours.
fn class_tier(class: &str) -> u8 {
    u8::from(!CORE_ARTIFACT_CLASSES.contains(&class))
}

/// Extract order *within a tier*: forensically critical classes first, broad
/// yara targets last, so the `limit` never crowds out registry/MFT/prefetch.
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
        // Web tier: a small, high-signal set (a handful of request logs; the
        // web root's scripts) that must not be crowded out by the generic sweep.
        "web_log" => 25,
        "webroot_script" => 26,
        // Local mail stores (Outlook .pst/.ost, Outlook Express .dbx).
        "mail_store" => 27,
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
    match class {
        "evtx" => evtx_subrank(rel_path),
        "webroot_script" => webroot_script_subrank(rel_path),
        _ => 0,
    }
}

/// Draw order within `webroot_script`. A web root holds hundreds of shipped
/// application scripts and only a handful of files the web server itself can
/// write; a dropped shell lands in the writable ones. Tier 0 = a script in an
/// upload/temp/cache directory (attacker-writable by design); tier 1 = a script
/// sitting directly at the document root (also unusual for a packaged app);
/// tier 2 = the shipped application tree.
fn webroot_script_subrank(rel_path: &str) -> u8 {
    let lower = rel_path.replace('\\', "/").to_ascii_lowercase();
    let dir = lower.rsplit_once('/').map_or("", |(d, _)| d);
    if [
        "upload",
        "uploads",
        "tmp",
        "temp",
        "cache",
        "files",
        "images",
        "img",
        "media",
        "avatars",
        "attachments",
        "data",
    ]
    .iter()
    .any(|w| dir.ends_with(&format!("/{w}")) || dir == *w)
    {
        return 0;
    }
    if ["htdocs", "wwwroot", "public_html", "www", "webroot"]
        .iter()
        .any(|root| dir.ends_with(root))
    {
        return 1;
    }
    2
}

fn evtx_subrank(rel_path: &str) -> u8 {
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

/// Choose up to `limit` artifacts to extract.
///
/// Two rules, in this order:
///
/// 1. **Tier before share.** [`CORE_ARTIFACT_CLASSES`] are allocated first;
///    everything else divides only what they leave. Without this, wiring a new
///    lane into the default sweep silently shrank every existing class's share
///    on any image whose candidates outrun the budget, and the untyped
///    `yara_target` sweep drew as much budget as `$MFT` despite
///    [`class_priority`] documenting it as last.
/// 2. **Round-robin within a tier**, so no single voluminous class starves its
///    neighbours: classes are visited in [`class_priority`] order, every class
///    with candidates gets a turn each pass, and a class that drains early
///    hands its unused budget to the rest of its tier.
///
/// Within a class, [`artifact_subrank`], then partition preference (the OS
/// volume ahead of boot/recovery partitions), then path order decides which
/// artifacts win the class's share. Pure (no I/O) so the allocation is
/// unit-testable.
fn select_artifacts(candidates: Vec<ArtifactCandidate>, limit: usize) -> Vec<ArtifactCandidate> {
    let mut buckets: BTreeMap<(u8, u8), Vec<ArtifactCandidate>> = BTreeMap::new();
    for candidate in candidates {
        buckets
            .entry((class_tier(candidate.class), class_priority(candidate.class)))
            .or_default()
            .push(candidate);
    }

    // A BTreeMap keyed on (tier, priority) iterates tier-major, so consecutive
    // entries sharing a tier are exactly that tier's round-robin group.
    let mut tiers: Vec<Vec<VecDeque<ArtifactCandidate>>> = Vec::new();
    let mut current_tier: Option<u8> = None;
    for ((tier, _), mut bucket) in buckets {
        bucket.sort_by(|a, b| {
            artifact_subrank(a.class, &a.rel_path)
                .cmp(&artifact_subrank(b.class, &b.rel_path))
                .then_with(|| a.partition_rank.cmp(&b.partition_rank))
                .then_with(|| a.rel_path.cmp(&b.rel_path))
        });
        if current_tier != Some(tier) {
            tiers.push(Vec::new());
            current_tier = Some(tier);
        }
        tiers
            .last_mut()
            .expect("a tier group is pushed before its first queue")
            .push(VecDeque::from(bucket));
    }

    let mut selected = Vec::new();
    for queues in &mut tiers {
        while selected.len() < limit && queues.iter().any(|queue| !queue.is_empty()) {
            for queue in queues.iter_mut() {
                if selected.len() >= limit {
                    break;
                }
                if let Some(item) = queue.pop_front() {
                    selected.push(item);
                }
            }
        }
        if selected.len() >= limit {
            break;
        }
    }
    selected
}

/// Fairly order every candidate so extraction can backfill rejected entries
/// until the accepted-artifact limit is reached.
fn order_artifacts(candidates: Vec<ArtifactCandidate>) -> Vec<ArtifactCandidate> {
    let candidate_count = candidates.len();
    select_artifacts(candidates, candidate_count)
}

/// Destination directory for one candidate: `output_dir/<class>` for the
/// preferred partition (rank 0) — the flat layout extraction has always
/// produced — and `output_dir/<class>/vol<sector_offset>` for every further
/// partition, so two filesystems carrying the same path (every NTFS volume
/// has a `$MFT`) can never silently overwrite each other's extraction.
fn candidate_dest_dir(output_dir: &Path, candidate: &ArtifactCandidate) -> PathBuf {
    let class_dir = output_dir.join(candidate.class);
    match (candidate.partition_rank, candidate.sector_offset) {
        (0, _) | (_, None) => class_dir,
        (_, Some(offset)) => class_dir.join(format!("vol{offset}")),
    }
}

/// `icat` one inode out of its partition into
/// `output_dir/<class>[/vol<offset>]/<rel_path>` (see [`candidate_dest_dir`]),
/// streaming to disk (no in-memory buffering) and enforcing the size cap.
/// A failed `icat` (unreadable inode) is skipped, not fatal.
fn tsk_extract(
    image_path: &Path,
    candidate: &ArtifactCandidate,
    output_dir: &Path,
    max_artifact_bytes: u64,
    out: &mut Vec<ExtractedDiskArtifact>,
    skipped_oversize: &mut usize,
) -> Result<(), DiskError> {
    let dest = safe_join(
        &candidate_dest_dir(output_dir, candidate),
        &candidate.rel_path,
    );
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    let bin = std::env::var("FINDEVIL_ICAT_BIN").unwrap_or_else(|_| "icat".to_string());
    let mut command = Command::new(&bin);
    if let Some(offset) = candidate.sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    command.arg(image_path).arg(&candidate.inode);
    let file = fs::File::create(&dest).map_err(|source| DiskError::Io {
        path: dest.clone(),
        source,
    })?;
    let status = command
        .stdout(file)
        .status()
        .map_err(|source| DiskError::Io {
            path: PathBuf::from(&bin),
            source,
        })?;
    if !status.success() {
        let _ = fs::remove_file(&dest);
        return Ok(());
    }
    let size = fs::metadata(&dest)
        .map_err(|source| DiskError::Io {
            path: dest.clone(),
            source,
        })?
        .len();
    if size > max_artifact_bytes {
        let _ = fs::remove_file(&dest);
        *skipped_oversize += 1;
        return Ok(());
    }
    if !extracted_artifact_type_matches(candidate.class, &dest)? {
        fs::remove_file(&dest).map_err(|source| DiskError::Io { path: dest, source })?;
        return Ok(());
    }
    // A carved blob whose signature is wrong is a reallocated cluster, not the
    // artifact the deleted name promised. Drop it rather than hand a downstream
    // parser bytes that belong to something else.
    if candidate.recovered_deleted && !recovered_content_matches(candidate.class, &dest)? {
        fs::remove_file(&dest).map_err(|source| DiskError::Io { path: dest, source })?;
        return Ok(());
    }
    out.push(ExtractedDiskArtifact {
        artifact_class: candidate.class.to_string(),
        source_path: PathBuf::from(&candidate.rel_path),
        extracted_path: dest,
        size_bytes: size,
        recovered_deleted: candidate.recovered_deleted,
    });
    Ok(())
}

/// Confirm filename-classified artifacts have the minimum format signature
/// required by their downstream parser. Browser databases are the only
/// filename-collision-prone class today (`History` is also used by shells).
fn extracted_artifact_type_matches(class: &str, path: &Path) -> Result<bool, DiskError> {
    if class != "browser_db" {
        return Ok(true);
    }
    super::browser_history::inspect_sqlite_header(path)
        .map(|header| matches!(header, super::browser_history::SqliteHeader::Valid))
        .map_err(|source| DiskError::Io {
            path: path.to_path_buf(),
            source,
        })
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
        .or_else(|| classify_web_tier(name, &rel))
        .or_else(|| classify_linux(name, &rel))
        .or_else(|| classify_macos(name, &rel))
        .or_else(|| classify_windows_generic(&rel))
}

/// Web-tier classes. OS-agnostic on purpose: Apache ships inside XAMPP on
/// Windows, IIS writes W3C logs under `inetpub`, and the same stack on Linux
/// puts logs under `/var/log`. Tried before the Linux and generic sweeps so
/// `var/log/apache2/access.log` reaches the request-log parser instead of the
/// untyped `linux_log` bucket, and a webroot under `users/` reaches the
/// webshell heuristic instead of the generic yara sweep.
fn classify_web_tier(name: &str, rel: &str) -> Option<&'static str> {
    if is_web_request_log(name, rel) {
        Some("web_log")
    } else if is_webroot_script(name, rel) {
        Some("webroot_script")
    } else {
        None
    }
}

/// A web server's request/error log. Matched on the server's *log directory*
/// plus the canonical filename, so a `.pid` or an installer log sitting in the
/// same directory is not mistaken for request traffic.
fn is_web_request_log(name: &str, rel: &str) -> bool {
    let in_server_log_dir = [
        "/apache/logs/",
        "/apache2/",
        "/httpd/",
        "/nginx/",
        "/lighttpd/",
        "/logs/w3svc",
    ]
    .iter()
    .any(|dir| rel.contains(dir))
        || rel.starts_with("apache/logs/")
        || rel.contains("inetpub/logs/");
    let canonical_name = matches!(
        name,
        "access.log"
            | "access_log"
            | "error.log"
            | "error_log"
            | "ssl_access.log"
            | "ssl_request.log"
            | "other_vhosts_access.log"
    ) || (name.starts_with("access.log.") || name.starts_with("access_log."))
        || (name.starts_with("u_ex") && has_extension(name, "log"));
    // `*.access` (per-vhost nginx/lighttpd naming) is self-describing.
    (in_server_log_dir && canonical_name) || has_extension(name, "access")
}

/// A server-side script living in a web root — the place a webshell lands.
/// Requires BOTH a document-root marker in the path and an executable
/// server-script extension: static content is not a script, and a build script
/// outside a web root is not web-reachable.
fn is_webroot_script(name: &str, rel: &str) -> bool {
    let in_web_root = [
        "htdocs/",
        "wwwroot/",
        "inetpub/",
        "public_html/",
        "www/",
        "webapps/",
        "web-root/",
        "webroot/",
    ]
    .iter()
    .any(|root| rel.starts_with(root) || rel.contains(&format!("/{root}")));
    in_web_root
        && [
            "php", "php3", "php4", "php5", "php7", "phps", "phtml", "asp", "aspx", "ashx", "asmx",
            "jsp", "jspx", "jspf", "cfm", "cgi",
        ]
        .iter()
        .any(|ext| has_extension(name, ext))
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
    } else if name == "thumbs.db" || name.ends_with(".thumbcache") {
        Some("thumbnail")
    } else if has_extension(name, "pst") || has_extension(name, "ost") || has_extension(name, "dbx")
    {
        // Local mail stores: Outlook personal folders (.pst) / offline store
        // (.ost) and the legacy Outlook Express folder format (.dbx). Carving
        // them is what lets the mail lane run without a mounted filesystem —
        // the TSK extractor works rootless, a loopback mount does not.
        Some("mail_store")
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
/// OS classes always win over the `users/`/`programdata/` directory match.
fn classify_windows_generic(rel: &str) -> Option<&'static str> {
    if rel.starts_with("users/")
        || rel.contains("/users/")
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
            "web_log",
            "webroot_script",
            "mail_store",
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
                ArtifactKind::WebLog => "web_log",
                ArtifactKind::WebrootScript => "webroot_script",
                ArtifactKind::MailStore => "mail_store",
            })
            .collect()
    };
    for class in classes {
        wanted.insert(class, true);
    }
    wanted
}

fn case_dir(case_id: &str) -> Result<PathBuf, DiskError> {
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
        artifact_subrank, candidate_dest_dir, class_priority, classify_artifact_path,
        classify_candidates, mock_list, order_partitions_by_preference, parse_fls_line,
        parse_mmls_filesystem_partitions, partition_byte_offsets, prefetch_wipe_limitation,
        recovered_content_matches, safe_join, select_artifacts, unmount_steps, wanted_kinds,
        ArtifactCandidate, ArtifactKind, ListedFile, MmlsPartition, CORE_ARTIFACT_CLASSES,
        MAX_RECOVERED_DELETED,
    };
    use std::collections::BTreeMap;
    use std::path::Path;

    /// Single-partition candidate shorthand for the fair-share tests.
    fn cand(class: &'static str, inode: &str, rel_path: &str) -> ArtifactCandidate {
        ArtifactCandidate {
            class,
            inode: inode.to_string(),
            rel_path: rel_path.to_string(),
            sector_offset: None,
            partition_rank: 0,
            recovered_deleted: false,
        }
    }

    /// One `fls` row as [`list_image_files`] would hand it to the classifier.
    fn listed_row(inode: &str, rel_path: &str, allocated: bool) -> ListedFile {
        ListedFile {
            partition_rank: 0,
            sector_offset: None,
            inode: inode.to_string(),
            rel_path: rel_path.to_string(),
            allocated,
        }
    }

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
        listed.sort();
        let paths: Vec<&str> = listed.iter().map(|(_, p)| p.as_str()).collect();
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
            .filter_map(|(_, p)| classify_artifact_path(p))
            .collect();
        assert!(classes.contains("mft"));
        assert!(classes.contains("prefetch"));
        assert!(classes.contains("registry"));
    }

    #[test]
    fn parse_fls_line_extracts_inode_and_path_for_live_files() {
        let row = parse_fls_line("r/r 380861-128-4:\tWindows/System32/config/SYSTEM")
            .expect("live file parses");
        assert_eq!(row.inode, "380861-128-4");
        assert_eq!(row.rel_path, "Windows/System32/config/SYSTEM");
        assert!(row.allocated, "an unmarked fls row is an allocated file");
    }

    #[test]
    fn parse_fls_line_keeps_deleted_entries_that_still_carry_an_inode() {
        // `*` marks a deleted name. When the MFT record is still resident the
        // inode is real and `icat` recovers the data runs — the only way to read
        // a Prefetch directory an attacker wiped.
        let row = parse_fls_line("r/r * 84023-128-4:\tWindows/Prefetch/CSRSS.EXE-8C04D631.pf")
            .expect("deleted-but-resident entry parses");
        assert_eq!(row.inode, "84023-128-4");
        assert_eq!(row.rel_path, "Windows/Prefetch/CSRSS.EXE-8C04D631.pf");
        assert!(!row.allocated);

        // TSK prints `-/r` when the directory-entry type is gone but the MFT
        // metadata still says "regular file". On a wiped Prefetch directory that
        // is the majority shape, so keying only on `r/r` still misses most of it.
        let row = parse_fls_line("-/r * 32749-128-4:\tWindows/Prefetch/SDELETE.EXE-257E3D6D.pf")
            .expect("deleted entry with metadata-only type parses");
        assert_eq!(row.inode, "32749-128-4");
        assert!(!row.allocated);
    }

    #[test]
    fn parse_fls_line_skips_dirs_unrecoverable_deletes_and_blanks() {
        assert_eq!(parse_fls_line("d/d 282867-144-5:\tUsers"), None);
        // `r/-` + inode 0: the MFT record is gone, there is nothing to icat.
        assert_eq!(
            parse_fls_line("r/- * 0:\tWindows/Prefetch/SMSS.EXE-1DCD0EB1.pf"),
            None
        );
        assert_eq!(parse_fls_line(""), None);
    }

    #[test]
    fn parse_fls_line_keeps_the_master_file_table_at_ntfs_entry_zero() {
        // REG-2. NTFS numbers the Master File Table's OWN record zero, so on
        // every NTFS volume `$MFT` addresses `0-128-<id>`. Verbatim row from
        // `fls -p -r -o 63` over the nist-hacking-case image (SCHARDT.001):
        //
        //     r/r 0-128-7:	$MFT
        //
        // Rejecting an address because its *entry number* is 0 therefore
        // discards the single highest-priority artifact class on the disk.
        // The unrecoverable rows TSK really does mark are printed as a BARE
        // `0` with no attribute address (see the test above) - that, and only
        // that, is what the guard may key on.
        let row = parse_fls_line("r/r 0-128-7:\t$MFT").expect("$MFT parses");
        assert_eq!(row.inode, "0-128-7");
        assert_eq!(row.rel_path, "$MFT");
        assert!(row.allocated, "$MFT is an allocated system file");
        assert_eq!(classify_artifact_path(&row.rel_path), Some("mft"));
    }

    #[test]
    fn an_ntfs_listing_still_yields_an_mft_extraction_candidate() {
        // The same regression one layer up. With no `mft` artifact extracted
        // the mft_timeline lane never runs, and on nist-hacking-case that is
        // the evidence the "hacking tools in Program Files" finding (nhc-004)
        // stood on. Rows are the real shapes seen on SCHARDT.001.
        let listed: Vec<ListedFile> = [
            "r/r 0-128-7:\t$MFT",
            "r/r 1-128-1:\t$MFTMirr",
            "r/r 380861-128-4:\tWINDOWS/system32/config/SYSTEM",
            "r/- * 0:\tDocuments and Settings/Default User/MPC7A4.tmp",
        ]
        .iter()
        .filter_map(|line| parse_fls_line(line))
        .map(|row| ListedFile {
            partition_rank: 0,
            sector_offset: None,
            inode: row.inode,
            rel_path: row.rel_path,
            allocated: row.allocated,
        })
        .collect();
        let candidates = classify_candidates(listed, &wanted_kinds(&[]));
        assert!(
            candidates.iter().any(|c| c.class == "mft"),
            "an NTFS listing must yield an mft candidate, got {:?}",
            candidates.iter().map(|c| c.class).collect::<Vec<_>>()
        );
    }

    #[test]
    fn classify_candidates_recovers_deleted_prefetch_when_none_are_allocated() {
        // A wiped Prefetch directory: every .pf deleted. Recovery is the only
        // way the lane sees any execution history at all.
        let listed = vec![
            listed_row("100", "$MFT", true),
            listed_row("101", "Windows/Prefetch/SDELETE.EXE-1.pf", false),
            listed_row("102", "Windows/Prefetch/CSRSS.EXE-2.pf", false),
        ];
        let wanted = wanted_kinds(&[]);
        let candidates = classify_candidates(listed, &wanted);
        let recovered: Vec<&ArtifactCandidate> = candidates
            .iter()
            .filter(|c| c.class == "prefetch")
            .collect();
        assert_eq!(recovered.len(), 2, "both wiped .pf entries recovered");
        assert!(
            recovered.iter().all(|c| c.recovered_deleted),
            "recovered rows must be labelled recovered-deleted"
        );
        assert!(candidates
            .iter()
            .any(|c| c.class == "mft" && !c.recovered_deleted));
    }

    #[test]
    fn classify_candidates_leaves_deleted_prefetch_alone_when_allocated_ones_exist() {
        // Recovery is a targeted fallback for a wiped directory, not a general
        // budget expansion: when live .pf files exist the normal lane already
        // reports execution history and the extraction budget stays where it is.
        let listed = vec![
            listed_row("101", "Windows/Prefetch/CMD.EXE-1.pf", true),
            listed_row("102", "Windows/Prefetch/SDELETE.EXE-2.pf", false),
        ];
        let wanted = wanted_kinds(&[]);
        let candidates = classify_candidates(listed, &wanted);
        let prefetch: Vec<&ArtifactCandidate> = candidates
            .iter()
            .filter(|c| c.class == "prefetch")
            .collect();
        assert_eq!(prefetch.len(), 1);
        assert!(!prefetch[0].recovered_deleted);
    }

    #[test]
    fn classify_candidates_never_recovers_deleted_non_prefetch_classes() {
        // Only prefetch is recovered. A deleted hive or event log is far more
        // likely to be an unrecoverable partial than a resident 4 KB .pf, and
        // carving them silently would inflate the ledger with garbage.
        let listed = vec![
            listed_row("201", "Windows/System32/config/SOFTWARE", false),
            listed_row("202", "Windows/System32/winevt/Logs/Security.evtx", false),
        ];
        let wanted = wanted_kinds(&[]);
        assert!(classify_candidates(listed, &wanted).is_empty());
    }

    #[test]
    fn classify_candidates_caps_recovered_deleted_prefetch() {
        let listed: Vec<ListedFile> = (0..(MAX_RECOVERED_DELETED + 50))
            .map(|i| listed_row(&format!("{i}"), &format!("Windows/Prefetch/A{i}.pf"), false))
            .collect();
        let wanted = wanted_kinds(&[]);
        assert_eq!(
            classify_candidates(listed, &wanted).len(),
            MAX_RECOVERED_DELETED
        );
    }

    #[test]
    fn wiped_prefetch_directory_becomes_an_analysis_limitation() {
        // The silent-gap bug: a Prefetch directory holding only deleted entries
        // used to report artifact_counts.prefetch = 0 with NO limitation, so a
        // reader could not tell "no prefetch on this host" from "every prefetch
        // file was wiped".
        let listed = vec![
            listed_row("100", "$MFT", true),
            listed_row("101", "Windows/Prefetch/SDELETE.EXE-1.pf", false),
            listed_row("102", "Windows/Prefetch/CSRSS.EXE-2.pf", false),
        ];
        let limitation = prefetch_wipe_limitation(&listed, 2).expect("limitation emitted");
        assert!(limitation.contains("Prefetch"), "{limitation}");
        assert!(limitation.contains('2'), "{limitation}");
        assert!(
            limitation.to_ascii_lowercase().contains("deleted"),
            "{limitation}"
        );
    }

    #[test]
    fn intact_or_absent_prefetch_directory_emits_no_limitation() {
        let intact = vec![listed_row("101", "Windows/Prefetch/CMD.EXE-1.pf", true)];
        assert_eq!(prefetch_wipe_limitation(&intact, 0), None);
        let no_prefetch = vec![listed_row("100", "$MFT", true)];
        assert_eq!(prefetch_wipe_limitation(&no_prefetch, 0), None);
    }

    #[test]
    fn recovered_prefetch_content_requires_a_prefetch_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Win10 compressed prefetch.
        let mam = dir.path().join("mam.pf");
        std::fs::write(&mam, b"MAM\x04\x7a\x88\x00\x00rest").unwrap();
        assert!(recovered_content_matches("prefetch", &mam).unwrap());
        // Win7/XP uncompressed prefetch: "SCCA" at offset 4.
        let scca = dir.path().join("scca.pf");
        std::fs::write(&scca, b"\x17\x00\x00\x00SCCArest").unwrap();
        assert!(recovered_content_matches("prefetch", &scca).unwrap());
        // A reused cluster: the inode now belongs to something else.
        let junk = dir.path().join("junk.pf");
        std::fs::write(&junk, b"\x00\x00\x00\x00\x00\x00\x00\x00").unwrap();
        assert!(!recovered_content_matches("prefetch", &junk).unwrap());
        // Classes with no recovery signature pass through.
        assert!(recovered_content_matches("registry", &junk).unwrap());
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
            classify_artifact_path("Documents and Settings/Suspect User/My Documents/Thumbs.db"),
            Some("thumbnail")
        );
        assert_eq!(
            classify_artifact_path(
                "Users/bob/AppData/Local/Microsoft/Windows/Explorer/thumbcache_256.thumbcache"
            ),
            Some("thumbnail")
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

    /// Env-gated selection check against a REAL image listing.
    /// `WEB_TIER_FLS_LISTING=/path/to/fls-output cargo test -p findevil-mcp
    /// --lib selection_over_a_real_image_listing -- --nocapture`
    #[test]
    fn selection_over_a_real_image_listing_keeps_the_web_tier() {
        let Ok(listing) = std::env::var("WEB_TIER_FLS_LISTING") else {
            return;
        };
        let text = std::fs::read_to_string(&listing).expect("listing readable");
        let mut candidates: Vec<ArtifactCandidate> = Vec::new();
        for line in text.lines() {
            let Some(row) = parse_fls_line(line) else {
                continue;
            };
            if let Some(class) = classify_artifact_path(&row.rel_path) {
                candidates.push(cand(class, &row.inode, &row.rel_path));
            }
        }
        let mut by_class: BTreeMap<&str, usize> = BTreeMap::new();
        for c in &candidates {
            *by_class.entry(c.class).or_insert(0) += 1;
        }
        println!("candidates by class: {by_class:?}");
        let selected = select_artifacts(candidates, 500);
        let mut sel_by_class: BTreeMap<&str, usize> = BTreeMap::new();
        for s in &selected {
            *sel_by_class.entry(s.class).or_insert(0) += 1;
        }
        println!("selected {} of 500: {sel_by_class:?}", selected.len());
        for want in [
            "xampp/apache/logs/access.log",
            "xampp/htdocs/DVWA/hackable/uploads/phpshell.php",
            "xampp/htdocs/DVWA/hackable/uploads/phpshell2.php",
        ] {
            let hit = selected.iter().any(|c| c.rel_path == want);
            println!("  selected {want}: {hit}");
            assert!(hit, "budget dropped {want}");
        }
    }

    /// Opt-in check against a REAL `fls -p -r` listing, run as
    /// `MFT_FLS_LISTING=<file> cargo test`. Skipped (silently passing) without
    /// the env var, so it is a developer receipt rather than CI coverage — the
    /// `parse_fls_line_keeps_the_master_file_table_at_ntfs_entry_zero` unit test
    /// is what actually guards the regression on every run.
    #[test]
    fn selection_over_a_real_image_listing_keeps_the_master_file_table() {
        let Ok(listing) = std::env::var("MFT_FLS_LISTING") else {
            return;
        };
        let text = std::fs::read_to_string(&listing).expect("listing readable");
        let mut candidates: Vec<ArtifactCandidate> = Vec::new();
        let (mut rows, mut dropped) = (0usize, 0usize);
        for line in text.lines() {
            rows += 1;
            let Some(row) = parse_fls_line(line) else {
                dropped += 1;
                continue;
            };
            if let Some(class) = classify_artifact_path(&row.rel_path) {
                if row.allocated {
                    candidates.push(cand(class, &row.inode, &row.rel_path));
                }
            }
        }
        let selected = select_artifacts(candidates, 500);
        let by_class = counts_by_class(&selected);
        println!("{rows} fls rows, {dropped} unparsed; selected {by_class:?}");
        assert_eq!(
            by_class.get("mft").copied().unwrap_or(0),
            1,
            "the NTFS Master File Table must reach the extraction budget"
        );
        assert!(selected.iter().any(|c| c.rel_path == "$MFT"));
    }

    #[test]
    fn classify_artifact_path_matches_web_tier_classes() {
        // Web server request logs — the primary record of an exploitation
        // attempt against a public-facing app. Apache (incl. XAMPP on Windows),
        // Apache on Linux (no `.log` suffix), IIS W3C, and nginx.
        assert_eq!(
            classify_artifact_path("xampp/apache/logs/access.log"),
            Some("web_log")
        );
        assert_eq!(
            classify_artifact_path("xampp\\apache\\logs\\error.log"),
            Some("web_log")
        );
        assert_eq!(
            classify_artifact_path("var/log/apache2/access.log"),
            Some("web_log")
        );
        assert_eq!(
            classify_artifact_path("var/log/httpd/access_log"),
            Some("web_log")
        );
        assert_eq!(
            classify_artifact_path("inetpub/logs/LogFiles/W3SVC1/u_ex150902.log"),
            Some("web_log")
        );
        assert_eq!(
            classify_artifact_path("var/log/nginx/site.access"),
            Some("web_log")
        );
        // Not every file under an apache logs dir is a request log.
        assert_eq!(classify_artifact_path("xampp/apache/logs/httpd.pid"), None);
        assert_eq!(
            classify_artifact_path("xampp/apache/logs/install.log"),
            None
        );

        // Server-side scripts living in a web root — where a webshell lands.
        assert_eq!(
            classify_artifact_path("xampp/htdocs/DVWA/hackable/uploads/phpshell.php"),
            Some("webroot_script")
        );
        assert_eq!(
            classify_artifact_path("inetpub/wwwroot/cmd.aspx"),
            Some("webroot_script")
        );
        assert_eq!(
            classify_artifact_path("var/www/html/index.php"),
            Some("webroot_script")
        );
        assert_eq!(
            classify_artifact_path("home/bob/public_html/shell.phtml"),
            Some("webroot_script")
        );
        assert_eq!(
            classify_artifact_path("opt/tomcat/webapps/ROOT/cmd.jsp"),
            Some("webroot_script")
        );
        // Static web content is not a script; a script outside a web root is
        // not a webroot script.
        assert_eq!(classify_artifact_path("xampp/htdocs/index.html"), None);
        assert_eq!(classify_artifact_path("tools/build.php"), None);
    }

    #[test]
    fn web_tier_classes_win_over_generic_and_linux_sweeps() {
        // A webroot under a user's home must classify as webroot_script, not the
        // generic `users/` yara sweep, or the webshell heuristic never sees it.
        assert_eq!(
            classify_artifact_path("Users/web/public_html/shell.php"),
            Some("webroot_script")
        );
        // Apache logs under /var/log must classify as web_log, not linux_log —
        // linux_log has no request parser.
        assert_eq!(
            classify_artifact_path("var/log/apache2/access.log"),
            Some("web_log")
        );
        // A non-web file under /var/log still classifies as linux_log.
        assert_eq!(
            classify_artifact_path("var/log/auth.log"),
            Some("linux_log")
        );
    }

    #[test]
    fn webroot_script_subrank_puts_writable_dirs_before_shipped_app_tree() {
        // A web root holds hundreds of shipped application scripts; the ones an
        // attacker can write sit in upload/temp/cache dirs. The fair-share
        // budget per class is small, so those must be drawn first.
        let uploads = "xampp/htdocs/DVWA/hackable/uploads/phpshell.php";
        let shipped = "xampp/htdocs/dashboard/faq.php";
        assert!(
            artifact_subrank("webroot_script", uploads)
                < artifact_subrank("webroot_script", shipped)
        );
        assert!(
            artifact_subrank("webroot_script", "inetpub/wwwroot/upload/x.aspx")
                < artifact_subrank("webroot_script", "inetpub/wwwroot/app/views/list.aspx")
        );
        // Other classes keep a flat sub-rank.
        assert_eq!(
            artifact_subrank("registry", "Windows/System32/config/SAM"),
            0
        );
    }

    #[test]
    fn wanted_kinds_default_includes_web_tier_classes() {
        let wanted = wanted_kinds(&[]);
        for class in ["web_log", "webroot_script"] {
            assert!(wanted.contains_key(class), "default set missing {class}");
        }
        let explicit = wanted_kinds(&[ArtifactKind::WebLog, ArtifactKind::WebrootScript]);
        assert!(explicit.contains_key("web_log"));
        assert!(explicit.contains_key("webroot_script"));
    }

    #[test]
    fn class_priority_ranks_web_tier_before_generic_yara_sweep() {
        assert!(class_priority("web_log") < class_priority("yara_target"));
        assert!(class_priority("webroot_script") < class_priority("yara_target"));
    }

    #[test]
    fn classify_artifact_path_recognises_mail_stores() {
        // Outlook personal-folders / offline store and the legacy Outlook
        // Express folder format. Without a class of their own the mail store is
        // never carved, so the mail lane has nothing to parse on a rootless run.
        assert_eq!(
            classify_artifact_path(
                "Documents and Settings/Jean/Local Settings/Application Data/Microsoft/Outlook/outlook.pst"
            ),
            Some("mail_store")
        );
        assert_eq!(
            classify_artifact_path("Users/bob/AppData/Local/Microsoft/Outlook/bob@corp.com.ost"),
            Some("mail_store")
        );
        assert_eq!(
            classify_artifact_path(
                "Documents and Settings/Jean/Local Settings/Application Data/Identities/{GUID}/Microsoft/Outlook Express/Inbox.dbx"
            ),
            Some("mail_store")
        );
        // Case-insensitive: fls emits the on-disk casing verbatim.
        assert_eq!(
            classify_artifact_path("Users/bob/Documents/Outlook Files/ARCHIVE.PST"),
            Some("mail_store")
        );
        // A mail store outside any users/ tree still classifies (it must not
        // fall through to the generic yara sweep, which never matches here).
        assert_eq!(
            classify_artifact_path("data/mail/archive.pst"),
            Some("mail_store")
        );
    }

    #[test]
    fn wanted_kinds_default_includes_mail_store() {
        assert!(wanted_kinds(&[]).contains_key("mail_store"));
    }

    #[test]
    fn wanted_kinds_maps_explicit_mail_store_request() {
        let wanted = wanted_kinds(std::slice::from_ref(&super::ArtifactKind::MailStore));
        assert!(wanted.contains_key("mail_store"));
        assert_eq!(wanted.len(), 1);
    }

    #[test]
    fn class_priority_draws_mail_store_before_generic_yara_sweep() {
        // A mail store is a decoded high-value class: it must be drawn ahead of
        // the broad content sweep so the extraction budget cannot crowd it out.
        assert!(class_priority("mail_store") < class_priority("yara_target"));
        assert!(class_priority("mail_store") < class_priority("_unmapped_class_"));
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
        let mut candidates: Vec<ArtifactCandidate> = Vec::new();
        for i in 0..400 {
            candidates.push(cand(
                "prefetch",
                &format!("{i}"),
                &format!("Windows/Prefetch/A{i:04}.pf"),
            ));
        }
        for i in 0..600 {
            candidates.push(cand(
                "evtx",
                &format!("e{i}"),
                &format!(
                    "Windows/System32/winevt/Logs/Microsoft-Windows-Zzz{i:04}%4Operational.evtx"
                ),
            ));
        }
        candidates.push(cand(
            "evtx",
            "sec",
            "Windows/System32/winevt/Logs/Security.evtx",
        ));
        candidates.push(cand("mft", "mft", "$MFT"));

        let selected = select_artifacts(candidates, 50);
        assert_eq!(selected.len(), 50);
        let classes: std::collections::HashSet<&str> = selected.iter().map(|c| c.class).collect();
        assert!(classes.contains("prefetch"), "prefetch starved");
        assert!(classes.contains("evtx"), "evtx starved (the original bug)");
        assert!(classes.contains("mft"), "mft missing");
        assert!(
            selected
                .iter()
                .any(|c| c.rel_path.ends_with("/Security.evtx")),
            "canonical Security.evtx must win evtx's fair share"
        );
    }

    /// How many artifacts of each class a selection drew.
    fn counts_by_class(selected: &[ArtifactCandidate]) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for c in selected {
            *out.entry(c.class).or_insert(0) += 1;
        }
        out
    }

    /// A disk whose CORE classes alone already outrun any sane budget.
    fn saturated_core_disk() -> Vec<ArtifactCandidate> {
        let mut candidates = vec![cand("mft", "mft", "$MFT")];
        for i in 0..200 {
            candidates.push(cand(
                "prefetch",
                &format!("p{i}"),
                &format!("Windows/Prefetch/A{i:04}.pf"),
            ));
            candidates.push(cand(
                "lnk",
                &format!("l{i}"),
                &format!("Users/x/R/{i:04}.lnk"),
            ));
            candidates.push(cand(
                "registry",
                &format!("r{i}"),
                &format!("Users/u{i:04}/NTUSER.DAT"),
            ));
        }
        candidates
    }

    #[test]
    fn wiring_a_new_artifact_class_cannot_shrink_the_core_classes_share() {
        // The wave-2 shape, generalised: three new classes (web_log,
        // webroot_script, mail_store) were wired into the default sweep and the
        // flat round-robin handed each of them the same turn as `$MFT`, so
        // every existing class's share shrank on any image whose candidates
        // outrun the budget. Measured on the goldens at the time:
        // alihadi-01-webserver yara_target 225 -> 154, alihadi-07-sysinternals
        // lnk 96 -> 85 / reg_txlog 95 -> 84 / scheduled_task 95 -> 85.
        //
        // A lane added later must not be able to do that silently. A class the
        // author has NOT deliberately added to CORE_ARTIFACT_CLASSES draws only
        // from budget the core classes left behind, so its arrival cannot move
        // any core count downward.
        const LIMIT: usize = 100;
        let before = counts_by_class(&select_artifacts(saturated_core_disk(), LIMIT));

        let mut with_new_lane = saturated_core_disk();
        for i in 0..200 {
            // Not in CORE_ARTIFACT_CLASSES: exactly what "the next lane" looks
            // like before anyone decides it belongs in the core budget.
            with_new_lane.push(cand(
                "future_lane",
                &format!("f{i}"),
                &format!("Some/New/Evidence/{i:04}.dat"),
            ));
        }
        let after = counts_by_class(&select_artifacts(with_new_lane, LIMIT));

        assert!(!CORE_ARTIFACT_CLASSES.contains(&"future_lane"));
        for class in ["mft", "prefetch", "lnk", "registry"] {
            let (b, a) = (
                before.get(class).copied().unwrap_or(0),
                after.get(class).copied().unwrap_or(0),
            );
            assert!(
                a >= b,
                "adding a new class shrank core class {class}: {b} -> {a} \
                 (before {before:?}, after {after:?})"
            );
        }
        assert_eq!(
            after.get("future_lane").copied().unwrap_or(0),
            0,
            "a saturated core budget leaves the new lane nothing, by design"
        );
    }

    #[test]
    fn the_broad_content_sweep_draws_after_every_typed_class() {
        // `class_priority` has always documented the generic yara sweep as
        // "always last ... so the limit never crowds out registry/MFT/prefetch",
        // but the flat round-robin gave it an equal turn with `$MFT`. On
        // alihadi-01-webserver that spent 225 of 411 extracted artifacts on the
        // untyped sweep.
        const LIMIT: usize = 100;
        let mut candidates = saturated_core_disk();
        for i in 0..500 {
            candidates.push(cand(
                "yara_target",
                &format!("y{i}"),
                &format!("Users/x/Documents/{i:04}.txt"),
            ));
        }
        let selected = counts_by_class(&select_artifacts(candidates, LIMIT));
        assert_eq!(
            selected.get("yara_target").copied().unwrap_or(0),
            0,
            "typed classes had unmet demand, so the sweep gets nothing: {selected:?}"
        );
    }

    #[test]
    fn supplementary_classes_still_get_the_budget_the_core_leaves_behind() {
        // The other side of the tier rule: draining core first must not mean
        // starving a small later lane on a disk that has room for it. Core
        // demand here is 3; the rest of the budget is shared round-robin by the
        // supplementary classes, so a 2-file mail store is never crowded out by
        // a 400-file content sweep.
        let mut candidates = vec![
            cand("mft", "mft", "$MFT"),
            cand("registry", "sys", "WINDOWS/system32/config/SYSTEM"),
            cand("prefetch", "pf", "WINDOWS/Prefetch/CMD.EXE-1.pf"),
            cand("mail_store", "pst1", "Users/jean/Outlook.pst"),
            cand("mail_store", "pst2", "Users/jean/archive.pst"),
        ];
        for i in 0..400 {
            candidates.push(cand(
                "yara_target",
                &format!("y{i}"),
                &format!("Users/x/Documents/{i:04}.txt"),
            ));
        }
        let selected = counts_by_class(&select_artifacts(candidates, 50));
        assert_eq!(selected.get("mft").copied().unwrap_or(0), 1);
        assert_eq!(selected.get("mail_store").copied().unwrap_or(0), 2);
        // 5 core artifacts drawn, 45 of the budget's 50 left for the sweep.
        assert_eq!(selected.get("yara_target").copied().unwrap_or(0), 45);
    }

    #[test]
    fn select_artifacts_prefers_the_preferred_partition_copy_within_a_class() {
        // Every NTFS volume carries a `$MFT`. When both the boot partition and
        // the OS volume offer one, the preferred (rank 0 = largest) volume's
        // copy must be drawn first so a tight budget spends itself on the
        // volume that actually holds the evidence.
        let boot = ArtifactCandidate {
            class: "mft",
            inode: "100".to_string(),
            rel_path: "$MFT".to_string(),
            sector_offset: Some(2048),
            partition_rank: 1,
            recovered_deleted: false,
        };
        let os = ArtifactCandidate {
            class: "mft",
            inode: "200".to_string(),
            rel_path: "$MFT".to_string(),
            sector_offset: Some(206_848),
            partition_rank: 0,
            recovered_deleted: false,
        };
        let selected = select_artifacts(vec![boot.clone(), os.clone()], 1);
        assert_eq!(selected, vec![os.clone()]);
        // Order of arrival must not matter.
        let selected = select_artifacts(vec![os.clone(), boot], 1);
        assert_eq!(selected, vec![os]);
    }

    #[test]
    fn select_artifacts_caps_at_limit_and_handles_empty() {
        assert!(select_artifacts(Vec::new(), 10).is_empty());
        let candidates = vec![
            cand("mft", "1", "$MFT"),
            cand("prefetch", "2", "Windows/Prefetch/X.pf"),
        ];
        assert_eq!(select_artifacts(candidates.clone(), 1).len(), 1);
        assert_eq!(select_artifacts(candidates, 5).len(), 2); // limit above supply
    }

    #[test]
    fn candidate_dest_dir_namespaces_secondary_partitions_only() {
        let out = Path::new("/cases/abc/extracted/disk/x");
        // Preferred partition (rank 0) keeps the flat layout downstream
        // tooling has always seen; every further partition is namespaced by
        // its sector offset so identical in-filesystem paths cannot collide.
        let os = ArtifactCandidate {
            class: "mft",
            inode: "200".to_string(),
            rel_path: "$MFT".to_string(),
            sector_offset: Some(206_848),
            partition_rank: 0,
            recovered_deleted: false,
        };
        assert_eq!(candidate_dest_dir(out, &os), out.join("mft"));
        let boot = ArtifactCandidate {
            partition_rank: 1,
            sector_offset: Some(2048),
            ..os.clone()
        };
        assert_eq!(
            candidate_dest_dir(out, &boot),
            out.join("mft").join("vol2048")
        );
        let bare = ArtifactCandidate {
            sector_offset: None,
            partition_rank: 0,
            ..os
        };
        assert_eq!(candidate_dest_dir(out, &bare), out.join("mft"));
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
    fn mmls_parser_returns_single_filesystem_partition() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000062   0000000063   Unallocated
002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
";

        let partitions = parse_mmls_filesystem_partitions(output);
        assert_eq!(
            partitions,
            vec![MmlsPartition {
                start_sector: 63,
                length_sectors: 9_510_417,
            }]
        );
        assert_eq!(partition_byte_offsets(partitions), vec![63 * 512]);
    }

    #[test]
    fn mmls_parser_returns_every_filesystem_partition() {
        // Verbatim layout of cfreds_2015_data_leakage_pc.dd (verified with
        // mmls against the fixture on the lab host): a Win7 ~100 MB NTFS
        // "System Reserved" boot partition ahead of the ~19.9 GB NTFS OS
        // volume. The old first-match parser stopped at sector 2048, so
        // extraction only ever saw the boot partition — 256 MFT records, zero
        // registry/prefetch/evtx.
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000206847   0000204800   NTFS / exFAT (0x07)
003:  000:001   0000206848   0041940991   0041734144   NTFS / exFAT (0x07)
004:  -------   0041940992   0041943039   0000002048   Unallocated
";

        assert_eq!(
            parse_mmls_filesystem_partitions(output),
            vec![
                MmlsPartition {
                    start_sector: 2048,
                    length_sectors: 204_800,
                },
                MmlsPartition {
                    start_sector: 206_848,
                    length_sectors: 41_734_144,
                },
            ]
        );
    }

    #[test]
    fn mmls_parser_ignores_metadata_and_unallocated_rows() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
";

        assert_eq!(parse_mmls_filesystem_partitions(output), Vec::new());
    }

    #[test]
    fn partition_preference_puts_the_largest_volume_first() {
        // Largest-first so the extraction budget and the mount favour the OS
        // volume over the boot partition that precedes it on disk; ties break
        // toward the lower start sector for determinism.
        let boot = MmlsPartition {
            start_sector: 2048,
            length_sectors: 204_800,
        };
        let os = MmlsPartition {
            start_sector: 206_848,
            length_sectors: 41_734_144,
        };
        assert_eq!(
            order_partitions_by_preference(vec![boot, os]),
            vec![os, boot]
        );

        let twin_a = MmlsPartition {
            start_sector: 63,
            length_sectors: 1000,
        };
        let twin_b = MmlsPartition {
            start_sector: 5000,
            length_sectors: 1000,
        };
        assert_eq!(
            order_partitions_by_preference(vec![twin_b, twin_a]),
            vec![twin_a, twin_b]
        );
    }
}
