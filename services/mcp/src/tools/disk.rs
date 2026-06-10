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

const LEDGER_NAME: &str = "session_resources.json";
const STDERR_TAIL_BYTES: usize = 4096;
const DEFAULT_MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;

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

    let sector_offset = first_partition_sector_offset(&image_path);

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
    let (listed, via_walk) = match tsk_list(&image_path, sector_offset) {
        Ok(files) if !files.is_empty() => (files, false),
        tsk_result => match &mock_root {
            Some(root) => (mock_list(root)?, true),
            None => (tsk_result?, false),
        },
    };
    let candidates: Vec<(&'static str, String, String)> = listed
        .into_iter()
        .filter_map(|(inode, path)| {
            let class = classify_artifact_path(&path)?;
            wanted
                .get(class)
                .copied()
                .unwrap_or(false)
                .then_some((class, inode, path))
        })
        .collect();
    let selected = select_artifacts(candidates, input.limit);

    let mut artifacts = Vec::new();
    let mut artifacts_skipped_oversize = 0;
    for (class, inode, path) in selected {
        match (via_walk, &mock_root) {
            (true, Some(root)) => mock_extract(
                root,
                &path,
                class,
                &output_dir,
                input.max_artifact_bytes,
                &mut artifacts,
                &mut artifacts_skipped_oversize,
            )?,
            _ => tsk_extract(
                &image_path,
                sector_offset,
                &inode,
                &path,
                class,
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
        max_artifact_bytes: input.max_artifact_bytes,
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
/// sudo (the EWF device is root-owned). Tries offset 0 (bare volume image) then
/// the first filesystem-partition offset from `mmls` (full disk image).
fn mount_ntfs_ro(device: &Path, mount_point: &Path) -> Result<(Vec<String>, String), DiskError> {
    let mount_bin = std::env::var("FINDEVIL_MOUNT_BIN").unwrap_or_else(|_| "mount".to_string());
    let mut offsets = vec![0u64];
    if let Some(offset) = first_partition_byte_offset_sudo(device) {
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

/// `mmls` first-filesystem-partition byte offset, run under sudo because the
/// EWF device is root-owned. None when the image is a bare volume (no table).
fn first_partition_byte_offset_sudo(image_path: &Path) -> Option<u64> {
    let output = Command::new("sudo")
        .args(["-n", "mmls"])
        .arg(image_path)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_mmls_first_partition_offset(&String::from_utf8_lossy(&output.stdout))
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
    if let Some(offset) = first_partition_byte_offset(image_path) {
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
                format!("mounted first filesystem partition read-only with loop offset {offset}"),
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
                        "mounted first filesystem partition read-only with sudo loop offset {offset}"
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

fn first_partition_byte_offset(image_path: &Path) -> Option<u64> {
    let output = Command::new("mmls").arg(image_path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_mmls_first_partition_offset(&String::from_utf8_lossy(&output.stdout))
}

fn parse_mmls_first_partition_offset(output: &str) -> Option<u64> {
    for line in output.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("meta")
            || lower.contains("unallocated")
            || !matches_filesystem_description(&lower)
        {
            continue;
        }
        let start_sector = line
            .split_whitespace()
            .find(|field| field.chars().all(|c| c.is_ascii_digit()))?
            .parse::<u64>()
            .ok()?;
        return start_sector.checked_mul(512);
    }
    None
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

/// Sector offset of the first filesystem partition for `fls`/`icat -o`, or None
/// for a bare volume image (TSK reads it at offset 0). mmls reports the start
/// sector; the byte helper multiplies by 512, so divide it back to sectors.
fn first_partition_sector_offset(image_path: &Path) -> Option<u64> {
    first_partition_byte_offset(image_path).map(|bytes| bytes / 512)
}

/// Enumerate every live regular file in the image via `fls -r -p`, returning
/// `(inode, relative_path)` pairs. Reads the image directly (no mount).
fn tsk_list(
    image_path: &Path,
    sector_offset: Option<u64>,
) -> Result<Vec<(String, String)>, DiskError> {
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
    out.push(ExtractedDiskArtifact {
        artifact_class: class.to_string(),
        source_path: PathBuf::from(rel_path),
        extracted_path: dest,
        size_bytes: size,
    });
    Ok(())
}

/// Parse one `fls -p` line into `(inode, relative_path)` for a live regular
/// file. Lines look like `r/r 380861-128-4:\tWindows/System32/config/SYSTEM`.
/// Returns None for directories, deleted entries (marked `*`), and non-files.
fn parse_fls_line(line: &str) -> Option<(String, String)> {
    let (kind, rest) = line.split_once(char::is_whitespace)?;
    if !kind.starts_with("r/r") {
        return None;
    }
    let rest = rest.trim_start();
    if rest.starts_with('*') {
        // deleted entry — not reliably recoverable, skip.
        return None;
    }
    let (inode, path) = rest.split_once(':')?;
    let inode = inode.trim();
    let path = path.trim();
    if inode.is_empty() || path.is_empty() {
        return None;
    }
    Some((inode.to_string(), path.to_string()))
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
        _ => 5,
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

/// Choose up to `limit` artifacts to extract, allocating the budget *fairly
/// across classes* so no single voluminous class starves the rest. Classes are
/// visited in [`class_priority`] order and drawn round-robin: every class with
/// candidates gets a turn each pass, and a class that drains early hands its
/// unused budget to the others. Within a class, [`artifact_subrank`] then path
/// order decides which artifacts win the class's share. Pure (no I/O) so the
/// allocation is unit-testable.
fn select_artifacts(
    candidates: Vec<(&'static str, String, String)>,
    limit: usize,
) -> Vec<(&'static str, String, String)> {
    let mut buckets: BTreeMap<u8, Vec<(&'static str, String, String)>> = BTreeMap::new();
    for candidate in candidates {
        buckets
            .entry(class_priority(candidate.0))
            .or_default()
            .push(candidate);
    }
    let mut queues: Vec<VecDeque<(&'static str, String, String)>> = buckets
        .into_values()
        .map(|mut bucket| {
            bucket.sort_by(|a, b| {
                artifact_subrank(a.0, &a.2)
                    .cmp(&artifact_subrank(b.0, &b.2))
                    .then_with(|| a.2.cmp(&b.2))
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

/// `icat` one inode out of the image into `output_dir/<class>/<rel_path>`,
/// streaming to disk (no in-memory buffering) and enforcing the size cap.
/// A failed `icat` (unreadable inode) is skipped, not fatal.
#[allow(clippy::too_many_arguments)]
fn tsk_extract(
    image_path: &Path,
    sector_offset: Option<u64>,
    inode: &str,
    rel_path: &str,
    class: &str,
    output_dir: &Path,
    max_artifact_bytes: u64,
    out: &mut Vec<ExtractedDiskArtifact>,
    skipped_oversize: &mut usize,
) -> Result<(), DiskError> {
    let dest = safe_join(&output_dir.join(class), rel_path);
    if let Some(parent) = dest.parent() {
        create_dir(parent)?;
    }
    let bin = std::env::var("FINDEVIL_ICAT_BIN").unwrap_or_else(|_| "icat".to_string());
    let mut command = Command::new(&bin);
    if let Some(offset) = sector_offset {
        command.arg("-o").arg(offset.to_string());
    }
    command.arg(image_path).arg(inode);
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
    out.push(ExtractedDiskArtifact {
        artifact_class: class.to_string(),
        source_path: PathBuf::from(rel_path),
        extracted_path: dest,
        size_bytes: size,
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

fn classify_artifact_path(rel: &str) -> Option<&'static str> {
    let rel = rel.replace('\\', "/").to_ascii_lowercase();
    let name = rel.rsplit('/').next().unwrap_or(rel.as_str());
    if name == "$mft" || name == "mft" {
        Some("mft")
    } else if name == "$j" || rel.contains("$usnjrnl") || has_extension(name, "usn") {
        Some("usnjrnl")
    } else if has_extension(name, "pf") {
        Some("prefetch")
    } else if matches!(
        name,
        "software" | "system" | "sam" | "security" | "ntuser.dat" | "usrclass.dat"
    ) {
        Some("registry")
    } else if has_extension(name, "evtx") {
        Some("evtx")
    } else if rel.starts_with("users/")
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
        artifact_subrank, class_priority, classify_artifact_path, mock_list, parse_fls_line,
        parse_mmls_first_partition_offset, select_artifacts, unmount_steps,
    };
    use std::path::Path;

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
        assert_eq!(
            parse_fls_line("r/r 380861-128-4:\tWindows/System32/config/SYSTEM"),
            Some((
                "380861-128-4".to_string(),
                "Windows/System32/config/SYSTEM".to_string(),
            ))
        );
    }

    #[test]
    fn parse_fls_line_skips_dirs_deleted_and_blanks() {
        assert_eq!(parse_fls_line("d/d 282867-144-5:\tUsers"), None);
        assert_eq!(
            parse_fls_line("r/r * 999-128-1:\tWindows/Prefetch/x.pf"),
            None
        );
        assert_eq!(parse_fls_line(""), None);
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
        let mut candidates: Vec<(&'static str, String, String)> = Vec::new();
        for i in 0..400 {
            candidates.push((
                "prefetch",
                format!("{i}"),
                format!("Windows/Prefetch/A{i:04}.pf"),
            ));
        }
        for i in 0..600 {
            candidates.push((
                "evtx",
                format!("e{i}"),
                format!(
                    "Windows/System32/winevt/Logs/Microsoft-Windows-Zzz{i:04}%4Operational.evtx"
                ),
            ));
        }
        candidates.push((
            "evtx",
            "sec".to_string(),
            "Windows/System32/winevt/Logs/Security.evtx".to_string(),
        ));
        candidates.push(("mft", "mft".to_string(), "$MFT".to_string()));

        let selected = select_artifacts(candidates, 50);
        assert_eq!(selected.len(), 50);
        let classes: std::collections::HashSet<&str> = selected.iter().map(|c| c.0).collect();
        assert!(classes.contains("prefetch"), "prefetch starved");
        assert!(classes.contains("evtx"), "evtx starved (the original bug)");
        assert!(classes.contains("mft"), "mft missing");
        assert!(
            selected.iter().any(|c| c.2.ends_with("/Security.evtx")),
            "canonical Security.evtx must win evtx's fair share"
        );
    }

    #[test]
    fn select_artifacts_caps_at_limit_and_handles_empty() {
        assert!(select_artifacts(Vec::new(), 10).is_empty());
        let candidates = vec![
            ("mft", "1".to_string(), "$MFT".to_string()),
            (
                "prefetch",
                "2".to_string(),
                "Windows/Prefetch/X.pf".to_string(),
            ),
        ];
        assert_eq!(select_artifacts(candidates.clone(), 1).len(), 1);
        assert_eq!(select_artifacts(candidates, 5).len(), 2); // limit above supply
    }

    #[test]
    fn unmount_steps_ewf_plus_ntfs_releases_loop_then_container() {
        let mp = Path::new("/m");
        let steps = unmount_steps(mp, &mp.join("fs"), "umount");
        assert_eq!(
            steps,
            vec![
                ("umount".to_string(), vec!["/m/fs".to_string()]),
                ("umount".to_string(), vec!["/m/ewf".to_string()]),
            ]
        );
    }

    #[test]
    fn unmount_steps_ewf_only_releases_container() {
        let mp = Path::new("/m");
        let steps = unmount_steps(mp, &mp.join("ewf"), "umount");
        assert_eq!(
            steps,
            vec![("umount".to_string(), vec!["/m/ewf".to_string()])]
        );
    }

    #[test]
    fn unmount_steps_raw_umounts_the_mount_point() {
        let mp = Path::new("/m");
        let steps = unmount_steps(mp, mp, "umount");
        assert_eq!(steps, vec![("umount".to_string(), vec!["/m".to_string()])]);
    }

    #[test]
    fn mmls_parser_returns_first_filesystem_partition_offset() {
        let output = r"DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000000062   0000000063   Unallocated
002:  000:000   0000000063   0009510479   0009510417   NTFS / exFAT (0x07)
";

        assert_eq!(parse_mmls_first_partition_offset(output), Some(63 * 512));
    }

    #[test]
    fn mmls_parser_ignores_metadata_and_unallocated_rows() {
        let output = r"      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
";

        assert_eq!(parse_mmls_first_partition_offset(output), None);
    }
}
