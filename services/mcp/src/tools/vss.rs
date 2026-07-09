//! `vss_list` / `vss_mount` — enumerate and mount Windows Volume Shadow Copies
//! from a disk image via libvshadow (`vshadowinfo` / `vshadowmount`).
//!
//! Volume Shadow Copy Service (VSS) snapshots hold *point-in-time* copies of a
//! volume. They are decisive for DFIR: a file an attacker deleted, a registry
//! hive value they changed, or a payload they wiped often still exists inside an
//! older shadow copy, and the delta between a snapshot and the live volume is a
//! direct anti-forensics / timeline signal. libvshadow reads the shadow store
//! from a raw/mounted volume: `vshadowinfo` lists the stores (creation time,
//! identifier), and `vshadowmount` exposes each snapshot as a `vssN` raw-volume
//! file under a FUSE mount that the normal disk tools then read unchanged.
//!
//! Both tools **degrade safely**: when libvshadow is not installed they return a
//! typed `*_available: false` result with empty data rather than erroring, so the
//! pipeline pivots (mirrors `ez_parse` / `plaso_parse`). Binary discovery is an
//! env override (`$FINDEVIL_VSHADOWINFO_BIN` / `$FINDEVIL_VSHADOWMOUNT_BIN`) then
//! PATH. Read-only: the shadow store and the exposed `vssN` files are never
//! modified.
//!
//! Evidence-agnostic: the `vshadowinfo` parser keys on libvshadow's stable field
//! labels, never on any host's identifiers, volume names, or timestamps.

use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::tools::disk::case_dir;

/// Cap on surfaced shadow stores so a pathological listing cannot bloat output.
const MAX_STORES: usize = 256;

fn vshadowinfo_bin() -> String {
    std::env::var("FINDEVIL_VSHADOWINFO_BIN").unwrap_or_else(|_| "vshadowinfo".to_string())
}

fn vshadowmount_bin() -> String {
    std::env::var("FINDEVIL_VSHADOWMOUNT_BIN").unwrap_or_else(|_| "vshadowmount".to_string())
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VssListInput {
    /// Case ID from a prior `case_open` call. Audit correlation only.
    pub case_id: String,
    /// Path to a raw volume image or mounted volume device to enumerate shadow
    /// copies from.
    pub image_path: PathBuf,
}

/// One Volume Shadow Copy store as reported by `vshadowinfo`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ShadowStore {
    /// 1-based store number (`vssN` when mounted).
    pub store_number: u32,
    /// Store identifier GUID, as reported.
    pub identifier: Option<String>,
    /// Snapshot creation time, as reported (not UTC-normalized here).
    pub creation_time: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VssListOutput {
    /// False when libvshadow is not installed (the pipeline pivots).
    pub vshadowinfo_available: bool,
    /// True if the image carries a VSS shadow store.
    pub has_shadow_store: bool,
    /// Number of shadow copies present (uncapped).
    pub store_count: usize,
    /// The shadow stores (sorted by number, capped).
    pub stores: Vec<ShadowStore>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VssMountInput {
    /// Case ID from a prior `case_open` call.
    pub case_id: String,
    /// Path to the raw volume image or mounted volume device holding the shadow
    /// store.
    pub image_path: PathBuf,
    /// Optional mount point; defaults under the case directory.
    #[serde(default)]
    pub mount_point: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VssMountOutput {
    /// False when libvshadow is not installed.
    pub vshadowmount_available: bool,
    /// Case-scoped mount id (also usable to locate the exposed snapshots).
    pub mount_id: String,
    /// Mount status: `mounted` or `unavailable`.
    pub status: String,
    /// The FUSE mount point holding the exposed `vssN` snapshot files.
    pub mount_point: PathBuf,
    /// Paths of the exposed per-snapshot raw-volume files (`vss1`, `vss2`, …),
    /// which the normal disk tools read unchanged.
    pub shadow_store_paths: Vec<PathBuf>,
    /// The exact command run (or the command that would run when available).
    pub command: Vec<String>,
}

#[derive(Debug, Error)]
pub enum VssError {
    #[error("image not found: {0}")]
    ImageNotFound(PathBuf),
    #[error("case not found or unusable: {0}")]
    Case(String),
    #[error("could not create mount point {path}: {source}")]
    MountPoint {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Enumerate the Volume Shadow Copies in `image_path`. Degrades to
/// `vshadowinfo_available: false` when libvshadow is absent.
///
/// # Errors
/// * [`VssError::ImageNotFound`] — `image_path` missing.
pub fn vss_list(input: &VssListInput) -> Result<VssListOutput, VssError> {
    if !input.image_path.exists() {
        return Err(VssError::ImageNotFound(input.image_path.clone()));
    }
    let output = match Command::new(vshadowinfo_bin())
        .arg(&input.image_path)
        .output()
    {
        Ok(out) => out,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(VssListOutput {
                vshadowinfo_available: false,
                has_shadow_store: false,
                store_count: 0,
                stores: Vec::new(),
            });
        }
        Err(_) => {
            return Ok(VssListOutput {
                vshadowinfo_available: false,
                has_shadow_store: false,
                store_count: 0,
                stores: Vec::new(),
            });
        }
    };
    // vshadowinfo exits non-zero on a volume with no shadow store; that is a
    // valid "no snapshots" answer, not a tool failure.
    let text = String::from_utf8_lossy(&output.stdout);
    let stores = parse_vshadowinfo(&text);
    Ok(VssListOutput {
        vshadowinfo_available: true,
        has_shadow_store: !stores.is_empty(),
        store_count: stores.len(),
        stores: stores.into_iter().take(MAX_STORES).collect(),
    })
}

/// Parse `vshadowinfo` output into shadow stores. Pure over the text so it is
/// unit-tested without libvshadow. libvshadow prints a `Store: N` block per
/// snapshot with indented `Identifier:` and `Creation time:` labels.
fn parse_vshadowinfo(text: &str) -> Vec<ShadowStore> {
    let mut stores: Vec<ShadowStore> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("Store:") {
            if let Ok(n) = rest.trim().parse::<u32>() {
                stores.push(ShadowStore {
                    store_number: n,
                    identifier: None,
                    creation_time: None,
                });
            }
        } else if let Some(rest) = trimmed.strip_prefix("Identifier") {
            if let Some(store) = stores.last_mut() {
                store.identifier = Some(clean_label_value(rest));
            }
        } else if let Some(rest) = trimmed.strip_prefix("Creation time") {
            if let Some(store) = stores.last_mut() {
                store.creation_time = Some(clean_label_value(rest));
            }
        }
    }
    stores.sort_by_key(|s| s.store_number);
    stores
}

/// Strip a libvshadow label's leading `:`/whitespace and trailing whitespace.
fn clean_label_value(rest: &str) -> String {
    rest.trim_start_matches([':', '\t', ' ']).trim().to_string()
}

/// Mount the shadow store's snapshots as `vssN` files under a case-scoped FUSE
/// mount. Degrades to `vshadowmount_available: false` when libvshadow is absent.
///
/// # Errors
/// * [`VssError::ImageNotFound`] — `image_path` missing.
/// * [`VssError::Case`] — the case directory is missing/unusable.
/// * [`VssError::MountPoint`] — the mount directory could not be created.
pub fn vss_mount(input: &VssMountInput) -> Result<VssMountOutput, VssError> {
    if !input.image_path.exists() {
        return Err(VssError::ImageNotFound(input.image_path.clone()));
    }
    let case = case_dir(&input.case_id).map_err(|e| VssError::Case(e.to_string()))?;
    let mount_id = format!("vss-mount-{}", Uuid::new_v4());
    let mount_point = input
        .mount_point
        .clone()
        .unwrap_or_else(|| case.join("mounts").join(&mount_id));
    std::fs::create_dir_all(&mount_point).map_err(|source| VssError::MountPoint {
        path: mount_point.clone(),
        source,
    })?;

    let bin = vshadowmount_bin();
    let command = vec![
        bin.clone(),
        input.image_path.to_string_lossy().to_string(),
        mount_point.to_string_lossy().to_string(),
    ];

    let spawn = Command::new(&bin)
        .arg(&input.image_path)
        .arg(&mount_point)
        .output();
    match spawn {
        Ok(out) if out.status.success() => {
            let shadow_store_paths = collect_vss_files(&mount_point);
            Ok(VssMountOutput {
                vshadowmount_available: true,
                mount_id,
                status: "mounted".to_string(),
                mount_point,
                shadow_store_paths,
                command,
            })
        }
        Ok(_) => Ok(VssMountOutput {
            // vshadowmount ran but could not mount (e.g. no shadow store): report
            // unavailable data rather than a hard error so the pipeline pivots.
            vshadowmount_available: true,
            mount_id,
            status: "unavailable".to_string(),
            mount_point,
            shadow_store_paths: Vec::new(),
            command,
        }),
        Err(_) => Ok(VssMountOutput {
            vshadowmount_available: false,
            mount_id,
            status: "unavailable".to_string(),
            mount_point,
            shadow_store_paths: Vec::new(),
            command,
        }),
    }
}

/// The `vssN` snapshot files libvshadow exposes under the mount point, sorted.
fn collect_vss_files(mount_point: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(mount_point) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vss"))
        })
        .collect();
    paths.sort();
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multiple_shadow_stores_with_metadata() {
        let text = "\
vshadowinfo 20240506

Volume Shadow Snapshot information:
    Number of stores:\t2

Store: 1
    Identifier\t\t: 11111111-1111-1111-1111-111111111111
    Creation time\t\t: Mar 01, 2026 10:00:00
Store: 2
    Identifier\t\t: 22222222-2222-2222-2222-222222222222
    Creation time\t\t: Mar 05, 2026 12:30:00
";
        let stores = parse_vshadowinfo(text);
        assert_eq!(stores.len(), 2);
        assert_eq!(stores[0].store_number, 1);
        assert_eq!(
            stores[0].identifier.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
        assert_eq!(stores[1].store_number, 2);
        assert!(stores[1]
            .creation_time
            .as_deref()
            .unwrap_or_default()
            .contains("Mar 05"));
    }

    #[test]
    fn no_shadow_store_yields_empty() {
        let text = "vshadowinfo 20240506\n\nNo Volume Shadow Snapshots found.\n";
        assert!(parse_vshadowinfo(text).is_empty());
    }

    #[test]
    fn stores_are_sorted_by_number() {
        let text = "Store: 3\nStore: 1\nStore: 2\n";
        let stores = parse_vshadowinfo(text);
        let nums: Vec<u32> = stores.iter().map(|s| s.store_number).collect();
        assert_eq!(nums, vec![1, 2, 3]);
    }

    #[test]
    fn clean_label_value_strips_colon_and_whitespace() {
        assert_eq!(clean_label_value("\t\t: value here"), "value here");
        assert_eq!(clean_label_value(": x"), "x");
    }
}
