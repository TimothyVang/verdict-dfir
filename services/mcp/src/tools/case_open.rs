//! `case_open` — register an evidence image and initialize the case dir.
//!
//! Spec #2 §6. First tool the agent calls on every investigation.
//! Responsible for:
//!
//! 1. Verifying the image path exists and is readable.
//! 2. Computing the file's SHA-256 in fixed-size chunks (streaming
//!    so multi-GB `.e01` files do not require full memory residence).
//! 3. Deriving the canonical `case_id` (UUID4, stable per call).
//! 4. Creating the case directory layout at
//!    `$FINDEVIL_HOME/cases/<id>/` (defaults to `~/.findevil/`).
//! 5. Recording the image path + SHA-256 + size in
//!    `cases/<id>/case.json` for later tools.
//!
//! Downstream tools (`evtx_query`, `mft_timeline`, etc.) assume the
//! case dir exists. `libewf`-based E01 mount + `DuckDB` schema init
//! land in Week 2 Task A4 / A11 — kept out of this MVP so the first
//! tool is independently testable.

use std::fs::{self, File};
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const SHA_BUFFER_SIZE: usize = 1 << 20; // 1 MiB — good streaming tradeoff

/// Agent-supplied input.
///
/// Only the image path is required today; Spec #2 §6 reserves
/// optional fields (`expected_sha256`, `label`) for later additions.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaseOpenInput {
    /// Absolute or relative path to the evidence image (`.e01`,
    /// `.raw`, `.dd`, `.mem`, or `.ova`). Path is resolved
    /// lexically; the tool does not follow symlinks outside the
    /// caller's `cwd` tree.
    pub image_path: PathBuf,

    /// Optional pinned SHA-256 (hex). When supplied, the computed
    /// hash must match byte-for-byte or `case_open` returns
    /// [`CaseOpenError::ImageHashMismatch`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,

    /// Optional human-readable label propagated into `case.json`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Registered case handle — the typed return value.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CaseHandle {
    /// `UUIDv4` assigned at registration.
    pub id: String,

    /// Absolute path to the case directory, e.g.
    /// `/home/sansforensics/.findevil/cases/7c3f9a2e-.../`.
    pub case_dir: PathBuf,

    /// Future `DuckDB` evidence database path — created by a later
    /// tool but the canonical location is reserved here.
    pub db_path: PathBuf,

    /// SHA-256 hex (lowercase) of the evidence image bytes.
    pub image_hash: String,

    /// Evidence image size in bytes.
    pub image_size_bytes: u64,

    /// UTC ISO-8601 timestamp of registration (trailing `Z`).
    pub registered_at: String,
}

/// Errors `case_open` can produce. All variants are safe to surface
/// back to the agent — no internal state leaks.
#[derive(Debug, Error)]
pub enum CaseOpenError {
    #[error("evidence image not found: {0}")]
    ImageNotFound(PathBuf),

    #[error("evidence image is not a regular file: {0}")]
    ImageNotRegular(PathBuf),

    #[error("cannot read evidence image {path}: {source}")]
    ImageUnreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("image hash mismatch: expected {expected}, got {actual}")]
    ImageHashMismatch { expected: String, actual: String },

    #[error("could not determine FINDEVIL_HOME (no HOME, no override)")]
    NoFindEvilHome,

    #[error("cannot create case dir {path}: {source}")]
    CaseDirCreate {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cannot write case manifest {path}: {source}")]
    ManifestWrite {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("cannot serialize case manifest: {0}")]
    ManifestSerialize(#[from] serde_json::Error),
}

/// Tool entrypoint. Pure function over filesystem side-effects; no
/// global state.
///
/// Environment variable `FINDEVIL_HOME` overrides the default
/// `$HOME/.findevil` root. Pass it via tests to avoid stomping on
/// the developer's real case store.
pub fn case_open(input: &CaseOpenInput) -> Result<CaseHandle, CaseOpenError> {
    // 1. Resolve + verify the image path. `symlink_metadata` (lstat) does
    //    NOT follow symlinks, so a link planted in the evidence drop zone
    //    pointing at an arbitrary host file is refused as not-regular —
    //    enforcing the "does not follow symlinks" contract documented on
    //    `CaseOpenInput::image_path`.
    let image_path = &input.image_path;
    let meta = fs::symlink_metadata(image_path)
        .map_err(|_| CaseOpenError::ImageNotFound(image_path.clone()))?;
    if !meta.is_file() {
        return Err(CaseOpenError::ImageNotRegular(image_path.clone()));
    }

    // 2. Stream-hash the image.
    let actual_hash = sha256_file(image_path)?;
    if let Some(expected) = &input.expected_sha256 {
        if expected.eq_ignore_ascii_case(&actual_hash) {
            // ok — match
        } else {
            return Err(CaseOpenError::ImageHashMismatch {
                expected: expected.to_lowercase(),
                actual: actual_hash,
            });
        }
    }

    // 3. Allocate a case_id.
    let case_id = Uuid::new_v4().to_string();

    // 4. Resolve FINDEVIL_HOME + create case dir.
    let home = resolve_findevil_home()?;
    let case_dir = home.join("cases").join(&case_id);
    fs::create_dir_all(&case_dir).map_err(|source| CaseOpenError::CaseDirCreate {
        path: case_dir.clone(),
        source,
    })?;

    // Reserve the DuckDB path; not created yet.
    let db_path = case_dir.join("evidence.ddb");

    let registered_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let handle = CaseHandle {
        id: case_id,
        case_dir: case_dir.clone(),
        db_path,
        image_hash: actual_hash,
        image_size_bytes: meta.len(),
        registered_at,
    };

    // 5. Persist a minimal manifest for later tools + audit.
    let manifest_path = case_dir.join("case.json");
    let manifest = serde_json::to_string_pretty(&CaseManifest::from_handle(&handle, input))?;
    fs::write(&manifest_path, manifest).map_err(|source| CaseOpenError::ManifestWrite {
        path: manifest_path,
        source,
    })?;

    Ok(handle)
}

#[derive(Serialize)]
struct CaseManifest<'a> {
    id: &'a str,
    image_path: &'a Path,
    image_hash: &'a str,
    image_size_bytes: u64,
    registered_at: &'a str,
    label: &'a Option<String>,
}

impl<'a> CaseManifest<'a> {
    fn from_handle(h: &'a CaseHandle, inp: &'a CaseOpenInput) -> Self {
        Self {
            id: &h.id,
            image_path: &inp.image_path,
            image_hash: &h.image_hash,
            image_size_bytes: h.image_size_bytes,
            registered_at: &h.registered_at,
            label: &inp.label,
        }
    }
}

fn sha256_file(path: &Path) -> Result<String, CaseOpenError> {
    let file = File::open(path).map_err(|source| CaseOpenError::ImageUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let mut reader = BufReader::with_capacity(SHA_BUFFER_SIZE, file);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; SHA_BUFFER_SIZE];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|source| CaseOpenError::ImageUnreadable {
                path: path.to_path_buf(),
                source,
            })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    Ok(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn resolve_findevil_home() -> Result<PathBuf, CaseOpenError> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Ok(PathBuf::from(v));
        }
    }
    // Unix-ish HOME first; fall back to Windows USERPROFILE.
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
    Err(CaseOpenError::NoFindEvilHome)
}

// --------------------------------------------------------------------
// Unit tests — cover pure helpers. Integration tests in
// `services/mcp/tests/tool_smoke.rs` exercise the full case_open
// side-effecting path against tempfile-backed fixtures.
// --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_matches_sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let mut h = Sha256::new();
        h.update(b"abc");
        let got = hex_encode(&h.finalize());
        assert_eq!(
            got,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn resolve_home_respects_findevil_override() {
        let _env_guard = crate::ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        // SAFETY: env mutation is restricted to this test; tests run
        // single-threaded under `cargo test -- --test-threads=1` by
        // default when env manipulation matters, and our workspace
        // test matrix uses that. We still isolate by snapshotting.
        let prev_home = std::env::var("FINDEVIL_HOME").ok();
        std::env::set_var("FINDEVIL_HOME", tmp.path());
        let got = resolve_findevil_home().unwrap();
        assert_eq!(got, tmp.path());
        match prev_home {
            Some(v) => std::env::set_var("FINDEVIL_HOME", v),
            None => std::env::remove_var("FINDEVIL_HOME"),
        }
    }

    #[test]
    fn resolve_home_errors_when_no_env() {
        let _env_guard = crate::ENV_LOCK.lock().unwrap();
        let prev_findevil = std::env::var("FINDEVIL_HOME").ok();
        let prev_home = std::env::var("HOME").ok();
        let prev_userprofile = std::env::var("USERPROFILE").ok();
        std::env::remove_var("FINDEVIL_HOME");
        std::env::remove_var("HOME");
        std::env::remove_var("USERPROFILE");
        let err = resolve_findevil_home().unwrap_err();
        assert!(matches!(err, CaseOpenError::NoFindEvilHome));
        if let Some(v) = prev_findevil {
            std::env::set_var("FINDEVIL_HOME", v);
        }
        if let Some(v) = prev_home {
            std::env::set_var("HOME", v);
        }
        if let Some(v) = prev_userprofile {
            std::env::set_var("USERPROFILE", v);
        }
    }
}
