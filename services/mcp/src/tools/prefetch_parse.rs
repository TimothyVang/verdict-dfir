//! `prefetch_parse` — extract execution evidence from a Windows Prefetch file.
//!
//! Spec #2 §6 + `agent-config/SOUL.md` cross-artifact rule: Prefetch
//! is the canonical "did this binary actually execute" artifact.
//! Combined with Amcache+ShimCache it establishes the ≥2 artifact-class
//! corroboration the correlator requires for execution claims.
//!
//! Backed by `frnsc-prefetch = "=0.13.3"` (MIT, pure Rust). Handles
//! both the MAM-compressed Win10+ format and the uncompressed SCCA
//! Win7-/8.1 format transparently.
//!
//! Output shape matches Spec #2 §6's `PrefetchOutput` contract:
//! `executable_name`, `version` (17=XP, 23=Win7, 26=Win8.1, 30=Win10),
//! `run_count`, `last_run_times_iso` (up to 8 entries on Win10+),
//! `file_references` (DLLs/EXEs the binary loaded), and `volume_paths`.
//!
//! The `last_run_times_iso` is the time evidence under the SOUL.md
//! "execution claims need ≥2 artifact classes" rule. Caveat: prefetch
//! can be disabled on SSDs (`EnablePrefetcher`=0); absence is not
//! evidence of absence — that caveat lives in `agent-config/MEMORY.md`
//! and the agent surfaces it.

use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use forensic_rs::prelude::StdVirtualFS;
use forensic_rs::traits::vfs::{VirtualFile, VirtualFileSystem};
use frnsc_prefetch::prelude::{read_prefetch_file, PrefetchFile};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrefetchInput {
    /// Case ID from a prior `case_open` call. Accepted so the agent
    /// can trace the call in the audit log; not consumed by the parser.
    pub case_id: String,

    /// Absolute or relative path to a `.pf` file.
    pub prefetch_path: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrefetchOutput {
    /// Name of the executable as recorded in the prefetch header.
    pub executable_name: String,

    /// Prefetch format version.
    /// 17 = Windows XP, 23 = Windows 7, 26 = Windows 8.1, 30 = Windows 10.
    pub version: u32,

    /// Number of times the executable ran.
    pub run_count: u32,

    /// Up to 8 last-run times in UTC ISO-8601Z. The most recent is first.
    pub last_run_times_iso: Vec<String>,

    /// File references (DLLs/EXEs/etc. loaded by the executable).
    /// Capped at the structural max from the format; the parser will
    /// not return more than the file actually contains.
    pub file_references: Vec<String>,

    /// Volume paths the binary or its dependencies live on.
    /// Each entry is a `\VOLUME{...}` path string from the volume table.
    pub volume_paths: Vec<String>,
}

#[derive(Debug, Error)]
pub enum PrefetchError {
    #[error("prefetch file not found: {0}")]
    NotFound(PathBuf),

    #[error("prefetch file unreadable {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Boxed because `forensic_rs::err::ForensicError` is large enough
    /// to push our `Result<_, PrefetchError>` over clippy's
    /// `result_large_err` threshold; the error path is rare anyway.
    #[error("prefetch parse failed for {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: Box<forensic_rs::err::ForensicError>,
    },

    #[error(
        "prefetch parse for {path} did not finish within {seconds}s and was abandoned; \
         the file's compressed body drives the decoder into a non-terminating loop \
         (seen on .pf files recovered from a deleted directory entry). No execution \
         evidence was read from this artifact."
    )]
    ParseTimedOut { path: PathBuf, seconds: u64 },

    #[error("prefetch parse for {path} panicked inside the decoder")]
    ParsePanicked { path: PathBuf },
}

/// Wall-clock bound on one `.pf` parse. Override with
/// `FINDEVIL_PREFETCH_PARSE_TIMEOUT_SECS`. A healthy prefetch file parses in
/// single-digit milliseconds, so this is orders of magnitude of headroom.
const DEFAULT_PARSE_TIMEOUT_SECS: u64 = 15;

fn parse_timeout() -> Duration {
    let secs = std::env::var("FINDEVIL_PREFETCH_PARSE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_PARSE_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

/// Why a bounded call did not produce a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BoundedError {
    TimedOut,
    Panicked,
}

/// Run `work` on a worker thread and give up after `limit`.
///
/// The MCP stdio server dispatches strictly serially (one JSON line in, one
/// out), so a tool call that never returns wedges every LATER call in the case
/// — the disk lane would lose its registry, EVTX and YARA passes because of one
/// malformed artifact. A timed-out worker is abandoned rather than killed
/// (Rust has no safe thread cancellation); that leaks one spinning thread per
/// pathological file, which is bounded by the number of `.pf` artifacts a run
/// extracts and is strictly better than losing the rest of the investigation.
pub(crate) fn run_bounded<T, F>(limit: Duration, work: F) -> Result<T, BoundedError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work));
        // A closed receiver means the caller already gave up; nothing to do.
        drop(tx.send(result));
    });
    match rx.recv_timeout(limit) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_panic)) => Err(BoundedError::Panicked),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(BoundedError::TimedOut),
        // The worker vanished without sending — treat as a failed parse.
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(BoundedError::Panicked),
    }
}

/// Cheap pre-flight: file path looks like a Prefetch artifact.
///
/// Mirrors `evtx_query::path_looks_like_evtx`. The Rust layer doesn't
/// reject on extension mismatch (some forensic tools rename `.pf` to
/// avoid OS auto-deletion), but the Python agent uses this to pick
/// which MCP tool to dispatch.
#[must_use]
pub fn path_looks_like_prefetch(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pf"))
}

/// Parse a `.pf` file and extract execution evidence.
///
/// Supports both MAM-compressed (Win10+) and uncompressed SCCA
/// (Win7/8.1) formats; auto-detected by the underlying parser. The
/// file is read in-process — no subprocess.
///
/// # Errors
/// * [`PrefetchError::NotFound`] — the file does not exist.
/// * [`PrefetchError::Unreadable`] — the file exists but cannot be
///   opened (permissions / I/O error).
/// * [`PrefetchError::ParseFailed`] — the parser rejected the file
///   (corrupt header, unsupported version, decompression failure).
/// * [`PrefetchError::ParseTimedOut`] — the decoder did not terminate within
///   the parse bound and was abandoned (see [`run_bounded`]).
/// * [`PrefetchError::ParsePanicked`] — the decoder panicked on this input.
pub fn prefetch_parse(input: &PrefetchInput) -> Result<PrefetchOutput, PrefetchError> {
    let path = &input.prefetch_path;
    if !path.is_file() {
        return Err(PrefetchError::NotFound(path.clone()));
    }

    // Bounded: some real .pf bodies (observed on files carved back out of a
    // wiped Prefetch directory) send the MAM decompressor into a
    // non-terminating loop. Left unbounded that hangs the whole serial stdio
    // server, so one bad artifact would cost the entire case its remaining
    // tool calls. A timeout is reported as an analysis limitation instead.
    //
    // `Box<dyn VirtualFile>` is not `Send`, so the open happens inside the
    // worker: the whole read is what has to be abandonable, not just the decode.
    let limit = parse_timeout();
    let owned_path = path.clone();
    let worker_path = path.clone();
    let parsed: PrefetchFile = match run_bounded(limit, move || read_prefetch(&worker_path)) {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(err)) => return Err(err),
        Err(BoundedError::TimedOut) => {
            return Err(PrefetchError::ParseTimedOut {
                path: owned_path,
                seconds: limit.as_secs(),
            })
        }
        Err(BoundedError::Panicked) => {
            return Err(PrefetchError::ParsePanicked { path: owned_path })
        }
    };

    Ok(to_output(parsed))
}

/// Open and decode one `.pf`. Runs on the bounded worker thread, so everything
/// it touches must be owned.
///
/// The frnsc-prefetch API is filesystem-abstract: `StdVirtualFS` wraps the real
/// disk and the parser asks it for one `VirtualFile`.
fn read_prefetch(path: &Path) -> Result<PrefetchFile, PrefetchError> {
    let mut fs = StdVirtualFS::new();
    let file: Box<dyn VirtualFile> = fs.open(path).map_err(|err| PrefetchError::Unreadable {
        path: path.to_path_buf(),
        source: std::io::Error::other(err.to_string()),
    })?;
    let artifact_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("UNKNOWN.pf");
    read_prefetch_file(artifact_name, file).map_err(|err| PrefetchError::ParseFailed {
        path: path.to_path_buf(),
        source: Box::new(err),
    })
}

fn to_output(p: PrefetchFile) -> PrefetchOutput {
    let last_run_times_iso = p
        .last_run_times
        .iter()
        .filter_map(filetime_to_iso)
        .collect();

    let file_references = p
        .metrics
        .iter()
        .map(|m| m.file.clone())
        .filter(|f| !f.is_empty())
        .collect();

    let volume_paths = p
        .volume
        .iter()
        .map(|v| v.device_path.clone())
        .filter(|s| !s.is_empty())
        .collect();

    PrefetchOutput {
        executable_name: p.name,
        version: p.version,
        run_count: p.run_count,
        last_run_times_iso,
        file_references,
        volume_paths,
    }
}

/// Convert a Windows FILETIME (100-ns ticks since 1601-01-01 UTC) to
/// the project-standard ISO-8601Z string.
///
/// FILETIME 0 means "never" — the prefetch format zero-pads the
/// last-run-times slot when fewer than 8 runs are recorded. We drop
/// those entries via the `?` on the conversion result.
// 116444736000000000 ticks = FILETIME for 1970-01-01 (Unix epoch).
const FILETIME_UNIX_EPOCH_TICKS: i64 = 116_444_736_000_000_000;

fn filetime_to_iso(ft: &forensic_rs::utils::time::Filetime) -> Option<String> {
    let raw = ft.filetime();
    if raw == 0 {
        return None;
    }
    let unix_100ns = i64::try_from(raw).ok()? - FILETIME_UNIX_EPOCH_TICKS;
    let secs = unix_100ns / 10_000_000;
    let nanos = u32::try_from((unix_100ns % 10_000_000) * 100).ok()?;
    let dt = chrono::DateTime::<chrono::Utc>::from_timestamp(secs, nanos)?;
    Some(dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::{run_bounded, BoundedError};
    use std::time::Duration;

    #[test]
    fn run_bounded_returns_the_value_when_the_work_finishes_in_time() {
        let out = run_bounded(Duration::from_secs(5), || 41 + 1).expect("finished");
        assert_eq!(out, 42);
    }

    #[test]
    fn run_bounded_gives_up_on_work_that_never_returns() {
        // A .pf recovered from a wiped Prefetch directory can drive the
        // third-party MAM decompressor into a non-terminating loop. The MCP
        // stdio server dispatches strictly serially, so an unbounded parse
        // wedges EVERY later tool call in the case, not just this one.
        let err = run_bounded(Duration::from_millis(150), || loop {
            std::hint::spin_loop();
        })
        .expect_err("must give up");
        assert!(matches!(err, BoundedError::TimedOut));
    }

    #[test]
    fn run_bounded_surfaces_a_panic_as_a_failure_rather_than_unwinding() {
        let err = run_bounded(Duration::from_secs(5), || -> u32 { panic!("boom") })
            .expect_err("panic must not propagate");
        assert!(matches!(err, BoundedError::Panicked));
    }
}
