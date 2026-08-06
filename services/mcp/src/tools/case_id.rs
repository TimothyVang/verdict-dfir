//! Shared `case_id` path-segment validation.
//!
//! Every tool that joins `case_id` into `$FINDEVIL_HOME/cases/<case_id>`
//! (and especially any that then `create_dir` / `remove_dir_all` under it)
//! must call [`is_valid_case_id`] first. Without this, a value like
//! `../../etc` escapes the case sandbox.
//!
//! UUID4 case ids from `case_open` satisfy the allowlist.

use std::path::PathBuf;

/// Whether a `case_id` is safe to use as a single path component.
///
/// True iff non-empty and every character is ASCII alphanumeric, `-`, or
/// `_`. Excludes `/`, `\`, `.` (so `.`/`..` traversal), and NUL.
#[must_use]
pub fn is_valid_case_id(case_id: &str) -> bool {
    !case_id.is_empty()
        && case_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Why a per-case scratch directory could not be resolved. Carries a
/// self-describing [`std::fmt::Display`] so a caller folding it into its own
/// string-carrying error variant still surfaces the real cause (not a
/// misleading "could not parse output").
#[derive(Debug)]
pub enum CaseScratchError {
    /// `case_id` failed [`is_valid_case_id`] (would escape the case sandbox).
    InvalidCaseId(String),
    /// Neither `FINDEVIL_HOME` nor a home directory could be resolved.
    HomeUnset,
    /// The case directory does not exist (was `case_open` run first?).
    CaseNotFound(PathBuf),
    /// The scratch directory could not be created.
    Create { path: PathBuf, source: std::io::Error },
}

impl std::fmt::Display for CaseScratchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCaseId(id) => write!(f, "invalid case_id {id:?}"),
            Self::HomeUnset => {
                write!(f, "could not determine FINDEVIL_HOME (no override, no HOME)")
            }
            Self::CaseNotFound(dir) => write!(
                f,
                "case dir {} not found under FINDEVIL_HOME/cases (run case_open first)",
                dir.display()
            ),
            Self::Create { path, source } => {
                write!(f, "could not create scratch dir {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for CaseScratchError {}

/// Resolve `$FINDEVIL_HOME`, falling back to `$HOME/.findevil` then
/// `$USERPROFILE/.findevil`. Mirrors the per-tool helpers in
/// `srum_parse`/`pst_parse`/`bulk_extract`.
fn findevil_home() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    for var in ["HOME", "USERPROFILE"] {
        if let Ok(v) = std::env::var(var) {
            if !v.is_empty() {
                return Some(PathBuf::from(v).join(".findevil"));
            }
        }
    }
    None
}

/// Create and return a fresh, unique per-case scratch directory at
/// `$FINDEVIL_HOME/cases/<case_id>/_xartifact/<label>-<pid>-<nanos>`.
///
/// This is the containment-safe replacement for `std::env::temp_dir()` in the
/// evidence-decoding tools: derived-artifact staging is anchored to the case
/// directory rather than the OS temp dir, so containment no longer depends on
/// an external `TMPDIR` being set. Fail-closed — if the case dir does not exist
/// (or `case_id` is unsafe, or no home can be resolved) it errors rather than
/// silently falling back to a shared world-writable temp location.
///
/// # Errors
/// Returns [`CaseScratchError`] when `case_id` is invalid, no home can be
/// resolved, the case dir is absent, or the directory cannot be created.
pub fn case_scratch_dir(case_id: &str, label: &str) -> Result<PathBuf, CaseScratchError> {
    if !is_valid_case_id(case_id) {
        return Err(CaseScratchError::InvalidCaseId(case_id.to_string()));
    }
    let case_dir = findevil_home()
        .ok_or(CaseScratchError::HomeUnset)?
        .join("cases")
        .join(case_id);
    if !case_dir.is_dir() {
        return Err(CaseScratchError::CaseNotFound(case_dir));
    }
    let nanos = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos())
    };
    let scratch = case_dir
        .join("_xartifact")
        .join(format!("{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&scratch).map_err(|source| CaseScratchError::Create {
        path: scratch.clone(),
        source,
    })?;
    Ok(scratch)
}

#[cfg(test)]
mod tests {
    use super::is_valid_case_id;

    #[test]
    fn accepts_uuid4_and_simple_ids() {
        assert!(is_valid_case_id("cdae1632-1d18-43af-9946-2aff955716a6"));
        assert!(is_valid_case_id("disk_case_01"));
        assert!(is_valid_case_id("A"));
    }

    #[test]
    fn rejects_empty_traversal_and_separators() {
        assert!(!is_valid_case_id(""));
        assert!(!is_valid_case_id("../../foo"));
        assert!(!is_valid_case_id(".."));
        assert!(!is_valid_case_id("."));
        assert!(!is_valid_case_id("a/b"));
        assert!(!is_valid_case_id("a.b"));
        assert!(!is_valid_case_id("a\\b"));
        assert!(!is_valid_case_id("a\0b"));
        assert!(!is_valid_case_id("a b"));
    }
}
