//! Shared `case_id` path-segment validation.
//!
//! Every tool that joins `case_id` into `$FINDEVIL_HOME/cases/<case_id>`
//! (and especially any that then `create_dir` / `remove_dir_all` under it)
//! must call [`is_valid_case_id`] first. Without this, a value like
//! `../../etc` escapes the case sandbox.
//!
//! UUID4 case ids from `case_open` satisfy the allowlist.

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
