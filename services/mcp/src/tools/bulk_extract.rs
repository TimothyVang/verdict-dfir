//! `bulk_extract` — subprocess wrapper for Simson Garfinkel's
//! `bulk_extractor`.
//!
//! `bulk_extractor` scans a disk image — INCLUDING unallocated space,
//! slack, and deleted regions the filesystem no longer references — for
//! "features": email addresses, RFC-822 message fragments, URLs, domain
//! names, and operator-supplied keyword/regex hits. It reads the raw
//! bytes without consulting the filesystem, so it recovers a deleted
//! email that no longer has a live directory entry — the exact class of
//! "deleted-email / free-space feature recovery" the typed disk parsers
//! (which walk the live filesystem or a carved artifact) cannot see.
//!
//! INSTALL-FIRST: `bulk_extractor` is NOT bundled. Install it from the
//! platform package manager (`apt-get install -y bulk-extractor` /
//! `brew install bulk_extractor`) or build from
//! <https://github.com/simsong/bulk_extractor>. When it is absent this
//! tool DEGRADES: it returns a typed [`BulkExtractOutput`] with
//! `bulk_extractor_available = false` and empty results — a
//! custody-only "not produced by this run" record, never an error and
//! never fabricated output. Every other tool keeps working.
//!
//! DETERMINISM (custody contract / `verify_finding` replay):
//!   * Runs single-threaded (`-j 1`) so scan order is fixed.
//!   * Returned feature rows are sorted in-tool by a stable key
//!     `(feature_type, offset, feature, context)` regardless of the
//!     order `bulk_extractor` emitted them.
//!   * Staged-file paths are recorded RELATIVE to the case directory
//!     (never an absolute `/home/...` path), and each staged feature
//!     file carries a SHA-256 of its exact bytes.
//!   * The captured `bulk_extractor` version is part of the hashed
//!     output body; NO wall-clock value is (`bulk_extractor`'s own
//!     timestamps live only in `report.xml`, which this tool neither
//!     parses nor records).
//!   * The scanner set is constrained to the [`BulkScanner`] allowlist
//!     enum — an operator can never smuggle an arbitrary scanner name
//!     (or a shell fragment) into the argv.
//!   * Keyword/regex inputs come ONLY from typed args (`find_regexes`)
//!     or an operator-configured keyword file (`keyword_file`, or the
//!     `$FINDEVIL_BULK_KEYWORD_FILE` default) — NEVER image-specific
//!     literals baked into this code (the evidence-agnostic gate
//!     enforces that).
//!
//! Binary discovery: `$FINDEVIL_BULK_EXTRACTOR_BIN` first (a name or an
//! explicit path), then a PATH probe for `bulk_extractor`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::tools::argsafe;

const DEFAULT_LIMIT: usize = 10_000;
const STDERR_TAIL_BYTES: usize = 4096;
const DEFAULT_BINARY: &str = "bulk_extractor";
/// Env var naming an operator-maintained keyword/regex file (one entry
/// per line) fed to `bulk_extractor -F`. Evidence-agnostic: the file is
/// operator-supplied, never a literal in this code.
const KEYWORD_FILE_ENV: &str = "FINDEVIL_BULK_KEYWORD_FILE";
const BIN_ENV: &str = "FINDEVIL_BULK_EXTRACTOR_BIN";

/// The forensic feature scanners a `bulk_extract` caller may enable.
///
/// A closed allowlist so an operator can never pass an arbitrary scanner
/// name (or a shell metacharacter) into the `bulk_extractor` argv — the
/// no-free-form-arg guarantee for this parameterized verb. Each variant
/// maps 1:1 to a real `bulk_extractor` scanner name (a valid `-e`
/// argument) via [`BulkScanner::as_str`].
///
/// Note: `email` emits the `email`, `rfc822`, `url`, and `domain`
/// RECORDER files — those are outputs of the email scanner, not
/// separately enable-able scanners, so they are not enum variants; this
/// tool parses every recorder file the enabled scanners produce.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BulkScanner {
    /// Email/RFC-822/URL/domain recovery — the deleted-email surface.
    Email,
    /// Account numbers (credit-card / track2 / SSN-style).
    Accts,
    /// Web/proxy access-log lines.
    Httplogs,
    /// GPS coordinates (EXIF / track logs).
    Gps,
    /// EXIF metadata blocks.
    Exif,
    /// JSON fragments.
    Json,
    /// Ethernet/IP packet-carved network artifacts.
    Net,
    /// ZIP archive members (recovers deleted archived files).
    Zip,
    /// gzip streams.
    Gzip,
    /// PDF text.
    Pdf,
    /// `SQLite` database fragments.
    Sqlite,
    /// Unix login accounting (utmp/wtmp).
    Utmp,
    /// Windows shortcut (LNK) targets.
    Winlnk,
    /// Windows Prefetch execution evidence.
    Winprefetch,
    /// NTFS `$UsnJrnl` change records carved from free space.
    Ntfsusn,
    /// NTFS `$MFT` records carved from free space.
    Ntfsmft,
    /// Carved Windows Event Log (EVTX) records.
    Evtx,
    /// Keyword/regex hits (driven by `find_regexes` / `keyword_file`).
    Find,
}

impl BulkScanner {
    /// Canonical `bulk_extractor` scanner name for the `-e <name>` flag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Accts => "accts",
            Self::Httplogs => "httplogs",
            Self::Gps => "gps",
            Self::Exif => "exif",
            Self::Json => "json",
            Self::Net => "net",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::Pdf => "pdf",
            Self::Sqlite => "sqlite",
            Self::Utmp => "utmp",
            Self::Winlnk => "winlnk",
            Self::Winprefetch => "winprefetch",
            Self::Ntfsusn => "ntfsusn",
            Self::Ntfsmft => "ntfsmft",
            Self::Evtx => "evtx",
            Self::Find => "find",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BulkExtractInput {
    /// Case ID from a prior `case_open` call. The staged feature files
    /// land under this case's `extracted/bulk_extract/` area.
    pub case_id: String,

    /// Path to the raw/E01 disk image (or any byte stream) to scan.
    /// `bulk_extractor` reads the bytes directly, so unallocated space
    /// and deleted regions are in scope.
    pub image_path: PathBuf,

    /// Scanners to enable. Empty → `bulk_extractor`'s own defaults run.
    /// Constrained to the [`BulkScanner`] allowlist.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scanners: Vec<BulkScanner>,

    /// Operator-supplied keyword/regex patterns for the `find` scanner.
    /// Passed via a generated `-F` file, never interpolated into a
    /// shell. NEVER image-specific literals baked into this tool.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub find_regexes: Vec<String>,

    /// Path to an operator-maintained keyword/regex file (one entry per
    /// line) fed to `bulk_extractor -F`. Defaults to
    /// `$FINDEVIL_BULK_KEYWORD_FILE` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyword_file: Option<PathBuf>,

    /// Hard cap on feature rows returned. Default `10_000`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

/// One recovered feature row (a single line of a `bulk_extractor`
/// feature file, comment/header lines excluded).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct BulkFeature {
    /// Feature file this row came from (`email`, `url`, `rfc822`, …).
    pub feature_type: String,
    /// Forensic byte offset (or `bulk_extractor` decoded-path offset,
    /// e.g. `1234-GZIP-56`), verbatim.
    pub offset: String,
    /// The recovered feature text.
    pub feature: String,
    /// Surrounding context `bulk_extractor` captured, verbatim.
    pub context: String,
}

/// One staged `bulk_extractor` output file with an integrity digest.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StagedFeatureFile {
    /// Feature file stem (`email`, `url`, `email_histogram`, …).
    pub feature_type: String,
    /// Path RELATIVE to the case directory — never an absolute
    /// `/home/...` path, so the hashed body stays host-independent.
    pub path: PathBuf,
    /// SHA-256 of the exact bytes `bulk_extractor` wrote.
    pub sha256: String,
    /// Data lines (comment/header lines excluded).
    pub line_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct BulkExtractOutput {
    /// False when `bulk_extractor` is not installed — the degrade
    /// signal. Everything below is empty in that case.
    pub bulk_extractor_available: bool,
    /// `bulk_extractor --version` string (or `unknown`). Part of the
    /// hashed body so a version change is visible to custody replay.
    pub engine_version: String,
    /// Scanner names requested (sorted, deduped). Empty when defaults
    /// were used.
    pub scanners_requested: Vec<String>,
    /// Recovered feature rows, sorted by the stable key and capped at
    /// `limit`.
    pub features: Vec<BulkFeature>,
    /// Total data rows parsed before the `limit` cap.
    pub features_seen: usize,
    /// Every staged output file with its SHA-256 (sorted by name).
    pub staged_files: Vec<StagedFeatureFile>,
    /// Stderr tail (capped). Empty on the degrade path.
    pub stderr_tail: String,
    /// Human-readable provenance note. Carries NO wall-clock value.
    pub note: String,
}

#[derive(Debug, Error)]
pub enum BulkExtractError {
    #[error("evidence image not found: {0}")]
    NotFound(PathBuf),

    #[error("image path is not a regular file: {0}")]
    NotRegular(PathBuf),

    #[error(
        "image filename begins with '-' (would be read as a bulk_extractor flag): {0}; \
         rename or pass it under a directory"
    )]
    DashLeadingImageName(PathBuf),

    #[error("case not found: {0}")]
    CaseNotFound(String),

    #[error("invalid case_id (must match [A-Za-z0-9_-]+, no path separators or '.'/'..'): {0}")]
    InvalidCaseId(String),

    #[error("keyword file not found: {0}")]
    KeywordFileNotFound(PathBuf),

    #[error("find_regexes entry {index} contains an illegal control character (newline/NUL)")]
    InvalidRegex { index: usize },

    #[error("bulk_extractor exited {exit_code}: {stderr}")]
    SubprocessFailed { exit_code: i32, stderr: String },

    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Run `bulk_extractor` over a disk image and return the recovered
/// features plus staged, SHA-256-attested output files.
///
/// # Errors
/// * [`BulkExtractError::NotFound`] / [`BulkExtractError::NotRegular`] —
///   the image path is missing or not a regular file.
/// * [`BulkExtractError::CaseNotFound`] — no case dir for `case_id`.
/// * [`BulkExtractError::KeywordFileNotFound`] — a supplied keyword file
///   does not exist.
/// * [`BulkExtractError::InvalidRegex`] — a `find_regexes` entry carries
///   a newline/NUL that would corrupt the generated `-F` file.
/// * [`BulkExtractError::SubprocessFailed`] — `bulk_extractor` returned
///   non-zero; check `stderr` in the error.
/// * [`BulkExtractError::Io`] — staging/read failure.
///
/// When `bulk_extractor` is not installed the function returns
/// `Ok(unavailable_output())` — a degrade, not an error.
pub fn bulk_extract(input: &BulkExtractInput) -> Result<BulkExtractOutput, BulkExtractError> {
    if !input.image_path.exists() {
        return Err(BulkExtractError::NotFound(input.image_path.clone()));
    }
    if !input.image_path.is_file() {
        return Err(BulkExtractError::NotRegular(input.image_path.clone()));
    }
    // Refuse a dash-leading filename: even with the end-of-options `--`
    // marker (belt and braces), a `-x`-named image is a foot-gun.
    if image_name_is_dash_leading(&input.image_path) {
        return Err(BulkExtractError::DashLeadingImageName(
            input.image_path.clone(),
        ));
    }

    // Degrade-safe: no bulk_extractor on this host → typed "unavailable".
    let Some(binary) = resolve_binary() else {
        return Ok(unavailable_output());
    };

    let case_dir = resolve_case_dir(&input.case_id)?;

    // Deterministic, uuid-free staging path so the recorded
    // (case-relative) path is stable across runs of the same image.
    let stem = sanitize_stem(&input.image_path);
    let staging = case_dir.join("extracted").join("bulk_extract").join(&stem);
    // bulk_extractor refuses a non-empty output dir; re-runs re-derive.
    if staging.exists() {
        std::fs::remove_dir_all(&staging).map_err(|source| BulkExtractError::Io {
            path: staging.clone(),
            source,
        })?;
    }
    create_dir(&staging)?;

    // Resolve the operator keyword sources (args first, then env). A
    // supplied keyword file MUST exist; find_regexes are written to a
    // generated -F file so no regex ever reaches the argv directly.
    let keyword_file = resolve_keyword_file(input)?;
    let generated_find_file = write_find_regexes(&input.find_regexes, &staging)?;

    let scanners_requested = normalize_scanners(&input.scanners);
    let mut find_files: Vec<PathBuf> = Vec::new();
    if let Some(f) = &generated_find_file {
        find_files.push(f.clone());
    }
    if let Some(f) = &keyword_file {
        find_files.push(f.clone());
    }

    let feature_dir = staging.join("out");
    let args = build_bulk_args(
        &feature_dir,
        &input.image_path,
        &input.scanners,
        &find_files,
    );

    // Defense-in-depth: refuse a poisoned $FINDEVIL_BULK_EXTRACTOR_BIN
    // that resolves to a denied binary, and reject NUL-carrying args.
    if let Err(e) = argsafe::guard_spawn(&binary, &args) {
        return Err(BulkExtractError::SubprocessFailed {
            exit_code: -1,
            stderr: e.to_string(),
        });
    }

    let engine_version = capture_version(&binary);

    let proc = match Command::new(&binary).args(&args).output() {
        Ok(proc) => proc,
        // Lost the resolve→spawn race (binary vanished): still degrade.
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(unavailable_output());
        }
        Err(err) => {
            return Err(BulkExtractError::SubprocessFailed {
                exit_code: -1,
                stderr: format!("spawn failed: {err}"),
            });
        }
    };

    // The failure path surfaces raw stderr in the (non-hashed) error
    // message; the SUCCESS path folds stderr_tail into the hashed output
    // body, so scrub the absolute paths we control (case dir, feature
    // dir, image path) to keep two identical runs on different
    // hosts/case-dirs hash-identical for verify_finding replay.
    if !proc.status.success() {
        return Err(BulkExtractError::SubprocessFailed {
            exit_code: proc.status.code().unwrap_or(-1),
            stderr: tail_utf8_lossy(&proc.stderr),
        });
    }
    let stderr_tail = scrub_absolute_paths(
        &tail_utf8_lossy(&proc.stderr),
        &[
            case_dir.as_path(),
            feature_dir.as_path(),
            input.image_path.as_path(),
        ],
    );

    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let (mut features, staged_files) = collect_outputs(&feature_dir, &case_dir)?;
    let features_seen = features.len();
    sort_features(&mut features);
    features.truncate(limit);

    Ok(BulkExtractOutput {
        bulk_extractor_available: true,
        engine_version,
        scanners_requested,
        features,
        features_seen,
        staged_files,
        stderr_tail,
        note: "bulk_extractor scanned the raw image (allocated + unallocated/free space) \
               single-threaded (-j 1); feature rows sorted in-tool and staged files \
               SHA-256-attested for custody replay"
            .to_string(),
    })
}

/// The typed result when `bulk_extractor` is not installed.
fn unavailable_output() -> BulkExtractOutput {
    BulkExtractOutput {
        bulk_extractor_available: false,
        engine_version: String::new(),
        scanners_requested: Vec::new(),
        features: Vec::new(),
        features_seen: 0,
        staged_files: Vec::new(),
        stderr_tail: String::new(),
        note: "bulk_extractor not installed (set $FINDEVIL_BULK_EXTRACTOR_BIN or \
               install bulk-extractor); no features produced by this run"
            .to_string(),
    }
}

/// Build the fixed argv. Pure + unit-tested. Shape:
/// `-j 1 -o <feature_dir> [-e <scanner>]... [-F <find_file>]... <image>`.
#[must_use]
pub fn build_bulk_args(
    feature_dir: &Path,
    image: &Path,
    scanners: &[BulkScanner],
    find_files: &[PathBuf],
) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        // Single-threaded: fixed scan order → deterministic output.
        "-j".into(),
        "1".into(),
        "-o".into(),
        feature_dir.as_os_str().to_os_string(),
    ];
    for scanner in scanners {
        args.push("-e".into());
        args.push(scanner.as_str().into());
    }
    for find_file in find_files {
        args.push("-F".into());
        args.push(find_file.as_os_str().to_os_string());
    }
    // End-of-options marker: everything after `--` is a positional, so a
    // `-`-leading image path can never be reinterpreted as a flag.
    args.push("--".into());
    args.push(image.as_os_str().to_os_string());
    args
}

/// True when the image's final path component begins with `-` (which
/// `bulk_extractor` would try to read as an option). Pure + tested.
#[must_use]
pub fn image_name_is_dash_leading(image: &Path) -> bool {
    image
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| name.starts_with('-'))
}

/// Parse one `bulk_extractor` feature-file line into a [`BulkFeature`].
///
/// Comment/header lines (leading `#`) and blank lines return `None`.
/// The format is tab-separated: `offset\tfeature\tcontext`; a missing
/// context field is tolerated (empty string).
#[must_use]
pub fn parse_feature_line(feature_type: &str, line: &str) -> Option<BulkFeature> {
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut fields = line.splitn(3, '\t');
    let offset = fields.next()?;
    let feature = fields.next()?;
    let context = fields.next().unwrap_or("");
    if offset.is_empty() && feature.is_empty() {
        return None;
    }
    Some(BulkFeature {
        feature_type: feature_type.to_string(),
        offset: offset.to_string(),
        feature: feature.to_string(),
        context: context.to_string(),
    })
}

/// Sort feature rows by the stable custody key
/// `(feature_type, offset, feature, context)`.
///
/// Deterministic regardless of the order `bulk_extractor` emitted them.
/// The offset compares by its leading integer NUMERICALLY (so
/// `9 < 20 < 100`, not lexicographically) via [`compare_offset`].
pub fn sort_features(features: &mut [BulkFeature]) {
    features.sort_by(|a, b| {
        a.feature_type
            .cmp(&b.feature_type)
            .then_with(|| compare_offset(&a.offset, &b.offset))
            .then_with(|| a.feature.cmp(&b.feature))
            .then_with(|| a.context.cmp(&b.context))
    });
}

/// Compare two `bulk_extractor` offsets by their leading integer.
///
/// Falls back to a byte comparison. `bulk_extractor` writes plain byte offsets
/// (`1234`) and decoded-path offsets (`1234-GZIP-56`); both lead with the
/// forensic byte offset, so parse that and compare numerically. When both
/// share the same leading integer (or one has no leading digits) the raw
/// string breaks the tie, keeping the order total and deterministic.
#[must_use]
pub fn compare_offset(a: &str, b: &str) -> std::cmp::Ordering {
    match (leading_u64(a), leading_u64(b)) {
        (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.cmp(b)),
        _ => a.cmp(b),
    }
}

/// The leading base-10 integer of `s`, or `None` when it does not start
/// with a digit.
///
/// Saturates to `u64::MAX` on overflow so a pathologically long digit run
/// still yields a total, deterministic order.
fn leading_u64(s: &str) -> Option<u64> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return None;
    }
    Some(digits.parse::<u64>().unwrap_or(u64::MAX))
}

/// A filesystem-safe, deterministic stem for the staging directory.
///
/// Derived from the image file name at runtime (never a baked-in
/// literal). Keeps ASCII alphanumerics, `.`, `-`, `_`; folds everything
/// else to `_`. Empty input yields `image`.
#[must_use]
pub fn sanitize_stem(image: &Path) -> String {
    let raw = image
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("image");
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "image".to_string()
    } else {
        cleaned
    }
}

/// Sorted, deduped scanner names for the output record.
fn normalize_scanners(scanners: &[BulkScanner]) -> Vec<String> {
    let mut names: Vec<String> = scanners.iter().map(|s| s.as_str().to_string()).collect();
    names.sort();
    names.dedup();
    names
}

/// Resolve the operator keyword file: the explicit arg first, then the
/// `$FINDEVIL_BULK_KEYWORD_FILE` default. A supplied path must exist.
fn resolve_keyword_file(input: &BulkExtractInput) -> Result<Option<PathBuf>, BulkExtractError> {
    let candidate = input.keyword_file.clone().or_else(|| {
        std::env::var(KEYWORD_FILE_ENV)
            .ok()
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    });
    match candidate {
        Some(path) if path.is_file() => Ok(Some(path)),
        Some(path) => Err(BulkExtractError::KeywordFileNotFound(path)),
        None => Ok(None),
    }
}

/// Write operator-supplied `find_regexes` to a generated `-F` file under
/// the staging area. Returns `None` when there are none. Rejects entries
/// carrying a newline/NUL (which would corrupt the one-entry-per-line
/// file or the argv).
fn write_find_regexes(
    regexes: &[String],
    staging: &Path,
) -> Result<Option<PathBuf>, BulkExtractError> {
    if regexes.is_empty() {
        return Ok(None);
    }
    for (index, regex) in regexes.iter().enumerate() {
        if regex.contains('\n') || regex.contains('\r') || regex.contains('\0') {
            return Err(BulkExtractError::InvalidRegex { index });
        }
    }
    let path = staging.join("find_regexes.txt");
    let body = regexes.join("\n");
    std::fs::write(&path, body).map_err(|source| BulkExtractError::Io {
        path: path.clone(),
        source,
    })?;
    Ok(Some(path))
}

/// Enumerate the `bulk_extractor` feature directory: stage every `.txt`
/// output file with a SHA-256, and parse the non-histogram feature files
/// into rows. `report.xml` (which carries wall-clock timestamps) is
/// deliberately neither staged nor parsed, so no clock value enters the
/// hashed body.
fn collect_outputs(
    feature_dir: &Path,
    case_dir: &Path,
) -> Result<(Vec<BulkFeature>, Vec<StagedFeatureFile>), BulkExtractError> {
    let mut features: Vec<BulkFeature> = Vec::new();
    let mut staged: Vec<StagedFeatureFile> = Vec::new();

    // BTreeMap keeps enumeration deterministic by feature file name.
    let mut entries: BTreeMap<String, PathBuf> = BTreeMap::new();
    let read_dir = std::fs::read_dir(feature_dir).map_err(|source| BulkExtractError::Io {
        path: feature_dir.to_path_buf(),
        source,
    })?;
    for entry in read_dir {
        let entry = entry.map_err(|source| BulkExtractError::Io {
            path: feature_dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("txt") {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
            entries.insert(name.to_string(), path);
        }
    }

    for (name, path) in entries {
        let bytes = std::fs::read(&path).map_err(|source| BulkExtractError::Io {
            path: path.clone(),
            source,
        })?;
        let sha256 = sha256_hex(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let feature_type = name.trim_end_matches(".txt").to_string();

        // Histogram files are derivatives of the base feature files; we
        // stage + attest them but do not re-emit their rows as features.
        let is_histogram = feature_type.ends_with("_histogram");
        let mut line_count = 0usize;
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            line_count += 1;
            if !is_histogram {
                if let Some(row) = parse_feature_line(&feature_type, line) {
                    features.push(row);
                }
            }
        }

        let rel = path.strip_prefix(case_dir).unwrap_or(&path).to_path_buf();
        staged.push(StagedFeatureFile {
            feature_type,
            path: rel,
            sha256,
            line_count,
        });
    }

    Ok((features, staged))
}

/// Capture `bulk_extractor --version` (first stdout line, trimmed).
/// `unknown` when the probe fails — this string is part of the hashed
/// body so a silent engine change is visible to replay.
fn capture_version(binary: &Path) -> String {
    match Command::new(binary).arg("--version").output() {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()
            .unwrap_or("")
            .trim()
            .to_string(),
        _ => "unknown".to_string(),
    }
}

/// Resolve the `bulk_extractor` binary: `$FINDEVIL_BULK_EXTRACTOR_BIN`
/// (a name or explicit path) then a PATH probe. `None` = degrade signal.
fn resolve_binary() -> Option<PathBuf> {
    let name = std::env::var(BIN_ENV)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_BINARY.to_string());

    let candidate = PathBuf::from(&name);
    if candidate.components().count() > 1 {
        return candidate.is_file().then_some(candidate);
    }

    let exe = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name
    };
    let path_var = std::env::var("PATH").ok()?;
    for dir in std::env::split_paths(&path_var) {
        let cand = dir.join(&exe);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}

/// Resolve `$FINDEVIL_HOME/cases/<case_id>`.
///
/// `case_id` is VALIDATED before the join: an attacker-influenced value
/// like `../../etc` would otherwise make the caller's `remove_dir_all` /
/// `create_dir` escape the case sandbox. Only `[A-Za-z0-9_-]+` is
/// accepted (which UUID4 case ids satisfy) — no separators, no `.`/`..`.
fn resolve_case_dir(case_id: &str) -> Result<PathBuf, BulkExtractError> {
    if !is_valid_case_id(case_id) {
        return Err(BulkExtractError::InvalidCaseId(case_id.to_string()));
    }
    let dir = findevil_home()
        .ok_or_else(|| BulkExtractError::CaseNotFound(case_id.to_string()))?
        .join("cases")
        .join(case_id);
    if dir.is_dir() {
        Ok(dir)
    } else {
        Err(BulkExtractError::CaseNotFound(case_id.to_string()))
    }
}

/// Re-export shared allowlist (see [`crate::tools::case_id`]).
pub use super::case_id::is_valid_case_id;

/// Replace every absolute path in `roots` (as a substring) with a stable
/// `<redacted-path>` token.
///
/// Keeps host-specific prefixes out of the hashed output body so a
/// `verify_finding` replay stays identical across hosts. Longest paths
/// first, so a nested feature dir is redacted before its case-dir prefix.
/// Pure + tested.
#[must_use]
pub fn scrub_absolute_paths(text: &str, roots: &[&Path]) -> String {
    let mut needles: Vec<String> = roots
        .iter()
        .filter_map(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    needles.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut out = text.to_string();
    for needle in needles {
        out = out.replace(&needle, "<redacted-path>");
    }
    out
}

fn findevil_home() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("FINDEVIL_HOME") {
        if !v.is_empty() {
            return Some(PathBuf::from(v));
        }
    }
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return Some(PathBuf::from(h).join(".findevil"));
        }
    }
    if let Ok(p) = std::env::var("USERPROFILE") {
        if !p.is_empty() {
            return Some(PathBuf::from(p).join(".findevil"));
        }
    }
    None
}

fn create_dir(path: &Path) -> Result<(), BulkExtractError> {
    std::fs::create_dir_all(path).map_err(|source| BulkExtractError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn tail_utf8_lossy(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&bytes[start..]).to_string()
}

// ---------------------------------------------------------------------------
// Unit tests for the pure argv/parse/sort helpers. A real bulk_extractor
// invocation stays opt-in via $FINDEVIL_BULK_EXTRACTOR_BIN + a fixture
// (install-first tool).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_bulk_args_is_single_threaded_and_ordered() {
        let args = build_bulk_args(
            Path::new("/case/out"),
            Path::new("/case/image.dd"),
            &[BulkScanner::Email, BulkScanner::Httplogs],
            &[],
        );
        // -j 1 must lead so scan order is fixed and deterministic.
        assert_eq!(args[0], OsString::from("-j"));
        assert_eq!(args[1], OsString::from("1"));
        assert_eq!(args[2], OsString::from("-o"));
        assert_eq!(args[3], OsString::from("/case/out"));
        assert!(args.contains(&OsString::from("email")));
        assert!(args.contains(&OsString::from("httplogs")));
        // End-of-options `--` marker must appear immediately before the
        // image, so a `-`-leading path can never be read as a flag.
        assert_eq!(args[args.len() - 2], OsString::from("--"));
        // Image is the final positional arg.
        assert_eq!(args.last(), Some(&OsString::from("/case/image.dd")));
    }

    #[test]
    fn dash_leading_image_name_is_detected() {
        assert!(image_name_is_dash_leading(Path::new("/case/-rf.dd")));
        assert!(image_name_is_dash_leading(Path::new("/case/--output.raw")));
        assert!(!image_name_is_dash_leading(Path::new("/case/image.dd")));
        assert!(!image_name_is_dash_leading(Path::new("/-case/image.dd")));
    }

    #[test]
    fn is_valid_case_id_rejects_traversal_and_separators() {
        assert!(is_valid_case_id("cdae1632-1d18-43af-9946-2aff955716a6"));
        assert!(is_valid_case_id("disk_case_01"));
        assert!(!is_valid_case_id(""));
        assert!(!is_valid_case_id("../../foo"));
        assert!(!is_valid_case_id(".."));
        assert!(!is_valid_case_id("a/b"));
        assert!(!is_valid_case_id("a.b"));
        assert!(!is_valid_case_id("a\\b"));
        assert!(!is_valid_case_id("a\0b"));
    }

    #[test]
    fn scrub_absolute_paths_redacts_controlled_prefixes() {
        let case = Path::new("/home/u/.findevil/cases/abc");
        let feat = Path::new("/home/u/.findevil/cases/abc/extracted/bulk_extract/img/out");
        let img = Path::new("/evidence/img.dd");
        let text = "wrote /home/u/.findevil/cases/abc/extracted/bulk_extract/img/out/email.txt \
                    scanning /evidence/img.dd done";
        let scrubbed = scrub_absolute_paths(text, &[case, feat, img]);
        assert!(!scrubbed.contains("/home/u"), "case/feature prefix leaked");
        assert!(!scrubbed.contains("/evidence/img.dd"), "image path leaked");
        assert!(scrubbed.contains("<redacted-path>"));
        // Deterministic: same inputs → same output.
        assert_eq!(scrubbed, scrub_absolute_paths(text, &[case, feat, img]));
    }

    #[test]
    fn build_bulk_args_appends_find_files() {
        let args = build_bulk_args(
            Path::new("/o"),
            Path::new("/img"),
            &[],
            &[PathBuf::from("/case/kw.txt")],
        );
        let joined: Vec<String> = args.iter().map(|a| a.to_string_lossy().into()).collect();
        let f_idx = joined.iter().position(|a| a == "-F").expect("has -F");
        assert_eq!(joined[f_idx + 1], "/case/kw.txt");
    }

    #[test]
    fn scanner_names_map_to_canonical_bulk_extractor_names() {
        assert_eq!(BulkScanner::Email.as_str(), "email");
        assert_eq!(BulkScanner::Ntfsusn.as_str(), "ntfsusn");
        assert_eq!(BulkScanner::Find.as_str(), "find");
    }

    #[test]
    fn parse_feature_line_splits_tab_separated_fields() {
        let row = parse_feature_line("email", "1234\tevil@example.test\tcontext bytes").unwrap();
        assert_eq!(row.feature_type, "email");
        assert_eq!(row.offset, "1234");
        assert_eq!(row.feature, "evil@example.test");
        assert_eq!(row.context, "context bytes");
    }

    #[test]
    fn parse_feature_line_tolerates_missing_context() {
        let row = parse_feature_line("url", "88\thttp://x.test").unwrap();
        assert_eq!(row.context, "");
    }

    #[test]
    fn parse_feature_line_skips_comments_and_blanks() {
        assert!(parse_feature_line("email", "# BULK_EXTRACTOR-Version: 2.0.0").is_none());
        assert!(parse_feature_line("email", "").is_none());
    }

    #[test]
    fn sort_features_orders_offsets_numerically_not_lexically() {
        let mk = |off: &str| BulkFeature {
            feature_type: "email".into(),
            offset: off.into(),
            feature: "x".into(),
            context: String::new(),
        };
        // Lexicographically "100" < "20" < "9"; numerically 9 < 20 < 100.
        let mut rows = vec![mk("100"), mk("9"), mk("20")];
        sort_features(&mut rows);
        assert_eq!(
            rows.iter().map(|r| r.offset.as_str()).collect::<Vec<_>>(),
            vec!["9", "20", "100"]
        );
    }

    #[test]
    fn sort_features_class_then_numeric_offset_and_stable() {
        let mut rows = vec![
            BulkFeature {
                feature_type: "url".into(),
                offset: "9".into(),
                feature: "b".into(),
                context: String::new(),
            },
            BulkFeature {
                feature_type: "email".into(),
                offset: "100".into(),
                feature: "z".into(),
                context: String::new(),
            },
            BulkFeature {
                feature_type: "email".into(),
                offset: "9".into(),
                feature: "a".into(),
                context: String::new(),
            },
        ];
        sort_features(&mut rows);
        // email before url; within email, offset 9 before 100 (numeric).
        assert_eq!(rows[0].feature_type, "email");
        assert_eq!(rows[0].offset, "9");
        assert_eq!(rows[1].feature_type, "email");
        assert_eq!(rows[1].offset, "100");
        assert_eq!(rows[2].feature_type, "url");
    }

    #[test]
    fn compare_offset_handles_decoded_path_offsets() {
        use std::cmp::Ordering;
        // Both lead with 1234 → tie-break on the raw string.
        assert_eq!(
            compare_offset("1234-GZIP-56", "1234-GZIP-78"),
            Ordering::Less
        );
        // Numeric leading compare, not lexical.
        assert_eq!(compare_offset("9", "100"), Ordering::Less);
        assert_eq!(compare_offset("100", "9"), Ordering::Greater);
        // Non-numeric offsets fall back to byte order.
        assert_eq!(compare_offset("abc", "abd"), Ordering::Less);
    }

    #[test]
    fn sanitize_stem_folds_unsafe_characters() {
        assert_eq!(
            sanitize_stem(Path::new("/e/disk image.dd")),
            "disk_image.dd"
        );
        assert_eq!(sanitize_stem(Path::new("/e/a;b|c.raw")), "a_b_c.raw");
    }

    #[test]
    fn unavailable_output_is_degrade_not_error() {
        let out = unavailable_output();
        assert!(!out.bulk_extractor_available);
        assert!(out.features.is_empty());
        assert!(out.staged_files.is_empty());
        assert_eq!(out.engine_version, "");
    }

    #[test]
    fn normalize_scanners_sorts_and_dedupes() {
        let names = normalize_scanners(&[BulkScanner::Net, BulkScanner::Email, BulkScanner::Net]);
        assert_eq!(names, vec!["email".to_string(), "net".to_string()]);
    }
}
