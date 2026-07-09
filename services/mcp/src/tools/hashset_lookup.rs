//! `hashset_lookup` — NSRL/known-good + known-bad hash-set lookup.
//!
//! Autopsy-class hash flagging behind a typed read-only tool: the agent
//! submits file hashes (hex MD5/SHA-1/SHA-256) and the tool reports which
//! operator-provisioned hash sets contain them. Known-bad membership is a
//! triage lead; known-good (NSRL RDS-style reference set) membership lets
//! benign OS/application files be de-prioritized.
//!
//! Set sources, in priority order:
//!   1. Explicit `hashset_paths` refs (`{path, disposition, name?}`).
//!   2. When `hashset_paths` is empty: enumerate `$FINDEVIL_HASHSET_DIR/
//!      known_good/**` and `.../known_bad/**` for files with `.txt` /
//!      `.hashes` (text) or `.db` / `.sqlite` / `.sqlite3` (`SQLite`)
//!      extensions. Disposition comes from the subdirectory name; the set
//!      name is the file stem. A missing env var or directory degrades
//!      honestly: empty `sets_loaded`, every hash `unknown` — never an error.
//!
//! Set formats (container detected by content, not name — a `SQLite` file
//! starts with the 16-byte `SQLite format 3\0` magic; anything else is
//! treated as text):
//!   * **Text** — one hex hash per line, `#` comments and blank lines
//!     ignored, case-insensitive. The file is STREAMED line-by-line against
//!     the (lowercased) query-hash set: NSRL text exports run to multiple
//!     GB and must never be loaded into memory.
//!   * **`SQLite`** — opened read-only + `immutable=1` (never writes a
//!     `-wal`/`-journal` next to the set file). Two schemas are supported,
//!     detected by table introspection: NSRL RDS v3 (`FILE` table with
//!     columns among `md5`/`sha1`/`sha256`) and generic (`hashes` table
//!     with a `hash` column). Lookups are parameterized ONLY; both hex
//!     cases are probed so a BINARY-collated index still serves the query.
//!     An unrecognized schema records `error` on that set's `sets_loaded`
//!     entry and is skipped — it never fails the whole call.
//!
//! HONEST SCOPE (see `agent-config/SOUL.md`): a `known_bad` hash match is a
//! LEAD until corroborated — hash sets can be stale, mislabeled, or
//! over-broad. A `known_good` match means only "present in a reference set";
//! it is NEVER proof a file is benign (NSRL contains dual-use tools, and a
//! benign hash says nothing about how the file was used). `unknown` means
//! only that the sets actually loaded did not contain the hash — it is not
//! evidence of anything. Output is deterministic (no wall-clock): the same
//! input + on-disk sets reproduce the same bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Hard cap on query hashes per call.
const MAX_HASHES: usize = 10_000;

/// Env var naming the default hash-set root used when `hashset_paths`
/// is empty.
const HASHSET_DIR_ENV: &str = "FINDEVIL_HASHSET_DIR";

/// Extensions enumerated under `$FINDEVIL_HASHSET_DIR` subdirectories.
const HASHSET_EXTENSIONS: &[&str] = &["txt", "hashes", "db", "sqlite", "sqlite3"];

/// First 16 bytes of every `SQLite` database file.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Recursion guard for the env-dir walk (symlink-loop protection).
const MAX_WALK_DEPTH: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HashsetLookupInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the lookup.
    pub case_id: String,

    /// Hashes to look up: each must be hex MD5 (32 chars), SHA-1 (40) or
    /// SHA-256 (64). 1 to 10000 entries; normalized to lowercase and
    /// deduplicated before matching.
    pub hashes: Vec<String>,

    /// Explicit hash-set files to check. When empty (the default) the tool
    /// enumerates `$FINDEVIL_HASHSET_DIR/known_good/**` and
    /// `$FINDEVIL_HASHSET_DIR/known_bad/**` instead.
    #[serde(default)]
    pub hashset_paths: Vec<HashsetRef>,
}

/// One explicit hash-set file reference.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HashsetRef {
    /// Path to the hash-set file (text or `SQLite`; detected by content).
    pub path: PathBuf,

    /// Whether a match in this set marks the hash known-good (NSRL-style
    /// reference set) or known-bad (IOC / malware hash list).
    pub disposition: SetDisposition,

    /// Display name for the set. Defaults to the file stem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// Disposition an operator assigns to a whole hash set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SetDisposition {
    KnownGood,
    KnownBad,
}

/// Per-hash lookup verdict. `KnownBad` takes precedence over `KnownGood`
/// when a hash appears in sets of both dispositions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupDisposition {
    KnownGood,
    KnownBad,
    Unknown,
}

/// Detected container/schema of a loaded set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HashsetKind {
    Text,
    SqliteRds,
    SqliteGeneric,
}

/// One row of the lookup result, per unique query hash.
#[derive(Clone, Debug, Serialize)]
pub struct HashLookupRow {
    /// The query hash, normalized to lowercase hex.
    pub hash: String,

    /// `known_bad` if any known-bad set matched; else `known_good` if any
    /// known-good set matched; else `unknown`.
    pub disposition: LookupDisposition,

    /// Names of every set (either disposition) that contained the hash,
    /// sorted.
    pub matched_sets: Vec<String>,
}

/// One entry per hash set the call attempted to load.
#[derive(Clone, Debug, Serialize)]
pub struct HashsetLoaded {
    /// Set display name (explicit `name`, else the file stem).
    pub name: String,

    /// Detected kind. Best-effort (extension-based) when the file could
    /// not be read at all.
    pub kind: HashsetKind,

    /// The operator-assigned disposition of this set.
    pub disposition: SetDisposition,

    /// The set file path.
    pub path: PathBuf,

    /// Why this set could not be (fully) used: unreadable file,
    /// unsupported `SQLite` schema, or a mid-scan read failure. Matches
    /// found before the failure are still reported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct HashsetLookupOutput {
    pub case_id: String,

    /// One row per unique normalized query hash, sorted by hash.
    pub results: Vec<HashLookupRow>,

    /// Every set the call attempted, sorted by name (then path).
    pub sets_loaded: Vec<HashsetLoaded>,

    /// Number of unique normalized hashes checked (duplicates in the
    /// input `hashes` array are deduplicated).
    pub hashes_checked: usize,
}

#[derive(Debug, Error)]
pub enum HashsetLookupError {
    #[error("hashes must contain between 1 and {MAX_HASHES} entries, got {0}")]
    BadHashCount(usize),

    // Deliberately does not echo the offending string: a malformed "hash"
    // is un-vetted caller text and the index + length localize it fine.
    #[error(
        "hashes[{index}] is not a hex MD5 (32), SHA-1 (40) or SHA-256 (64) \
         digest (got {got_len} chars)"
    )]
    InvalidHash { index: usize, got_len: usize },
}

/// Look up file hashes against known-good / known-bad hash sets.
///
/// Set-level failures (missing file, unsupported schema, corrupt DB) are
/// NOT errors: each degrades into that set's `sets_loaded[].error` so a
/// partial hash-set inventory still yields an honest, usable result.
///
/// # Errors
/// * [`HashsetLookupError::BadHashCount`] — `hashes` is empty or has more
///   than 10000 entries.
/// * [`HashsetLookupError::InvalidHash`] — an entry is not a hex
///   MD5/SHA-1/SHA-256 digest.
pub fn hashset_lookup(
    input: &HashsetLookupInput,
) -> Result<HashsetLookupOutput, HashsetLookupError> {
    if input.hashes.is_empty() || input.hashes.len() > MAX_HASHES {
        return Err(HashsetLookupError::BadHashCount(input.hashes.len()));
    }
    let mut queries: BTreeSet<String> = BTreeSet::new();
    for (index, raw) in input.hashes.iter().enumerate() {
        let normalized = normalize_hash(raw).ok_or_else(|| HashsetLookupError::InvalidHash {
            index,
            got_len: raw.chars().count(),
        })?;
        queries.insert(normalized);
    }

    let refs = if input.hashset_paths.is_empty() {
        enumerate_env_sets()
    } else {
        input.hashset_paths.iter().map(ResolvedRef::from).collect()
    };

    // BTreeMap keyed by the normalized hash: iteration order IS the
    // sorted-by-hash output order.
    let mut states: BTreeMap<String, HashState> = queries
        .iter()
        .map(|h| (h.clone(), HashState::default()))
        .collect();

    let mut sets_loaded: Vec<HashsetLoaded> = refs
        .iter()
        .map(|set_ref| probe_set(set_ref, &queries, &mut states))
        .collect();
    sets_loaded.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));

    let results: Vec<HashLookupRow> = states
        .into_iter()
        .map(|(hash, state)| HashLookupRow {
            hash,
            disposition: state.disposition(),
            matched_sets: state.matched_sets.into_iter().collect(),
        })
        .collect();
    let hashes_checked = results.len();

    Ok(HashsetLookupOutput {
        case_id: input.case_id.clone(),
        results,
        sets_loaded,
        hashes_checked,
    })
}

/// Validate one query hash and normalize it to lowercase hex.
/// Accepts exactly 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex chars.
fn normalize_hash(raw: &str) -> Option<String> {
    if !matches!(raw.len(), 32 | 40 | 64) || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.to_ascii_lowercase())
}

/// Match-state accumulator for one query hash.
#[derive(Default)]
struct HashState {
    in_known_bad: bool,
    in_known_good: bool,
    matched_sets: BTreeSet<String>,
}

impl HashState {
    /// `known_bad` wins over `known_good` when both matched.
    const fn disposition(&self) -> LookupDisposition {
        if self.in_known_bad {
            LookupDisposition::KnownBad
        } else if self.in_known_good {
            LookupDisposition::KnownGood
        } else {
            LookupDisposition::Unknown
        }
    }
}

/// A hash-set reference with its display name resolved.
struct ResolvedRef {
    path: PathBuf,
    disposition: SetDisposition,
    name: String,
}

impl From<&HashsetRef> for ResolvedRef {
    fn from(r: &HashsetRef) -> Self {
        Self {
            name: r.name.clone().unwrap_or_else(|| set_name_for(&r.path)),
            path: r.path.clone(),
            disposition: r.disposition,
        }
    }
}

/// Default display name: file stem, then file name, then the whole path.
fn set_name_for(path: &Path) -> String {
    path.file_stem().or_else(|| path.file_name()).map_or_else(
        || path.to_string_lossy().into_owned(),
        |s| s.to_string_lossy().into_owned(),
    )
}

/// Enumerate `$FINDEVIL_HASHSET_DIR/known_good/**` + `.../known_bad/**`.
/// Missing env var / directories yield an empty list (degrade honestly).
fn enumerate_env_sets() -> Vec<ResolvedRef> {
    let Ok(root) = std::env::var(HASHSET_DIR_ENV) else {
        return Vec::new();
    };
    if root.trim().is_empty() {
        return Vec::new();
    }
    let root = PathBuf::from(root);
    let mut refs = Vec::new();
    for (subdir, disposition) in [
        ("known_good", SetDisposition::KnownGood),
        ("known_bad", SetDisposition::KnownBad),
    ] {
        let mut files = Vec::new();
        collect_hashset_files(&root.join(subdir), 0, &mut files);
        files.sort();
        refs.extend(files.into_iter().map(|path| ResolvedRef {
            name: set_name_for(&path),
            disposition,
            path,
        }));
    }
    refs
}

/// Recursive walk collecting files with a recognized hash-set extension.
/// Unreadable directories are skipped; depth is capped so a symlink loop
/// cannot recurse forever.
fn collect_hashset_files(dir: &Path, depth: usize, acc: &mut Vec<PathBuf>) {
    if depth > MAX_WALK_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_hashset_files(&path, depth + 1, acc);
        } else if has_hashset_extension(&path) {
            acc.push(path);
        }
    }
}

fn has_hashset_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            HASHSET_EXTENSIONS
                .iter()
                .any(|allowed| ext.eq_ignore_ascii_case(allowed))
        })
}

enum Container {
    Text,
    Sqlite,
}

/// Content-based container detection: a `SQLite` file starts with the
/// 16-byte magic; anything shorter or different streams as text.
fn detect_container(path: &Path) -> Result<Container, String> {
    let mut file = std::fs::File::open(path).map_err(|e| format!("open failed: {e}"))?;
    let mut magic = [0u8; 16];
    match file.read_exact(&mut magic) {
        Ok(()) if &magic == SQLITE_MAGIC => Ok(Container::Sqlite),
        Ok(()) => Ok(Container::Text),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(Container::Text),
        Err(e) => Err(format!("read failed: {e}")),
    }
}

/// Best-effort kind label for a set that could not be read at all.
fn kind_hint_from_extension(path: &Path) -> HashsetKind {
    let is_sqlite_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            ["db", "sqlite", "sqlite3"]
                .iter()
                .any(|s| ext.eq_ignore_ascii_case(s))
        });
    if is_sqlite_ext {
        HashsetKind::SqliteGeneric
    } else {
        HashsetKind::Text
    }
}

/// Probe one set against the query hashes and fold matches into `states`.
/// Never fails the call: any problem lands in the returned entry's `error`.
fn probe_set(
    set_ref: &ResolvedRef,
    queries: &BTreeSet<String>,
    states: &mut BTreeMap<String, HashState>,
) -> HashsetLoaded {
    let (kind, matches, error) = match detect_container(&set_ref.path) {
        Ok(Container::Sqlite) => probe_sqlite(&set_ref.path, queries),
        Ok(Container::Text) => {
            let (matches, error) = probe_text(&set_ref.path, queries);
            (HashsetKind::Text, matches, error)
        }
        Err(msg) => (
            kind_hint_from_extension(&set_ref.path),
            BTreeSet::new(),
            Some(msg),
        ),
    };
    for hash in &matches {
        if let Some(state) = states.get_mut(hash) {
            match set_ref.disposition {
                SetDisposition::KnownBad => state.in_known_bad = true,
                SetDisposition::KnownGood => state.in_known_good = true,
            }
            state.matched_sets.insert(set_ref.name.clone());
        }
    }
    HashsetLoaded {
        name: set_ref.name.clone(),
        kind,
        disposition: set_ref.disposition,
        path: set_ref.path.clone(),
        error,
    }
}

/// Stream a text hash set line-by-line, checking membership against the
/// query set. Never loads the file into memory (NSRL text exports are
/// GBs); stops early once every query hash has matched. Lines are read
/// as raw bytes and lossily decoded so a stray non-UTF-8 byte cannot
/// abort the scan.
fn probe_text(path: &Path, queries: &BTreeSet<String>) -> (BTreeSet<String>, Option<String>) {
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return (BTreeSet::new(), Some(format!("open failed: {e}"))),
    };
    let mut reader = BufReader::new(file);
    let mut matches = BTreeSet::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => return (matches, Some(format!("read failed: {e}"))),
        }
        let line = String::from_utf8_lossy(&buf);
        let candidate = line.trim();
        if candidate.is_empty() || candidate.starts_with('#') {
            continue;
        }
        let normalized = candidate.to_ascii_lowercase();
        if queries.contains(&normalized) {
            matches.insert(normalized);
            if matches.len() == queries.len() {
                break; // every query hash already matched — stop streaming
            }
        }
    }
    (matches, None)
}

/// Which NSRL RDS `FILE` hash columns exist in this database.
struct RdsColumns {
    md5: bool,
    sha1: bool,
    sha256: bool,
}

enum SqliteSchema {
    Rds(RdsColumns),
    Generic,
    Unsupported,
}

/// Open a `SQLite` hash set read-only and probe the supported schemas.
fn probe_sqlite(
    path: &Path,
    queries: &BTreeSet<String>,
) -> (HashsetKind, BTreeSet<String>, Option<String>) {
    // Read-only + immutable so we never write a -wal/-journal next to the
    // set file, and a stale WAL header can't block the open.
    let uri = format!("file:{}?mode=ro&immutable=1", path.to_string_lossy());
    let conn = match Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            return (
                HashsetKind::SqliteGeneric,
                BTreeSet::new(),
                Some(format!("sqlite open failed: {e}")),
            )
        }
    };
    match detect_sqlite_schema(&conn) {
        Ok(SqliteSchema::Rds(columns)) => {
            let (matches, error) = probe_rds(&conn, queries, &columns);
            (HashsetKind::SqliteRds, matches, error)
        }
        Ok(SqliteSchema::Generic) => {
            let (matches, error) = probe_generic(&conn, queries);
            (HashsetKind::SqliteGeneric, matches, error)
        }
        Ok(SqliteSchema::Unsupported) => (
            HashsetKind::SqliteGeneric,
            BTreeSet::new(),
            Some(
                "unsupported schema: expected an NSRL RDS FILE table \
                 (md5/sha1/sha256 columns) or a generic hashes(hash) table"
                    .to_string(),
            ),
        ),
        Err(e) => (
            HashsetKind::SqliteGeneric,
            BTreeSet::new(),
            Some(format!("schema introspection failed: {e}")),
        ),
    }
}

fn has_table(conn: &Connection, lower_name: &str) -> Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND lower(name)=?1",
        [lower_name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Column names (lowercased) of a table, via the parameterizable
/// `pragma_table_info` table-valued function — no identifier splicing.
fn table_columns_lower(
    conn: &Connection,
    table: &str,
) -> Result<BTreeSet<String>, rusqlite::Error> {
    let mut stmt = conn.prepare("SELECT lower(name) FROM pragma_table_info(?1)")?;
    let rows = stmt.query_map([table], |row| row.get::<_, String>(0))?;
    rows.collect()
}

fn detect_sqlite_schema(conn: &Connection) -> Result<SqliteSchema, rusqlite::Error> {
    // SQLite identifiers are ASCII case-insensitive, so `FILE` in our
    // fixed SQL below resolves however the table was declared.
    if has_table(conn, "file")? {
        let cols = table_columns_lower(conn, "FILE")?;
        let columns = RdsColumns {
            md5: cols.contains("md5"),
            sha1: cols.contains("sha1"),
            sha256: cols.contains("sha256"),
        };
        if columns.md5 || columns.sha1 || columns.sha256 {
            return Ok(SqliteSchema::Rds(columns));
        }
        return Ok(SqliteSchema::Unsupported);
    }
    if has_table(conn, "hashes")? && table_columns_lower(conn, "hashes")?.contains("hash") {
        return Ok(SqliteSchema::Generic);
    }
    Ok(SqliteSchema::Unsupported)
}

/// Parameterized single-hash membership probe. Binds both hex cases so a
/// BINARY-collated index on the column still serves the lookup (NSRL RDS
/// stores uppercase hex; our normalized queries are lowercase).
fn probe_membership(
    conn: &Connection,
    sql: &str,
    hash_lower: &str,
) -> Result<bool, rusqlite::Error> {
    let mut stmt = conn.prepare_cached(sql)?;
    let upper = hash_lower.to_ascii_uppercase();
    let mut rows = stmt.query(rusqlite::params![hash_lower, upper])?;
    Ok(rows.next()?.is_some())
}

/// NSRL RDS v3 probe: choose the `FILE` column by hash length. A hash
/// whose column is absent from this database simply cannot match here.
fn probe_rds(
    conn: &Connection,
    queries: &BTreeSet<String>,
    columns: &RdsColumns,
) -> (BTreeSet<String>, Option<String>) {
    let mut matches = BTreeSet::new();
    for hash in queries {
        // Fixed column identifiers from a literal set — the only dynamic
        // values are the bound hash parameters.
        let sql = match hash.len() {
            32 if columns.md5 => "SELECT 1 FROM FILE WHERE md5 IN (?1, ?2) LIMIT 1",
            40 if columns.sha1 => "SELECT 1 FROM FILE WHERE sha1 IN (?1, ?2) LIMIT 1",
            64 if columns.sha256 => "SELECT 1 FROM FILE WHERE sha256 IN (?1, ?2) LIMIT 1",
            _ => continue,
        };
        match probe_membership(conn, sql, hash) {
            Ok(true) => {
                matches.insert(hash.clone());
            }
            Ok(false) => {}
            Err(e) => return (matches, Some(format!("sqlite query failed: {e}"))),
        }
    }
    (matches, None)
}

/// Generic-schema probe: `hashes(hash)`, any hash length.
fn probe_generic(
    conn: &Connection,
    queries: &BTreeSet<String>,
) -> (BTreeSet<String>, Option<String>) {
    let mut matches = BTreeSet::new();
    for hash in queries {
        let sql = "SELECT 1 FROM hashes WHERE hash IN (?1, ?2) LIMIT 1";
        match probe_membership(conn, sql, hash) {
            Ok(true) => {
                matches.insert(hash.clone());
            }
            Ok(false) => {}
            Err(e) => return (matches, Some(format!("sqlite query failed: {e}"))),
        }
    }
    (matches, None)
}

// ---------------------------------------------------------------------------
// Unit tests. All hash values below are synthetic test fixtures, not
// image-specific literals (evidence-agnostic rule).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Synthetic MD5-length hex (32 chars).
    const MD5_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// Synthetic SHA-1-length hex (40 chars).
    const SHA1_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    /// Synthetic SHA-256-length hex (64 chars).
    const SHA256_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn input_with(hashes: &[&str], hashset_paths: Vec<HashsetRef>) -> HashsetLookupInput {
        HashsetLookupInput {
            case_id: "test-case".to_string(),
            hashes: hashes.iter().map(ToString::to_string).collect(),
            hashset_paths,
        }
    }

    fn text_ref(path: PathBuf, disposition: SetDisposition) -> HashsetRef {
        HashsetRef {
            path,
            disposition,
            name: None,
        }
    }

    #[test]
    fn normalize_hash_accepts_md5_sha1_sha256_and_lowercases() {
        assert_eq!(
            normalize_hash("ABCDEF0123456789ABCDEF0123456789"),
            Some("abcdef0123456789abcdef0123456789".to_string())
        );
        assert_eq!(normalize_hash(SHA1_B), Some(SHA1_B.to_string()));
        assert_eq!(normalize_hash(SHA256_C), Some(SHA256_C.to_string()));
    }

    #[test]
    fn normalize_hash_rejects_wrong_length_and_non_hex() {
        assert_eq!(normalize_hash(""), None);
        assert_eq!(normalize_hash("abc123"), None); // wrong length
        assert_eq!(normalize_hash(&"a".repeat(33)), None); // 33 chars
        assert_eq!(normalize_hash(&"g".repeat(32)), None); // non-hex
        assert_eq!(normalize_hash(&format!("{}Z", &"a".repeat(31))), None);
    }

    #[test]
    fn empty_and_oversized_hash_arrays_are_typed_errors() {
        let err = hashset_lookup(&input_with(&[], vec![])).unwrap_err();
        assert!(matches!(err, HashsetLookupError::BadHashCount(0)));

        let too_many: Vec<String> = (0..=MAX_HASHES).map(|_| MD5_A.to_string()).collect();
        let input = HashsetLookupInput {
            case_id: "test-case".to_string(),
            hashes: too_many,
            hashset_paths: vec![],
        };
        let err = hashset_lookup(&input).unwrap_err();
        assert!(matches!(err, HashsetLookupError::BadHashCount(n) if n == MAX_HASHES + 1));
    }

    #[test]
    fn invalid_hash_is_a_typed_error_with_index() {
        let err = hashset_lookup(&input_with(&[MD5_A, "not-a-hash"], vec![])).unwrap_err();
        match err {
            HashsetLookupError::InvalidHash { index, got_len } => {
                assert_eq!(index, 1);
                assert_eq!(got_len, 10);
            }
            other @ HashsetLookupError::BadHashCount(_) => {
                panic!("expected InvalidHash, got {other:?}")
            }
        }
    }

    #[test]
    fn text_set_streams_comments_blanks_and_case_insensitivity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("iocs.txt");
        std::fs::write(
            &path,
            format!(
                "# synthetic known-bad list\n\n{}\nnot-a-hash-line\n{}\n",
                MD5_A.to_ascii_uppercase(),
                SHA256_C
            ),
        )
        .unwrap();

        let input = input_with(
            &[&MD5_A.to_ascii_uppercase(), SHA1_B],
            vec![text_ref(path, SetDisposition::KnownBad)],
        );
        let out = hashset_lookup(&input).expect("lookup");

        assert_eq!(out.hashes_checked, 2);
        assert_eq!(out.results.len(), 2);
        // Sorted by hash: MD5_A ("aaa…") before SHA1_B ("bbb…").
        assert_eq!(out.results[0].hash, MD5_A);
        assert_eq!(out.results[0].disposition, LookupDisposition::KnownBad);
        assert_eq!(out.results[0].matched_sets, vec!["iocs".to_string()]);
        assert_eq!(out.results[1].hash, SHA1_B);
        assert_eq!(out.results[1].disposition, LookupDisposition::Unknown);
        assert!(out.results[1].matched_sets.is_empty());

        assert_eq!(out.sets_loaded.len(), 1);
        assert_eq!(out.sets_loaded[0].kind, HashsetKind::Text);
        assert_eq!(out.sets_loaded[0].name, "iocs");
        assert!(out.sets_loaded[0].error.is_none());
    }

    #[test]
    fn known_bad_takes_precedence_over_known_good() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let good = tmp.path().join("reference.txt");
        let bad = tmp.path().join("iocs.txt");
        std::fs::write(&good, format!("{MD5_A}\n")).unwrap();
        std::fs::write(&bad, format!("{MD5_A}\n")).unwrap();

        let input = input_with(
            &[MD5_A],
            vec![
                text_ref(good, SetDisposition::KnownGood),
                text_ref(bad, SetDisposition::KnownBad),
            ],
        );
        let out = hashset_lookup(&input).expect("lookup");
        assert_eq!(out.results[0].disposition, LookupDisposition::KnownBad);
        // Both sets still appear in matched_sets, sorted.
        assert_eq!(
            out.results[0].matched_sets,
            vec!["iocs".to_string(), "reference".to_string()]
        );
    }

    #[test]
    fn duplicate_hashes_deduplicate() {
        let out = hashset_lookup(&input_with(
            &[MD5_A, &MD5_A.to_ascii_uppercase(), MD5_A],
            vec![],
        ))
        .expect("lookup");
        assert_eq!(out.hashes_checked, 1);
        assert_eq!(out.results.len(), 1);
    }

    #[test]
    fn missing_set_file_degrades_to_error_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let input = input_with(
            &[MD5_A],
            vec![text_ref(
                tmp.path().join("absent.txt"),
                SetDisposition::KnownBad,
            )],
        );
        let out = hashset_lookup(&input).expect("lookup");
        assert_eq!(out.sets_loaded.len(), 1);
        let entry = &out.sets_loaded[0];
        assert!(entry.error.as_deref().is_some_and(|e| e.contains("open")));
        assert_eq!(out.results[0].disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn sqlite_generic_schema_matches_case_insensitively() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("bad.sqlite");
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE hashes (hash TEXT, set_name TEXT)", [])
            .unwrap();
        // Stored uppercase; the query is normalized lowercase.
        conn.execute(
            "INSERT INTO hashes (hash, set_name) VALUES (?1, 'synthetic')",
            [SHA256_C.to_ascii_uppercase()],
        )
        .unwrap();
        drop(conn);

        let input = input_with(
            &[SHA256_C, MD5_A],
            vec![text_ref(path, SetDisposition::KnownBad)],
        );
        let out = hashset_lookup(&input).expect("lookup");
        assert_eq!(out.sets_loaded[0].kind, HashsetKind::SqliteGeneric);
        assert!(out.sets_loaded[0].error.is_none());
        let sha_row = out.results.iter().find(|r| r.hash == SHA256_C).unwrap();
        assert_eq!(sha_row.disposition, LookupDisposition::KnownBad);
        let md5_row = out.results.iter().find(|r| r.hash == MD5_A).unwrap();
        assert_eq!(md5_row.disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn sqlite_rds_schema_matches_per_column_by_hash_length() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("rds.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, file_name TEXT)",
            [],
        )
        .unwrap();
        // RDS stores uppercase hex.
        conn.execute(
            "INSERT INTO FILE (sha256, sha1, md5, file_name) VALUES (?1, ?2, ?3, 'benign.dll')",
            rusqlite::params![
                SHA256_C.to_ascii_uppercase(),
                SHA1_B.to_ascii_uppercase(),
                MD5_A.to_ascii_uppercase()
            ],
        )
        .unwrap();
        drop(conn);

        let other_md5 = "dddddddddddddddddddddddddddddddd";
        let input = input_with(
            &[MD5_A, SHA1_B, SHA256_C, other_md5],
            vec![text_ref(path, SetDisposition::KnownGood)],
        );
        let out = hashset_lookup(&input).expect("lookup");
        assert_eq!(out.sets_loaded[0].kind, HashsetKind::SqliteRds);
        assert!(out.sets_loaded[0].error.is_none());
        for hash in [MD5_A, SHA1_B, SHA256_C] {
            let row = out.results.iter().find(|r| r.hash == hash).unwrap();
            assert_eq!(
                row.disposition,
                LookupDisposition::KnownGood,
                "hash {hash} should match its RDS column"
            );
        }
        let miss = out.results.iter().find(|r| r.hash == other_md5).unwrap();
        assert_eq!(miss.disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn unsupported_sqlite_schema_degrades_to_error_entry() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("notes.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute("CREATE TABLE notes (id INTEGER, body TEXT)", [])
            .unwrap();
        drop(conn);

        let input = input_with(&[MD5_A], vec![text_ref(path, SetDisposition::KnownBad)]);
        let out = hashset_lookup(&input).expect("lookup must not fail");
        let entry = &out.sets_loaded[0];
        assert!(entry
            .error
            .as_deref()
            .is_some_and(|e| e.contains("unsupported schema")));
        assert_eq!(out.results[0].disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn sqlite_magic_with_corrupt_body_degrades_to_error_entry() {
        // Starts with the SQLite magic so container detection routes it to
        // the SQLite path, but the body is garbage — must degrade, not panic.
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("corrupt.db");
        let mut bytes = SQLITE_MAGIC.to_vec();
        bytes.extend_from_slice(b"garbage body, definitely not sqlite pages");
        std::fs::write(&path, bytes).unwrap();

        let input = input_with(&[MD5_A], vec![text_ref(path, SetDisposition::KnownBad)]);
        let out = hashset_lookup(&input).expect("lookup must not fail");
        assert!(out.sets_loaded[0].error.is_some());
        assert_eq!(out.results[0].disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn env_dir_enumeration_maps_subdirs_to_dispositions() {
        // Serialized via ENV_LOCK: this test and the missing-env test are
        // the only readers/writers of FINDEVIL_HASHSET_DIR in-process.
        let _env_guard = crate::ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().expect("tempdir");
        let good_dir = tmp.path().join("known_good").join("nested");
        let bad_dir = tmp.path().join("known_bad");
        std::fs::create_dir_all(&good_dir).unwrap();
        std::fs::create_dir_all(&bad_dir).unwrap();
        std::fs::write(good_dir.join("reference.hashes"), format!("{SHA1_B}\n")).unwrap();
        std::fs::write(bad_dir.join("iocs.txt"), format!("{MD5_A}\n")).unwrap();
        // Ignored: unrecognized extension.
        std::fs::write(bad_dir.join("readme.md"), "not a hash set\n").unwrap();

        let prev = std::env::var(HASHSET_DIR_ENV).ok();
        std::env::set_var(HASHSET_DIR_ENV, tmp.path());

        let out =
            hashset_lookup(&input_with(&[MD5_A, SHA1_B, SHA256_C], vec![])).expect("env lookup");

        match prev {
            Some(v) => std::env::set_var(HASHSET_DIR_ENV, v),
            None => std::env::remove_var(HASHSET_DIR_ENV),
        }

        assert_eq!(out.sets_loaded.len(), 2, "readme.md must be ignored");
        // Sorted by name: iocs, reference.
        assert_eq!(out.sets_loaded[0].name, "iocs");
        assert_eq!(out.sets_loaded[0].disposition, SetDisposition::KnownBad);
        assert_eq!(out.sets_loaded[1].name, "reference");
        assert_eq!(out.sets_loaded[1].disposition, SetDisposition::KnownGood);

        let md5_row = out.results.iter().find(|r| r.hash == MD5_A).unwrap();
        assert_eq!(md5_row.disposition, LookupDisposition::KnownBad);
        let sha1_row = out.results.iter().find(|r| r.hash == SHA1_B).unwrap();
        assert_eq!(sha1_row.disposition, LookupDisposition::KnownGood);
        let sha256_row = out.results.iter().find(|r| r.hash == SHA256_C).unwrap();
        assert_eq!(sha256_row.disposition, LookupDisposition::Unknown);
    }

    #[test]
    fn missing_env_dir_yields_empty_sets_and_all_unknown() {
        let _env_guard = crate::ENV_LOCK.lock().unwrap();
        let prev = std::env::var(HASHSET_DIR_ENV).ok();
        std::env::remove_var(HASHSET_DIR_ENV);

        let out = hashset_lookup(&input_with(&[MD5_A], vec![])).expect("lookup");

        match prev {
            Some(v) => std::env::set_var(HASHSET_DIR_ENV, v),
            None => std::env::remove_var(HASHSET_DIR_ENV),
        }

        assert!(out.sets_loaded.is_empty());
        assert_eq!(out.hashes_checked, 1);
        assert_eq!(out.results[0].disposition, LookupDisposition::Unknown);
    }
}
