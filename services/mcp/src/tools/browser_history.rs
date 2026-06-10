//! `browser_history` — read visited URLs from an offline browser history
//! `SQLite` database (Chrome/Edge `History`, Firefox `places.sqlite`).
//!
//! Pool B exfil + general triage surface: a downloaded-payload URL, a
//! credential-phishing visit, or a C2 panel opened in a browser all land
//! here. The tool reads the DB **read-only** (and `immutable=1`, so it never
//! touches the evidence's `-wal`/`-journal`) and emits a typed, browser-
//! agnostic row shape.
//!
//! Timestamps are normalized to UTC ISO-8601Z from each browser's native
//! epoch: Chrome/`Chromium` store `last_visit_time` as **`WebKit` microseconds
//! since 1601-01-01 UTC**; Firefox stores `last_visit_date` as **microseconds
//! since the Unix epoch (1970)**.
//!
//! HONEST SCOPE (see `agent-config/SOUL.md`): a history row CONFIRMS that a URL
//! *was recorded as visited* at time T — a browser-artifact fact. It does NOT
//! assert the user *ran* anything (no execution token), so a single
//! `browser_history` Finding is a legitimate CONFIRMED browser fact and never
//! trips the >=2-artifact-class execution rule. Intent ("this is a malware
//! stager") is a separate `hypothesis:`-prefixed layer.

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `WebKit`/Chrome epoch (1601-01-01) to Unix epoch (1970-01-01), in seconds.
const WEBKIT_UNIX_OFFSET_SECS: i64 = 11_644_473_600;
const DEFAULT_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BrowserHistoryInput {
    /// Case ID from a prior `case_open` call. Accepted for audit-log
    /// correlation; not consumed by the parser.
    pub case_id: String,

    /// Path to the history `SQLite` database: a Chrome/Edge `History` file
    /// (`.../User Data/Default/History`) or a Firefox `places.sqlite`.
    /// Pass the file extracted from the mounted image, not a live profile.
    pub history_path: PathBuf,

    /// Hard cap on rows returned, highest `last_visit_time` first.
    /// Default 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserHistoryRow {
    /// The visited URL.
    pub url: String,

    /// Page title, when the browser recorded one.
    pub title: Option<String>,

    /// Last-visit time as UTC ISO-8601Z, or None when the stored timestamp
    /// is zero/unparseable (a row with no recorded visit time).
    pub last_visit_time_iso: Option<String>,

    /// Number of recorded visits to this URL.
    pub visit_count: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BrowserHistoryOutput {
    /// Which browser family the schema matched: `chrome` or `firefox`.
    pub browser_family: String,
    pub rows: Vec<BrowserHistoryRow>,
    pub rows_seen: usize,
}

#[derive(Debug, Error)]
pub enum BrowserHistoryError {
    #[error("browser history database not found: {0}")]
    NotFound(PathBuf),

    #[error("browser history database unreadable {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error("browser history parse failed for {path}: {source}")]
    ParseFailed {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },

    #[error(
        "{0} is not a recognized browser history database \
         (no Chrome urls/visits or Firefox moz_places table)"
    )]
    UnknownSchema(PathBuf),
}

/// Cheap pre-flight: the path looks like a browser history database.
///
/// Matches the canonical base names (`History`, `places.sqlite`) and any
/// `.sqlite` file. The parser is the source of truth on whether the file is
/// genuinely a history DB.
#[must_use]
pub fn path_looks_like_browser_history(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("sqlite"))
    {
        return true;
    }
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        "history" | "places.sqlite"
    )
}

/// Read visited URLs from an offline browser history database.
///
/// # Errors
/// * [`BrowserHistoryError::NotFound`] — the file does not exist.
/// * [`BrowserHistoryError::Unreadable`] — exists but cannot be opened.
/// * [`BrowserHistoryError::ParseFailed`] — opened but a query failed
///   (corrupt DB / unexpected column shape).
/// * [`BrowserHistoryError::UnknownSchema`] — a valid `SQLite` file that is
///   neither a Chrome nor a Firefox history database.
pub fn browser_history(
    input: &BrowserHistoryInput,
) -> Result<BrowserHistoryOutput, BrowserHistoryError> {
    let path = &input.history_path;
    if !path.is_file() {
        return Err(BrowserHistoryError::NotFound(path.clone()));
    }
    // Read-only + immutable so we never write a -wal/-journal next to the
    // evidence file, and a stale WAL header can't block the open.
    let uri = format!("file:{}?immutable=1", path.to_string_lossy());
    let conn = Connection::open_with_flags(
        &uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .map_err(|source| BrowserHistoryError::Unreadable {
        path: path.clone(),
        source,
    })?;

    let limit = input.limit.unwrap_or(DEFAULT_LIMIT);
    let family = detect_family(&conn, path)?;
    let rows = match family {
        Family::Chrome => read_chrome(&conn, path, limit)?,
        Family::Firefox => read_firefox(&conn, path, limit)?,
    };
    Ok(BrowserHistoryOutput {
        browser_family: family.as_str().to_string(),
        rows_seen: rows.len(),
        rows,
    })
}

enum Family {
    Chrome,
    Firefox,
}

impl Family {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Firefox => "firefox",
        }
    }
}

fn has_table(conn: &Connection, name: &str) -> Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

fn detect_family(conn: &Connection, path: &Path) -> Result<Family, BrowserHistoryError> {
    let map_err = |source| BrowserHistoryError::ParseFailed {
        path: path.to_path_buf(),
        source,
    };
    if has_table(conn, "urls").map_err(map_err)? && has_table(conn, "visits").map_err(map_err)? {
        return Ok(Family::Chrome);
    }
    if has_table(conn, "moz_places").map_err(map_err)? {
        return Ok(Family::Firefox);
    }
    Err(BrowserHistoryError::UnknownSchema(path.to_path_buf()))
}

/// `LIMIT` accepts an `i64`; a `usize` past `i64::MAX` is clamped (no real
/// history DB has that many rows, and a smaller bound would silently truncate).
fn limit_as_i64(limit: usize) -> i64 {
    i64::try_from(limit).unwrap_or(i64::MAX)
}

fn read_chrome(
    conn: &Connection,
    path: &Path,
    limit: usize,
) -> Result<Vec<BrowserHistoryRow>, BrowserHistoryError> {
    let map_err = |source| BrowserHistoryError::ParseFailed {
        path: path.to_path_buf(),
        source,
    };
    let mut stmt = conn
        .prepare(
            "SELECT url, title, visit_count, last_visit_time \
             FROM urls ORDER BY last_visit_time DESC LIMIT ?1",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let webkit_micros: i64 = row.get(3)?;
            Ok(BrowserHistoryRow {
                url: row.get(0)?,
                title: row.get::<_, Option<String>>(1)?,
                visit_count: row.get(2)?,
                last_visit_time_iso: webkit_micros_to_iso(webkit_micros),
            })
        })
        .map_err(map_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_err)?;
    Ok(rows)
}

fn read_firefox(
    conn: &Connection,
    path: &Path,
    limit: usize,
) -> Result<Vec<BrowserHistoryRow>, BrowserHistoryError> {
    let map_err = |source| BrowserHistoryError::ParseFailed {
        path: path.to_path_buf(),
        source,
    };
    let mut stmt = conn
        .prepare(
            "SELECT url, title, visit_count, last_visit_date \
             FROM moz_places ORDER BY last_visit_date DESC LIMIT ?1",
        )
        .map_err(map_err)?;
    let rows = stmt
        .query_map([limit_as_i64(limit)], |row| {
            let unix_micros: Option<i64> = row.get(3)?;
            Ok(BrowserHistoryRow {
                url: row.get(0)?,
                title: row.get::<_, Option<String>>(1)?,
                visit_count: row.get(2)?,
                last_visit_time_iso: unix_micros.and_then(unix_micros_to_iso),
            })
        })
        .map_err(map_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_err)?;
    Ok(rows)
}

/// `WebKit` microseconds (since 1601) -> UTC ISO-8601Z. Zero/negative -> None.
fn webkit_micros_to_iso(webkit_micros: i64) -> Option<String> {
    if webkit_micros <= 0 {
        return None;
    }
    let unix_micros = webkit_micros - WEBKIT_UNIX_OFFSET_SECS * 1_000_000;
    unix_micros_to_iso(unix_micros)
}

/// Unix microseconds (since 1970) -> UTC ISO-8601Z. Zero/negative -> None.
fn unix_micros_to_iso(unix_micros: i64) -> Option<String> {
    if unix_micros <= 0 {
        return None;
    }
    let secs = unix_micros.div_euclid(1_000_000);
    let nanos = u32::try_from(unix_micros.rem_euclid(1_000_000) * 1_000).unwrap_or(0);
    chrono::DateTime::from_timestamp(secs, nanos)
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webkit_epoch_converts_to_known_instant() {
        // The `WebKit` value for the Unix epoch is the offset itself; +1s lands
        // one second past 1970-01-01.
        let unix_epoch_in_webkit = WEBKIT_UNIX_OFFSET_SECS * 1_000_000;
        assert_eq!(
            webkit_micros_to_iso(unix_epoch_in_webkit + 1_000_000),
            Some("1970-01-01T00:00:01Z".to_string())
        );
    }

    #[test]
    fn firefox_unix_micros_converts() {
        // 2021-01-01T00:00:00Z = 1609459200 s.
        assert_eq!(
            unix_micros_to_iso(1_609_459_200 * 1_000_000),
            Some("2021-01-01T00:00:00Z".to_string())
        );
    }

    #[test]
    fn zero_timestamps_are_none() {
        assert_eq!(webkit_micros_to_iso(0), None);
        assert_eq!(unix_micros_to_iso(0), None);
    }

    #[test]
    fn path_predicate_matches_history_dbs() {
        assert!(path_looks_like_browser_history(Path::new("History")));
        assert!(path_looks_like_browser_history(Path::new("places.sqlite")));
        assert!(path_looks_like_browser_history(Path::new("x.sqlite")));
        assert!(!path_looks_like_browser_history(Path::new("evil.evtx")));
        assert!(!path_looks_like_browser_history(Path::new("SOFTWARE")));
    }
}
