//! Split EWF segment discovery shared by case custody and disk extraction.
//!
//! The operator passes the first segment (`.E01` / `.Ex01`). When sibling
//! segments are visibly present, every fixed subprocess must receive the whole
//! contiguous set in order. A visible gap (for example `.E01` + `.E03`) is a
//! partial image and must fail before any parser can make the run look clean.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
#[derive(Debug)]
pub(super) enum EwfSegmentError {
    SegmentDirectory {
        directory: PathBuf,
        source: io::Error,
    },
    SegmentMetadata {
        path: PathBuf,
        source: io::Error,
    },
    NonRegularSegment(PathBuf),
    MissingSegment {
        missing_segment: PathBuf,
        found_later_segment: PathBuf,
    },
}

impl fmt::Display for EwfSegmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentDirectory { source, .. } => {
                write!(
                    formatter,
                    "could not list split EWF segment directory: {source}"
                )
            }
            Self::SegmentMetadata { source, .. } => {
                write!(
                    formatter,
                    "could not inspect split EWF segment metadata: {source}"
                )
            }
            Self::NonRegularSegment(_) => {
                write!(formatter, "split EWF segment is not a regular file")
            }
            Self::MissingSegment { .. } => {
                write!(
                    formatter,
                    "missing split EWF segment before visible later segment"
                )
            }
        }
    }
}

impl Error for EwfSegmentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::SegmentDirectory { source, .. } | Self::SegmentMetadata { source, .. } => {
                Some(source)
            }
            Self::NonRegularSegment(_) | Self::MissingSegment { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SegmentExtension {
    prefix: String,
    number: u32,
    width: usize,
}

pub(super) fn is_first_ewf_segment(path: &Path) -> bool {
    first_segment_extension(path).is_some()
}

pub(super) fn segment_paths_for_image(image_path: &Path) -> Result<Vec<PathBuf>, EwfSegmentError> {
    let Some(first_ext) = first_segment_extension(image_path) else {
        return Ok(vec![image_path.to_path_buf()]);
    };
    let Some(stem) = image_path.file_stem() else {
        return Ok(vec![image_path.to_path_buf()]);
    };

    let parent = image_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut segments: BTreeMap<u32, PathBuf> = BTreeMap::new();

    let entries = fs::read_dir(parent).map_err(|source| EwfSegmentError::SegmentDirectory {
        directory: parent.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| EwfSegmentError::SegmentDirectory {
            directory: parent.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.file_stem() != Some(stem) {
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        let Some(segment_ext) = parse_segment_extension(ext) else {
            continue;
        };
        if !segment_ext.prefix.eq_ignore_ascii_case(&first_ext.prefix) {
            continue;
        }
        let meta =
            fs::symlink_metadata(&path).map_err(|source| EwfSegmentError::SegmentMetadata {
                path: path.clone(),
                source,
            })?;
        if !meta.file_type().is_file() {
            return Err(EwfSegmentError::NonRegularSegment(path));
        }
        segments.entry(segment_ext.number).or_insert(path);
    }

    segments
        .entry(1)
        .or_insert_with(|| image_path.to_path_buf());
    let max_segment = segments.keys().next_back().copied().unwrap_or(1);
    for number in 1..=max_segment {
        if segments.contains_key(&number) {
            continue;
        }
        let found_later_segment = segments.range((number + 1)..).next().map_or_else(
            || expected_segment_path(image_path, &first_ext, max_segment),
            |(_, path)| path.clone(),
        );
        return Err(EwfSegmentError::MissingSegment {
            missing_segment: expected_segment_path(image_path, &first_ext, number),
            found_later_segment,
        });
    }

    Ok((1..=max_segment)
        .filter_map(|number| {
            if number == 1 {
                Some(image_path.to_path_buf())
            } else {
                segments.get(&number).cloned()
            }
        })
        .collect())
}

fn first_segment_extension(path: &Path) -> Option<SegmentExtension> {
    let ext = path.extension()?.to_str()?;
    let parsed = parse_segment_extension(ext)?;
    (parsed.number == 1).then_some(parsed)
}

fn parse_segment_extension(ext: &str) -> Option<SegmentExtension> {
    let digit_start = ext.find(|c: char| c.is_ascii_digit())?;
    let (prefix, digits) = ext.split_at(digit_start);
    if prefix.is_empty() || digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let prefix_lower = prefix.to_ascii_lowercase();
    if prefix_lower != "e" && prefix_lower != "ex" {
        return None;
    }
    let number = digits.parse::<u32>().ok()?;
    if number == 0 {
        return None;
    }
    Some(SegmentExtension {
        prefix: prefix.to_string(),
        number,
        width: digits.len(),
    })
}

fn expected_segment_path(
    first_segment: &Path,
    first_ext: &SegmentExtension,
    number: u32,
) -> PathBuf {
    let Some(stem) = first_segment.file_stem().and_then(|stem| stem.to_str()) else {
        return first_segment.to_path_buf();
    };
    let filename = format!(
        "{stem}.{}{number:0width$}",
        first_ext.prefix,
        width = first_ext.width
    );
    match first_segment.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(parent) => parent.join(filename),
        None => PathBuf::from(filename),
    }
}

#[cfg(test)]
mod tests {
    use super::{segment_paths_for_image, EwfSegmentError};
    use std::fs;

    #[test]
    fn returns_single_path_for_non_ewf_images() {
        let tmp = tempfile::tempdir().unwrap();
        let raw = tmp.path().join("disk.raw");
        fs::write(&raw, b"raw").unwrap();

        assert_eq!(segment_paths_for_image(&raw).unwrap(), vec![raw]);
    }

    #[test]
    fn discovers_contiguous_split_ewf_segments() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("host.e01");
        let second = tmp.path().join("host.E02");
        fs::write(&first, b"one").unwrap();
        fs::write(&second, b"two").unwrap();

        assert_eq!(
            segment_paths_for_image(&first).unwrap(),
            vec![first, second]
        );
    }

    #[test]
    fn rejects_visible_split_ewf_segment_gaps() {
        let tmp = tempfile::tempdir().unwrap();
        let first = tmp.path().join("host.E01");
        let third = tmp.path().join("host.E03");
        fs::write(&first, b"one").unwrap();
        fs::write(&third, b"three").unwrap();

        let err = segment_paths_for_image(&first).unwrap_err();
        let message = err.to_string();
        assert!(matches!(
            err,
            EwfSegmentError::MissingSegment {
                missing_segment,
                found_later_segment
            } if missing_segment.ends_with("host.E02") && found_later_segment == third
        ));
        assert!(message.contains("missing split EWF segment"));
        assert!(!message.contains(tmp.path().to_string_lossy().as_ref()));
    }
}
