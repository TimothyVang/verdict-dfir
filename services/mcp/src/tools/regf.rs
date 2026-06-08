//! Self-contained, read-only Windows Registry hive (`regf`) reader.
//!
//! Why this exists: `frnsc-hive` only implements the modern `lh` (hash-leaf)
//! subkey-list cell and panics `unimplemented!()` on the `lf`/`li`/`ri` cells
//! that Windows XP-era hives use; `notatin` won't build on the repo's pinned
//! rustc. This module parses the `regf` format directly — header, `nk`/`vk`
//! cells, all four subkey-list types (`lf`/`lh`/`li`/`ri`), resident and
//! non-resident value data, and `db` big-data values — with full bounds
//! checking and no panics, so a malformed or unusual hive yields a clean
//! error/skip rather than taking the process down.
//!
//! Read-only: the hive bytes are loaded once and never mutated. Cell offsets
//! in the format are relative to the start of the first hive bin at 0x1000.

use std::path::Path;

/// Base of the first hive bin; all cell offsets are relative to it.
const HBIN_BASE: usize = 0x1000;
/// Offset of the key name within an `nk` cell body.
const NK_NAME_OFFSET: usize = 0x4c;
/// Sentinel for "no subkey/value list".
const NO_OFFSET: u32 = 0xffff_ffff;
/// Defensive caps so a corrupt hive can't fan out unboundedly.
const MAX_ENTRIES: usize = 200_000;
const MAX_LIST_DEPTH: usize = 16;
/// Max data bytes a single big-data segment carries.
const DB_SEGMENT_BYTES: usize = 16_344;

#[derive(Debug)]
pub enum RegfError {
    Io(std::io::Error),
    BadMagic,
    Truncated,
}

impl std::fmt::Display for RegfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::BadMagic => write!(f, "not a regf hive (bad magic)"),
            Self::Truncated => write!(f, "hive truncated (header too small)"),
        }
    }
}

impl std::error::Error for RegfError {}

/// Lightweight handle to a key node, identified by its cell offset.
#[derive(Clone, Copy, Debug)]
pub struct Key {
    offset: u32,
}

/// A decoded registry value (raw data; the caller formats by type).
pub struct Value {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// A memory-mapped-equivalent view over a registry hive file.
pub struct Hive {
    data: Vec<u8>,
    root_offset: u32,
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    buf.get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(buf: &[u8], at: usize) -> Option<u64> {
    buf.get(at..at + 8)
        .and_then(|b| b.try_into().ok())
        .map(u64::from_le_bytes)
}

fn read_i32(buf: &[u8], at: usize) -> Option<i32> {
    buf.get(at..at + 4)
        .map(|b| i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn decode_name(bytes: &[u8], ascii: bool) -> String {
    if ascii {
        // KEY_COMP_NAME / value ASCII flag: latin-1 codepoints.
        bytes.iter().map(|&b| b as char).collect()
    } else {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }
}

impl Hive {
    /// Open and validate a hive file.
    ///
    /// # Errors
    /// Returns [`RegfError::Io`] on read failure, [`RegfError::BadMagic`] if
    /// the `regf` signature is absent, or [`RegfError::Truncated`] if the
    /// header is too small to hold the root-cell pointer.
    pub fn open(path: &Path) -> Result<Self, RegfError> {
        let data = std::fs::read(path).map_err(RegfError::Io)?;
        Self::from_bytes(data)
    }

    /// Validate an in-memory hive image.
    ///
    /// # Errors
    /// See [`Hive::open`].
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, RegfError> {
        if data.len() < HBIN_BASE {
            return Err(RegfError::Truncated);
        }
        if data.get(0..4) != Some(b"regf") {
            return Err(RegfError::BadMagic);
        }
        // The root cell offset lives at +0x24 in the base block.
        let root_offset = read_u32(&data, 0x24).ok_or(RegfError::Truncated)?;
        Ok(Self { data, root_offset })
    }

    /// Body of the cell at `cell_offset` (excludes the 4-byte size prefix).
    fn cell(&self, cell_offset: u32) -> Option<&[u8]> {
        if cell_offset == NO_OFFSET {
            return None;
        }
        let abs = HBIN_BASE.checked_add(cell_offset as usize)?;
        let raw_size = read_i32(&self.data, abs)?;
        // Negative size = allocated (in use); positive = free. Use magnitude
        // and clamp to the file end so a bogus size can't read OOB.
        let size = (raw_size.unsigned_abs() as usize).max(4);
        let end = abs.checked_add(size)?.min(self.data.len());
        self.data.get(abs + 4..end)
    }

    fn nk(&self, key: Key) -> Option<&[u8]> {
        let c = self.cell(key.offset)?;
        (c.get(0..2) == Some(b"nk")).then_some(c)
    }

    /// The hive root key.
    #[must_use]
    pub fn root(&self) -> Option<Key> {
        let key = Key {
            offset: self.root_offset,
        };
        self.nk(key).map(|_| key)
    }

    /// Key name (the leaf component).
    #[must_use]
    pub fn key_name(&self, key: Key) -> String {
        let Some(c) = self.nk(key) else {
            return String::new();
        };
        let flags = read_u16(c, 0x02).unwrap_or(0);
        let name_len = read_u16(c, 0x48).unwrap_or(0) as usize;
        c.get(NK_NAME_OFFSET..NK_NAME_OFFSET + name_len)
            .map(|nb| decode_name(nb, flags & 0x0020 != 0))
            .unwrap_or_default()
    }

    /// Key last-write time as a raw Windows FILETIME (100ns ticks since 1601).
    #[must_use]
    pub fn key_timestamp(&self, key: Key) -> u64 {
        self.nk(key).and_then(|c| read_u64(c, 0x04)).unwrap_or(0)
    }

    /// Direct child keys (resolves `lf`/`lh`/`li`/`ri` subkey lists).
    #[must_use]
    pub fn subkeys(&self, key: Key) -> Vec<Key> {
        let Some(c) = self.nk(key) else {
            return Vec::new();
        };
        let count = read_u32(c, 0x14).unwrap_or(0);
        let list_off = read_u32(c, 0x1c).unwrap_or(NO_OFFSET);
        if count == 0 || list_off == NO_OFFSET {
            return Vec::new();
        }
        let mut out = Vec::new();
        self.collect_subkeys(list_off, &mut out, 0);
        out
    }

    fn collect_subkeys(&self, list_off: u32, out: &mut Vec<Key>, depth: usize) {
        if depth > MAX_LIST_DEPTH || out.len() >= MAX_ENTRIES {
            return;
        }
        let Some(c) = self.cell(list_off) else {
            return;
        };
        let count = read_u16(c, 0x02).unwrap_or(0) as usize;
        match c.get(0..2) {
            // lf/lh: 8-byte elements (u32 nk offset + u32 hash/hint).
            Some(b"lf" | b"lh") => {
                for i in 0..count {
                    if out.len() >= MAX_ENTRIES {
                        return;
                    }
                    if let Some(off) = read_u32(c, 0x04 + i * 8) {
                        self.push_if_nk(off, out);
                    }
                }
            }
            // li: 4-byte elements (u32 nk offset).
            Some(b"li") => {
                for i in 0..count {
                    if out.len() >= MAX_ENTRIES {
                        return;
                    }
                    if let Some(off) = read_u32(c, 0x04 + i * 4) {
                        self.push_if_nk(off, out);
                    }
                }
            }
            // ri: 4-byte elements pointing at further subkey lists — recurse.
            Some(b"ri") => {
                for i in 0..count {
                    if let Some(sub) = read_u32(c, 0x04 + i * 4) {
                        self.collect_subkeys(sub, out, depth + 1);
                    }
                }
            }
            _ => {}
        }
    }

    fn push_if_nk(&self, off: u32, out: &mut Vec<Key>) {
        if self.cell(off).and_then(|c| c.get(0..2)) == Some(b"nk") {
            out.push(Key { offset: off });
        }
    }

    /// Find a direct child key by name (case-insensitive).
    #[must_use]
    pub fn subkey(&self, key: Key, name: &str) -> Option<Key> {
        let target = name.to_ascii_lowercase();
        self.subkeys(key)
            .into_iter()
            .find(|k| self.key_name(*k).to_ascii_lowercase() == target)
    }

    /// Resolve a `\\`-separated key path relative to the hive root.
    #[must_use]
    pub fn find(&self, path: &str) -> Option<Key> {
        let mut cur = self.root()?;
        for part in path.split('\\').filter(|s| !s.is_empty()) {
            cur = self.subkey(cur, part)?;
        }
        Some(cur)
    }

    /// All values directly attached to `key`.
    #[must_use]
    pub fn values(&self, key: Key) -> Vec<Value> {
        let Some(c) = self.nk(key) else {
            return Vec::new();
        };
        let count = read_u32(c, 0x24).unwrap_or(0) as usize;
        let list_off = read_u32(c, 0x28).unwrap_or(NO_OFFSET);
        if count == 0 || list_off == NO_OFFSET {
            return Vec::new();
        }
        let Some(list) = self.cell(list_off) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..count {
            if out.len() >= MAX_ENTRIES {
                break;
            }
            if let Some(vk_off) = read_u32(list, i * 4) {
                if let Some(v) = self.value_at(vk_off) {
                    out.push(v);
                }
            }
        }
        out
    }

    fn value_at(&self, vk_off: u32) -> Option<Value> {
        let c = self.cell(vk_off)?;
        if c.get(0..2) != Some(b"vk") {
            return None;
        }
        let name_len = read_u16(c, 0x02)? as usize;
        let data_size_raw = read_u32(c, 0x04)?;
        let data_offset = read_u32(c, 0x08)?;
        let value_type = read_u32(c, 0x0c)?;
        let flags = read_u16(c, 0x10).unwrap_or(0);
        let name = if name_len == 0 {
            String::new() // the key's default value
        } else {
            c.get(0x14..0x14 + name_len)
                .map(|nb| decode_name(nb, flags & 0x0001 != 0))
                .unwrap_or_default()
        };
        let resident = data_size_raw & 0x8000_0000 != 0;
        let data_size = (data_size_raw & 0x7fff_ffff) as usize;
        let data = if resident {
            // Resident data lives in the 4-byte data-offset field itself.
            c.get(0x08..0x08 + data_size.min(4))
                .map(<[u8]>::to_vec)
                .unwrap_or_default()
        } else {
            self.read_data(data_offset, data_size)
        };
        Some(Value {
            name,
            value_type,
            data,
        })
    }

    /// Read `size` bytes of value data, following a `db` big-data record when
    /// present (large values split across multiple cells).
    fn read_data(&self, data_offset: u32, size: usize) -> Vec<u8> {
        let Some(cell) = self.cell(data_offset) else {
            return Vec::new();
        };
        if cell.get(0..2) == Some(b"db") {
            let seg_count = read_u16(cell, 0x02).unwrap_or(0) as usize;
            let Some(seg_list_off) = read_u32(cell, 0x04) else {
                return Vec::new();
            };
            let Some(seg_list) = self.cell(seg_list_off) else {
                return Vec::new();
            };
            let mut out = Vec::with_capacity(size.min(1 << 20));
            for i in 0..seg_count {
                if out.len() >= size {
                    break;
                }
                if let Some(seg_off) = read_u32(seg_list, i * 4) {
                    if let Some(seg) = self.cell(seg_off) {
                        let take = seg.len().min(DB_SEGMENT_BYTES);
                        out.extend_from_slice(&seg[..take]);
                    }
                }
            }
            out.truncate(size);
            out
        } else {
            let take = size.min(cell.len());
            cell[..take].to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host iteration harness: point at a real hive via env and dump a key.
    // Skipped in normal CI (no hive committed). Example:
    //   FINDEVIL_TEST_HIVE=tmp/xptest/SYSTEM.hive FINDEVIL_TEST_KEY='Select' \
    //   cargo test -p findevil-mcp regf_dump -- --nocapture --ignored
    #[test]
    #[ignore = "needs a real hive via FINDEVIL_TEST_HIVE"]
    fn regf_dump() {
        let path = std::env::var("FINDEVIL_TEST_HIVE").expect("set FINDEVIL_TEST_HIVE");
        let key_path = std::env::var("FINDEVIL_TEST_KEY").unwrap_or_default();
        let hive = Hive::open(Path::new(&path)).expect("open hive");
        let root = hive.root().expect("root nk");
        eprintln!("root name: {:?}", hive.key_name(root));
        let key = hive.find(&key_path.replace('/', "\\")).expect("find key");
        eprintln!("key: {key_path}  ts={}", hive.key_timestamp(key));
        eprintln!("subkeys:");
        for k in hive.subkeys(key) {
            eprintln!("  - {}", hive.key_name(k));
        }
        eprintln!("values:");
        for v in hive.values(key) {
            eprintln!(
                "  - {} (type {}) {} bytes",
                v.name,
                v.value_type,
                v.data.len()
            );
        }
    }
}
