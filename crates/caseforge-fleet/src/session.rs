//! Live session capture: spawn a command in a PTY and stream its output into a
//! scrollback buffer on a background thread. This is what "attach to a running
//! investigation" reads from. Kept generic + testable with any process.

use anyhow::Result;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct Session {
    output: Arc<Mutex<String>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

impl Session {
    /// Spawn `program args` in a fresh PTY; a reader thread appends its output.
    pub fn spawn(program: &str, args: &[String]) -> Result<Session> {
        let pty = native_pty_system().openpty(PtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut cmd = CommandBuilder::new(program);
        cmd.args(args);
        let child = pty.slave.spawn_command(cmd)?;
        drop(pty.slave);
        let mut reader = pty.master.try_clone_reader()?;
        // keep the master alive for the life of the reader thread
        let output = Arc::new(Mutex::new(String::new()));
        let sink = Arc::clone(&output);
        thread::spawn(move || {
            let _keep = pty.master;
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut g) = sink.lock() {
                            g.push_str(&String::from_utf8_lossy(&buf[..n]));
                            // bound the scrollback: keep the last ~64 KiB
                            const MAX: usize = 64 * 1024;
                            if g.len() > MAX {
                                let mut cut = g.len() - MAX;
                                while !g.is_char_boundary(cut) {
                                    cut += 1;
                                }
                                *g = g[cut..].to_string();
                            }
                        }
                    }
                }
            }
        });
        Ok(Session { output, child })
    }

    /// The last `max_lines` lines of captured output (ANSI stripped for display).
    pub fn snapshot_tail(&self, max_lines: usize) -> Vec<String> {
        let g = self.output.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let stripped = strip_ansi(&g);
        let lines: Vec<&str> = stripped.lines().collect();
        let start = lines.len().saturating_sub(max_lines);
        lines[start..].iter().map(|s| s.to_string()).collect()
    }

    #[allow(dead_code)] // liveness check for the live-refresh slice
    pub fn is_running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Minimal CSI/SGR stripper for display of captured terminal output.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn captures_process_output() {
        let mut s = Session::spawn("sh", &["-c".into(), "printf 'alpha\\nbeta\\n'".into()]).unwrap();
        thread::sleep(Duration::from_millis(400));
        let tail = s.snapshot_tail(10).join("\n");
        assert!(tail.contains("alpha"), "got: {tail:?}");
        assert!(tail.contains("beta"));
        std::thread::sleep(Duration::from_millis(300));
        assert!(!s.is_running(), "exited PTY child detected");
    }

    #[test]
    fn strip_ansi_removes_escapes() {
        assert_eq!(strip_ansi("\x1b[38;2;1;2;3mhi\x1b[0m"), "hi");
        assert_eq!(strip_ansi("a\x1b[Kb"), "ab");
    }
}
