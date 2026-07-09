//! `proc_runner` — bounded, process-group-isolated subprocess execution.
//!
//! The long-running exec verbs (`vol_run`, `plaso_parse`) used to call a bare,
//! blocking `std::process::Command::output()`: no timeout and no process-group
//! isolation. A hung `vol`/`plaso` (a wedged plugin, a stuck NFS read, a parser
//! that never returns) blocked the single-threaded MCP server **forever**, and
//! any child processes those tools spawned were left orphaned. This module is the
//! shared runner those tools now go through:
//!
//!   1. **Own process group.** On Unix the child is launched in its own process
//!      group via [`std::os::unix::process::CommandExt::process_group`] (a safe
//!      std builder — this crate is `#![forbid(unsafe_code)]`), so the child's
//!      whole subtree is isolated from the server's group and can be reasoned
//!      about as one unit.
//!   2. **Configurable timeout.** [`run_with_timeout`] bounds the wall-clock the
//!      child may run; [`timeout_from_env`] reads an env override with a default.
//!   3. **Whole-group force-kill + reap on timeout.** When the deadline passes the
//!      runner force-kills the child's **entire process group** (leader plus the
//!      descendants the tool spawned) and reaps the leader, then returns a typed
//!      [`RunError::Timeout`] so the caller surfaces an honest error instead of
//!      wedging or orphaning children.
//!
//! ### How the whole-group reap stays `unsafe`-free, dependency-free, and safe
//!
//! The textbook whole-group kill is `kill(-pgid, SIGKILL)` (a negative PID targets
//! the group). The libc FFI form needs `unsafe` and the `libc`/`nix` crates — both
//! off-limits (`#![forbid(unsafe_code)]`, no new dependency); the `kill -- -<pgid>`
//! coreutil form also trips some job-control supervisors (a negative-PID group
//! signal can take down the whole job). So the runner instead reaps the group by
//! **enumerating the group's members from `/proc` and `SIGKILL`ing each by its own
//! positive PID** via `kill(1)` — same end result (leader + descendants gone), no
//! `unsafe`, no dependency, and no negative-PID group signal. Two safety gates:
//!
//! - It only does this once it **proves via `/proc`** that the child is a real,
//!   DISTINCT group leader (its PGID equals its PID) whose PGID is NOT the
//!   server's own group, so a no-op `setpgid` can never make it target the server.
//! - It only kills PIDs whose PGID equals that verified child group, so an
//!   unrelated process can never be hit.
//!
//! The leader is always `SIGKILL`ed directly too (backstop + non-Unix targets).

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// How often [`run_with_timeout`] polls the child for exit. Small enough that a
/// timeout is detected promptly; large enough that the poll loop is not a busy
/// spin. The actual sleep is capped at the remaining budget so we never overshoot.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Captured result of a bounded child run. Field names mirror
/// [`std::process::Output`] so callers that previously used `Command::output()`
/// need no downstream churn.
#[derive(Debug)]
pub struct RunOutput {
    /// The child's exit status.
    pub status: ExitStatus,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
}

/// Typed failure modes of [`run_with_timeout`].
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    /// The child could not be spawned. The inner [`std::io::Error`] is preserved
    /// so callers can distinguish [`std::io::ErrorKind::NotFound`] (binary
    /// missing) from other spawn failures.
    #[error("spawn failed: {0}")]
    Spawn(std::io::Error),

    /// An I/O error occurred while waiting on or draining the child.
    #[error("io error while running child: {0}")]
    Io(std::io::Error),

    /// The child exceeded its time budget and was force-killed (and reaped).
    #[error("subprocess exceeded its {} s time budget and was killed", .0.as_secs())]
    Timeout(Duration),

    /// An output-draining thread panicked (should be unreachable).
    #[error("output reader thread panicked")]
    ReaderPanicked,
}

/// Resolve a timeout from an environment variable, falling back to `default`.
///
/// The variable must hold a positive integer count of **seconds**; any missing,
/// empty, non-numeric, or zero value falls back to `default`.
#[must_use]
pub fn timeout_from_env(var: &str, default: Duration) -> Duration {
    parse_timeout_secs(std::env::var(var).ok().as_deref(), default)
}

/// Pure parse half of [`timeout_from_env`] (unit-tested without touching env).
fn parse_timeout_secs(raw: Option<&str>, default: Duration) -> Duration {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&secs| secs > 0)
        .map_or(default, Duration::from_secs)
}

/// Run `command` to completion, capturing stdout/stderr, but kill it if it runs
/// longer than `timeout`.
///
/// The child is launched in its own process group (Unix), with stdin set to null
/// and stdout/stderr piped. Both pipes are drained on dedicated threads so a child
/// that emits more than the OS pipe-buffer's worth of output cannot deadlock the
/// wait loop (the same concurrency guarantee `Command::output()` gives, plus the
/// timeout). On timeout the child is `SIGKILL`ed and reaped before returning.
///
/// # Errors
/// * [`RunError::Spawn`] — the child could not be started.
/// * [`RunError::Timeout`] — the child outran `timeout` and was killed.
/// * [`RunError::Io`] — an I/O error while waiting on / draining the child.
/// * [`RunError::ReaderPanicked`] — a drain thread panicked (unreachable).
pub fn run_with_timeout(mut command: Command, timeout: Duration) -> Result<RunOutput, RunError> {
    #[cfg(unix)]
    {
        // Own process group: isolates the child's subtree from the server's group
        // so the timeout teardown (and any operator `kill -- -<pgid>`) acts on the
        // child tree alone. `process_group` is a safe std builder method.
        command.process_group(0);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().map_err(RunError::Spawn)?;

    // Drain both pipes concurrently so a large writer cannot block before exit.
    let stdout = child.stdout.take().expect("stdout piped above");
    let stderr = child.stderr.take().expect("stderr piped above");
    let out_reader = thread::spawn(move || read_to_end(stdout));
    let err_reader = thread::spawn(move || read_to_end(stderr));

    let Some(status) = wait_with_deadline(&mut child, timeout)? else {
        // Deadline passed: force-kill the child's whole process group (leader plus
        // descendants) and reap the leader so the server never blocks and nothing
        // is zombified. Joining the readers closes our pipe ends and lets the drain
        // threads finish.
        kill_child_tree(&mut child);
        let _ = child.wait();
        drop(out_reader.join());
        drop(err_reader.join());
        return Err(RunError::Timeout(timeout));
    };

    let stdout = out_reader.join().map_err(|_| RunError::ReaderPanicked)?;
    let stderr = err_reader.join().map_err(|_| RunError::ReaderPanicked)?;
    Ok(RunOutput {
        status,
        stdout: stdout.map_err(RunError::Io)?,
        stderr: stderr.map_err(RunError::Io)?,
    })
}

/// Poll `child` until it exits or `timeout` elapses. `Ok(Some(status))` on exit,
/// `Ok(None)` on deadline, `Err` on a wait I/O error.
fn wait_with_deadline(
    child: &mut Child,
    timeout: Duration,
) -> Result<Option<ExitStatus>, RunError> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(RunError::Io)? {
            return Ok(Some(status));
        }
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return Ok(None);
        }
        let remaining = timeout - elapsed;
        thread::sleep(POLL_INTERVAL.min(remaining));
    }
}

/// Force-kill the child's whole process group on timeout, then leave the leader
/// for the caller to reap with [`std::process::Child::wait`].
///
/// The child was spawned as its own group leader (`process_group(0)`), so its PID
/// equals its PGID and `kill -KILL -<pgid>` (a negative PID targets the group)
/// tears down the leader AND every descendant — the whole-group kill that
/// [`std::process::Child::kill`] (leader-only) cannot do. Shelling out to `kill(1)`
/// keeps the crate `unsafe`-free and dependency-free. The group signal is issued
/// ONLY when [`child_owns_distinct_group`] proves the child is a real, distinct
/// group leader (guarding against a no-op `setpgid` that would otherwise let the
/// signal reach the server's group); the leader is always `SIGKILL`ed directly too
/// as a backstop and for non-Unix targets.
fn kill_child_tree(child: &mut Child) {
    #[cfg(unix)]
    {
        let pgid = child.id();
        if child_owns_distinct_group(pgid) {
            // Enumerate the group's members from /proc and SIGKILL each by its own
            // positive PID (no negative-PID group signal). Done before reaping the
            // leader so the PGIDs are still live and cannot have been recycled.
            let members = group_member_pids(pgid);
            if !members.is_empty() {
                let mut cmd = Command::new("kill");
                cmd.arg("-KILL");
                for pid in &members {
                    cmd.arg(pid.to_string());
                }
                let _ = cmd
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    // Always SIGKILL the leader directly too: covers non-Unix targets, the degraded
    // path where the group reap was skipped/raced, and any leftover leader.
    let _ = child.kill();
}

/// Every PID currently in process group `pgid`, read from `/proc`. Used to reap a
/// timed-out child's whole tree by individual positive-PID `SIGKILL` (avoiding a
/// negative-PID group signal). Only numeric `/proc/<pid>` entries are considered;
/// any unreadable/exited entry is skipped. The caller has already proven `pgid` is
/// the child's distinct group (not the server's), so every returned PID belongs to
/// the child subtree.
#[cfg(unix)]
fn group_member_pids(pgid: u32) -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| read_pgid(&pid.to_string()) == Some(pgid))
        .collect()
}

/// True when `pgid` is safe to whole-group `SIGKILL`: the process is its OWN group
/// leader (its `/proc` PGID equals its PID, i.e. `process_group(0)` took effect)
/// and that group is NOT this server process's own group. Either check failing
/// (or `/proc` being unreadable) returns false, so the caller falls back to the
/// leader-only kill and never risks signaling the server's group.
#[cfg(unix)]
fn child_owns_distinct_group(pgid: u32) -> bool {
    let own = read_pgid("self");
    let child = read_pgid(&pgid.to_string());
    pgid > 1 && child == Some(pgid) && own != Some(pgid)
}

/// Read the process-group ID (PGID) from `/proc/<who>/stat` (`who` is a PID string
/// or `"self"`). `None` if `/proc` is unavailable or unparsable. The `comm` field
/// is parenthesized and may contain spaces/parens, so the numeric fields are read
/// from after the LAST `)`, where the layout is `state ppid pgrp ...` — making
/// PGID the third whitespace token.
#[cfg(unix)]
fn read_pgid(who: &str) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{who}/stat")).ok()?;
    let after_comm = stat.rsplit_once(')')?.1;
    after_comm.split_whitespace().nth(2)?.parse::<u32>().ok()
}

/// Read a child pipe to end. Runs on its own thread.
fn read_to_end(mut reader: impl Read) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timeout_secs_falls_back_on_bad_or_missing_values() {
        let default = Duration::from_secs(99);
        assert_eq!(parse_timeout_secs(None, default), default);
        assert_eq!(parse_timeout_secs(Some(""), default), default);
        assert_eq!(parse_timeout_secs(Some("   "), default), default);
        assert_eq!(parse_timeout_secs(Some("abc"), default), default);
        // Zero is rejected: a zero-second budget would kill every child instantly.
        assert_eq!(parse_timeout_secs(Some("0"), default), default);
        assert_eq!(parse_timeout_secs(Some("-5"), default), default);
    }

    #[test]
    fn parse_timeout_secs_accepts_positive_integers() {
        let default = Duration::from_secs(99);
        assert_eq!(
            parse_timeout_secs(Some("120"), default),
            Duration::from_secs(120)
        );
        // Surrounding whitespace is tolerated.
        assert_eq!(
            parse_timeout_secs(Some("  90 "), default),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn timeout_from_env_uses_default_for_unset_var() {
        // A var name that is essentially guaranteed unset in the test environment.
        let default = Duration::from_secs(123);
        assert_eq!(
            timeout_from_env("FINDEVIL_PROC_RUNNER_TEST_UNSET_XYZZY", default),
            default
        );
    }

    // The exec-backed tests below rely on standard Unix coreutils. They are
    // gated to Unix because the runner's process-group isolation is Unix-only.
    #[cfg(unix)]
    mod unix {
        use super::*;

        #[test]
        fn runs_fast_command_and_captures_stdout() {
            let mut cmd = Command::new("echo");
            cmd.arg("hello-proc-runner");
            let out = run_with_timeout(cmd, Duration::from_secs(30)).expect("echo runs");
            assert!(out.status.success(), "echo should exit 0");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout).trim(),
                "hello-proc-runner"
            );
        }

        #[test]
        fn propagates_nonzero_exit_status() {
            let out = run_with_timeout(Command::new("false"), Duration::from_secs(30))
                .expect("`false` spawns and exits");
            assert!(!out.status.success(), "`false` exits non-zero");
        }

        #[test]
        fn large_output_does_not_deadlock() {
            // `seq 1 50000` emits well over the ~64 KiB pipe buffer. If the runner
            // did not drain the pipe concurrently, the child would block on write,
            // never exit, and this would (wrongly) time out. A generous timeout
            // means a pass proves the concurrent drain, not a lucky race.
            let mut cmd = Command::new("seq");
            cmd.args(["1", "50000"]);
            let out = run_with_timeout(cmd, Duration::from_secs(60)).expect("seq runs");
            assert!(out.status.success());
            assert!(
                out.stdout.len() > 64 * 1024,
                "expected >64 KiB of output, got {} bytes",
                out.stdout.len()
            );
        }

        #[test]
        fn times_out_and_kills_long_running_child() {
            // `sleep 30` would block the server forever under the old code path.
            let mut cmd = Command::new("sleep");
            cmd.arg("30");
            let start = Instant::now();
            let err = run_with_timeout(cmd, Duration::from_millis(200)).unwrap_err();
            let elapsed = start.elapsed();
            assert!(
                matches!(err, RunError::Timeout(_)),
                "expected Timeout, got {err:?}"
            );
            // The call must return promptly (the child was killed), not after the
            // full 30 s sleep. A few seconds of slack absorbs slow CI scheduling.
            assert!(
                elapsed < Duration::from_secs(10),
                "timeout teardown took too long: {elapsed:?}"
            );
        }

        #[test]
        fn spawned_child_owns_a_distinct_group() {
            // Proves process_group(0) takes effect here: a child launched the way
            // run_with_timeout launches it is its OWN group leader (its /proc PGID
            // equals its PID) and that group is NOT the test runner's group. This
            // is the precondition that lets the timeout path issue a SAFE whole-
            // group kill instead of silently degrading to a leader-only kill.
            let mut cmd = Command::new("sleep");
            cmd.arg("5").process_group(0).stdin(Stdio::null());
            let mut child = cmd.spawn().expect("sleep spawns");
            let pid = child.id();
            let is_distinct = child_owns_distinct_group(pid);
            assert_eq!(
                read_pgid(&pid.to_string()),
                Some(pid),
                "child should lead its own group"
            );
            assert_ne!(
                read_pgid("self"),
                Some(pid),
                "child group must differ from ours"
            );
            assert!(
                is_distinct,
                "child should be a distinct, safe-to-group-kill leader"
            );
            let _ = child.kill();
            let _ = child.wait();
        }

        #[test]
        fn timeout_reaps_whole_process_group_not_just_leader() {
            // Distinguishes a whole-group kill from a leader-only kill. The leader
            // `sh` backgrounds a GRANDCHILD subshell that sleeps then touches a
            // sentinel, and the leader itself sleeps long. We time out almost
            // immediately: a whole-group `kill -KILL -<pgid>` kills the grandchild
            // before its sleep elapses, so the sentinel is NEVER created. A
            // leader-only kill would orphan the grandchild, which would survive its
            // sleep and create the sentinel — failing this assertion.
            let sentinel = std::env::temp_dir().join(format!(
                "findevil-pgkill-{}-{:?}.sentinel",
                std::process::id(),
                thread::current().id()
            ));
            let _ = std::fs::remove_file(&sentinel);
            let script = format!("(sleep 1; touch '{}') & sleep 30", sentinel.display());
            let mut cmd = Command::new("sh");
            cmd.args(["-c", &script]);
            let err = run_with_timeout(cmd, Duration::from_millis(200)).unwrap_err();
            assert!(
                matches!(err, RunError::Timeout(_)),
                "expected Timeout, got {err:?}"
            );

            // Wait well past the grandchild's 1 s sleep. If the group kill worked,
            // the grandchild died at ~200 ms and the sentinel never appears.
            thread::sleep(Duration::from_millis(2000));
            let leaked = sentinel.exists();
            let _ = std::fs::remove_file(&sentinel);
            assert!(
                !leaked,
                "grandchild survived the timeout and wrote {} — group not reaped",
                sentinel.display()
            );
        }

        #[test]
        fn missing_binary_surfaces_spawn_not_found() {
            let cmd = Command::new("definitely-not-a-real-binary-zzz-proc-runner");
            let err = run_with_timeout(cmd, Duration::from_secs(5)).unwrap_err();
            match err {
                RunError::Spawn(e) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
                }
                other => panic!("expected Spawn(NotFound), got {other:?}"),
            }
        }
    }
}
