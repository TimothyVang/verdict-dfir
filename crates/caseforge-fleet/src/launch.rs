//! Launch primitive: spawn an investigation as a child process. The fleet points
//! this at `caseforge investigate <evidence> ...`; the resulting run dir is then
//! tracked by status::derive_status. Kept minimal + injectable so it is testable
//! without the real caseforge/verdict binary.

use std::process::{Child, Command, Stdio};

#[allow(dead_code)] // process-spawn primitive (non-PTY launch path)
/// Spawn `program` with `args`, detached from our stdio (the fleet renders status
/// from the run dir, not the child's stdout). Returns the live child handle.
pub fn spawn(program: &str, args: &[String]) -> std::io::Result<Child> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Command to open the single-case viewer (the TS caseforge-tui) for a run dir.
pub fn viewer_command(cmd: &str, dir: &std::path::Path) -> (String, Vec<String>) {
    (cmd.to_string(), vec!["tui".to_string(), dir.display().to_string()])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawn_runs_a_process() {
        let mut child = spawn("sh", &["-c".into(), "exit 0".into()]).expect("spawn");
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn viewer_command_shape() {
        let (c, a) = viewer_command("caseforge", std::path::Path::new("/runs/x"));
        assert_eq!(c, "caseforge");
        assert_eq!(a, vec!["tui".to_string(), "/runs/x".to_string()]);
    }

}
