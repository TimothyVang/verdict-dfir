//! Local Unix-socket command API — herdr-style orchestration surface, so an agent
//! (or script) can list/launch/query investigations against a running fleet.
//! Line-delimited JSON: one request object per line, one response per line.
//! Clean-room: models herdr's socket-API behavior; implemented independently.

use crate::fleet::FleetState;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::thread;

pub type Shared = Arc<Mutex<FleetState>>;

/// Handle one request object, returning the response object. Pure w.r.t. I/O
/// (operates on the shared state), so it is unit-testable without a socket.
pub fn handle_command(state: &Shared, req: &Value) -> Value {
    match req.get("cmd").and_then(|c| c.as_str()).unwrap_or("") {
        "ping" => json!({ "ok": true, "reply": "pong" }),
        "list" => {
            let st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let items: Vec<Value> = st
                .entries
                .iter()
                .map(|s| {
                    json!({
                        "dir": s.dir.display().to_string(),
                        "state": format!("{:?}", st.effective_state(s)),
                        "custody": format!("{:?}", s.custody),
                        "records": s.audit_records,
                        "live": st.sessions.contains_key(&s.dir),
                    })
                })
                .collect();
            json!({ "ok": true, "count": items.len(), "investigations": items })
        }
        "launch" => match req.get("evidence").and_then(|e| e.as_str()) {
            Some(ev) => {
                let cases_root = std::env::var("FINDEVIL_HOME")
                    .map(|h| std::path::PathBuf::from(h).join("cases"))
                    .unwrap_or_else(|_| std::env::temp_dir().join("caseforge-fleet"));
                let cmd = std::env::var("CASEFORGE_CMD").unwrap_or_else(|_| "caseforge".to_string());
                let mut st = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                match st.launch_investigation(ev, &cases_root, &cmd) {
                    Ok(()) => json!({ "ok": true, "launched": ev }),
                    Err(e) => json!({ "ok": false, "error": e.to_string() }),
                }
            }
            None => json!({ "ok": false, "error": "missing 'evidence'" }),
        },
        other => json!({ "ok": false, "error": format!("unknown cmd: {other}") }),
    }
}

/// Bind `path` and serve requests on a background thread against `state`.
pub fn serve(path: &Path, state: Shared) -> std::io::Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    // owner-only: a same-user process can still connect, but not other users.
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let state = Arc::clone(&state);
            thread::spawn(move || {
                let _ = handle_client(stream, &state);
            });
        }
    });
    Ok(())
}

fn handle_client(stream: UnixStream, state: &Shared) -> std::io::Result<()> {
    let reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Value>(&line) {
            Ok(req) => handle_command(state, &req),
            Err(e) => json!({ "ok": false, "error": format!("bad json: {e}") }),
        };
        writeln!(writer, "{resp}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::derive_status;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
    }
    fn shared() -> Shared {
        Arc::new(Mutex::new(FleetState::scan(
            &[fixtures().join("sample-run"), fixtures().join("custody-invalid-run")],
            4_000_000_000,
        )))
    }

    #[test]
    fn ping_replies_pong() {
        let s = shared();
        let r = handle_command(&s, &json!({"cmd":"ping"}));
        assert_eq!(r["ok"], json!(true));
        assert_eq!(r["reply"], json!("pong"));
    }

    #[test]
    fn list_returns_investigations() {
        let s = shared();
        let r = handle_command(&s, &json!({"cmd":"list"}));
        assert_eq!(r["count"], json!(2));
        let txt = r.to_string();
        assert!(txt.contains("sample-run"));
        assert!(txt.contains("CustodyInvalid"));
    }

    #[test]
    fn unknown_cmd_errors() {
        let s = shared();
        let r = handle_command(&s, &json!({"cmd":"nope"}));
        assert_eq!(r["ok"], json!(false));
        let _ = derive_status(&fixtures().join("sample-run"), 0);
    }

    #[test]
    fn socket_round_trip() {
        let dir = std::env::temp_dir().join(format!("cf-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("fleet.sock");
        serve(&sock, shared()).unwrap();
        thread::sleep(std::time::Duration::from_millis(150));
        let mut client = UnixStream::connect(&sock).unwrap();
        writeln!(client, "{}", json!({"cmd":"list"})).unwrap();
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains("sample-run"), "resp: {line}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
