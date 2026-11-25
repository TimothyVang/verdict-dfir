//! Reattach client — connect to a running fleet's socket from any terminal and
//! render its live state (herdr's detach/reattach model). The server keeps running
//! when this client detaches. Read-only view; control still goes via the socket API.

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::{cursor, execute};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};
use serde_json::Value;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const LILAC: Color = Color::Rgb(184, 168, 255);
const SEAFOAM: Color = Color::Rgb(115, 217, 194);
const BUTTER: Color = Color::Rgb(255, 215, 106);
const COBALT: Color = Color::Rgb(120, 140, 255);
const CORAL: Color = Color::Rgb(255, 98, 87);

pub struct RemoteRow {
    pub dir: String,
    pub state: String,
    pub custody: String,
    pub records: u64,
    pub live: bool,
}

pub fn parse_list(resp: &Value) -> Vec<RemoteRow> {
    resp.get("investigations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|e| RemoteRow {
                    dir: e.get("dir").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    state: e.get("state").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    custody: e.get("custody").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                    records: e.get("records").and_then(|v| v.as_u64()).unwrap_or(0),
                    live: e.get("live").and_then(|v| v.as_bool()).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn state_color(s: &str) -> Color {
    match s {
        "Blocked" => CORAL,
        "Working" => BUTTER,
        "Done" => COBALT,
        _ => Color::DarkGray,
    }
}
fn custody_label(c: &str) -> &str {
    match c {
        "Complete" => "complete",
        "CustodyInvalid" => "custody-invalid",
        "Incomplete" => "incomplete",
        _ => "unknown",
    }
}
fn custody_color(c: &str) -> Color {
    match c {
        "Complete" => SEAFOAM,
        "CustodyInvalid" => CORAL,
        _ => BUTTER,
    }
}
fn base(d: &str) -> &str {
    d.rsplit('/').next().unwrap_or(d)
}

pub fn render_remote(f: &mut Frame, rows: &[RemoteRow], cursor: usize, sock: &str, connected: bool) {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "FLEET \u{b7} caseforge",
                Style::default().fg(LILAC).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  attached: {sock}  {} investigations", rows.len()), dim),
        ]),
        Line::from(""),
    ];
    if rows.is_empty() {
        lines.push(Line::from(Span::styled("  (fleet has no investigations)", dim)));
    }
    for (i, r) in rows.iter().enumerate() {
        let sel = i == cursor;
        let arrow = if sel {
            Span::styled("\u{25b6} ", Style::default().fg(LILAC))
        } else {
            Span::raw("  ")
        };
        let live = if r.live {
            Span::styled(" \u{25cf} live", Style::default().fg(BUTTER))
        } else {
            Span::raw("")
        };
        lines.push(Line::from(vec![
            arrow,
            Span::styled(format!("{:>2} ", i + 1), dim),
            Span::styled("\u{25cf} ", Style::default().fg(state_color(&r.state))),
            Span::styled(
                format!("{:<8}", r.state.to_lowercase()),
                if sel { Style::default().add_modifier(Modifier::BOLD) } else { Style::default() },
            ),
            Span::styled(format!("{:<16}", custody_label(&r.custody)), Style::default().fg(custody_color(&r.custody))),
            Span::styled(format!("{:<20} ", base(&r.dir)), dim),
            Span::styled(format!("{} rec", r.records), dim),
            live,
            if r.custody == "CustodyInvalid" {
                Span::styled(" \u{26a0}", Style::default().fg(CORAL))
            } else {
                Span::raw("")
            },
        ]));
    }
    lines.push(Line::from(""));
    if connected {
        lines.push(Line::from(Span::styled(
            "\u{2191}\u{2193} move \u{b7} r refresh \u{b7} q detach (fleet keeps running)",
            dim,
        )));
    } else {
        lines.push(Line::from(Span::styled(
            "\u{26a0} fleet server disconnected \u{b7} q to exit",
            Style::default().fg(CORAL).add_modifier(Modifier::BOLD),
        )));
    }
    f.render_widget(Paragraph::new(lines), f.area());
}

fn query(reader: &mut BufReader<UnixStream>, writer: &mut UnixStream) -> Option<Vec<RemoteRow>> {
    if writeln!(writer, "{{\"cmd\":\"list\"}}").is_err() {
        return None;
    }
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) => None, // EOF: the fleet server closed the connection
        Ok(_) => Some(serde_json::from_str::<Value>(&line).map(|v| parse_list(&v)).unwrap_or_default()),
        Err(_) => None,
    }
}

pub fn run_attached(socket: &Path) -> io::Result<()> {
    let stream = UnixStream::connect(socket)?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    let sock_str = socket.display().to_string();

    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, cursor::Hide)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;

    let mut rows = query(&mut reader, &mut writer).unwrap_or_default();
    let mut cur = 0usize;
    let mut connected = true;
    let res = (|| -> io::Result<()> {
        loop {
            let c = cur.min(rows.len().saturating_sub(1));
            cur = c;
            term.draw(|f| render_remote(f, &rows, cur, &sock_str, connected))?;
            if event::poll(Duration::from_millis(1500))? {
                if let Event::Key(k) = event::read()? {
                    let ctrlc = k.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(k.code, KeyCode::Char('c'));
                    match k.code {
                        _ if ctrlc => break,
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Up | KeyCode::Char('k') => cur = cur.saturating_sub(1),
                        KeyCode::Down | KeyCode::Char('j') => {
                            cur = (cur + 1).min(rows.len().saturating_sub(1))
                        }
                        KeyCode::Char('r') => match query(&mut reader, &mut writer) {
                            Some(r) => rows = r,
                            None => connected = false,
                        },
                        _ => {}
                    }
                }
            } else if connected {
                match query(&mut reader, &mut writer) {
                    Some(r) => rows = r,
                    None => connected = false,
                }
            }
        }
        Ok(())
    })();
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_list_reads_rows() {
        let resp = json!({"ok": true, "investigations": [
            {"dir":"/runs/a","state":"Working","custody":"Complete","records":3,"live":true},
            {"dir":"/runs/b","state":"Done","custody":"CustodyInvalid","records":2,"live":false}
        ]});
        let rows = parse_list(&resp);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].state, "Working");
        assert!(rows[0].live);
        assert_eq!(rows[1].custody, "CustodyInvalid");
    }

    #[test]
    fn render_remote_shows_attached_header_and_rows() {
        use ratatui::backend::TestBackend;
        let rows = parse_list(&json!({"investigations":[
            {"dir":"/runs/host-x","state":"Working","custody":"Complete","records":5,"live":true}
        ]}));
        let mut term = Terminal::new(TestBackend::new(90, 10)).unwrap();
        term.draw(|f| render_remote(f, &rows, 0, "/tmp/f.sock", true)).unwrap();
        let buf = term.backend().buffer().clone();
        let area = *buf.area();
        let mut text = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                text.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(text.contains("attached"));
        assert!(text.contains("host-x"));
        assert!(text.contains("live"));
    }
}
