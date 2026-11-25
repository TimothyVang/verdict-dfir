//! caseforge-fleet — DFIR investigation multiplexer (clean-room, herdr-inspired).
//! Interactive at a TTY; static status scan when piped (keeps CI/tests headless).

mod attach;
mod fleet;
mod launch;
mod session;
mod socket;
mod status;
mod ui;


use fleet::{FleetState, Key};
use std::io::{self, IsTerminal, Stdout};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers, MouseButton,
    MouseEventKind,
};
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::crossterm::{cursor, execute};
use ratatui::Terminal;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn map_key(code: KeyCode) -> Key {
    match code {
        KeyCode::Up | KeyCode::Char('k') => Key::Up,
        KeyCode::Down | KeyCode::Char('j') => Key::Down,
        KeyCode::Enter => Key::Enter,
        KeyCode::Tab => Key::Tab,
        KeyCode::Char('o') => Key::Open,
        KeyCode::Char('q') | KeyCode::Esc => Key::Back,
        _ => Key::Other,
    }
}

fn run_interactive(shared: socket::Shared) -> io::Result<()> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, EnableMouseCapture, cursor::Hide)?;
    let mut term = Terminal::new(CrosstermBackend::new(out))?;
    let res = (|| -> io::Result<()> {
        loop {
            {
                let st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                term.draw(|f| ui::render(f, &st))?;
            }
            if event::poll(Duration::from_millis(1000))? {
                let ev = event::read()?;
                if let Event::Mouse(m) = ev {
                    if matches!(m.kind, MouseEventKind::Down(MouseButton::Left)) {
                        let cols = ratatui::crossterm::terminal::size().map(|(c, _)| c).unwrap_or(80);
                        shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner).on_mouse(m.column, m.row, cols);
                    }
                }
                if let Event::Key(k) = ev {
                    let mut open_dir: Option<PathBuf> = None;
                    let quit;
                    {
                        let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        if st.input.is_some() {
                            match k.code {
                                KeyCode::Char(c) => st.input_push(c),
                                KeyCode::Backspace => st.input_backspace(),
                                KeyCode::Esc => st.cancel_input(),
                                KeyCode::Enter => {
                                    if let Some(ev) = st.take_input() {
                                        let cases_root = std::env::var("FINDEVIL_HOME")
                                            .map(|h| PathBuf::from(h).join("cases"))
                                            .unwrap_or_else(|_| std::env::temp_dir().join("caseforge-fleet"));
                                        let cmd = std::env::var("CASEFORGE_CMD")
                                            .unwrap_or_else(|_| "caseforge".to_string());
                                        let _ = st.launch_investigation(&ev, &cases_root, &cmd);
                                    }
                                }
                                _ => {}
                            }
                        } else if k.modifiers.contains(KeyModifiers::CONTROL)
                            && matches!(k.code, KeyCode::Char('c'))
                        {
                            st.quit = true;
                        } else if matches!(k.code, KeyCode::Char('n')) {
                            st.begin_input();
                        } else {
                            st.on_key(map_key(k.code));
                            if st.pending_open {
                                st.pending_open = false;
                                open_dir = st.selected().map(|s| s.dir.clone());
                            }
                        }
                        quit = st.quit;
                    }
                    if let Some(dir) = open_dir {
                        open_viewer(&mut term, &dir)?;
                    }
                    if quit {
                        break;
                    }
                }
            } else {
                let mut st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                st.refresh(now_secs());
            }
        }
        Ok(())
    })();
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, DisableMouseCapture, cursor::Show)?;
    res
}

fn open_viewer(term: &mut Terminal<CrosstermBackend<Stdout>>, dir: &Path) -> io::Result<()> {
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen, cursor::Show)?;
    let cmd = std::env::var("CASEFORGE_CMD").unwrap_or_else(|_| "caseforge".to_string());
    let (prog, args) = launch::viewer_command(&cmd, dir);
    let _ = std::process::Command::new(prog).args(args).status();
    enable_raw_mode()?;
    execute!(term.backend_mut(), EnterAlternateScreen, cursor::Hide)?;
    term.clear()?;
    Ok(())
}

fn print_static(st: &FleetState) {
    println!("FLEET \u{b7} caseforge  {} investigations", st.entries.len());
    for (i, s) in st.entries.iter().enumerate() {
        println!(
            "  {:>2} {:<8?} custody={:<15?} {}",
            i + 1,
            s.state,
            s.custody,
            s.dir.display()
        );
    }
}

fn main() -> io::Result<()> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut socket_path: Option<PathBuf> = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        if a == "--socket" {
            socket_path = it.next().map(PathBuf::from);
        } else if a == "--attach" {
            if let Some(sp) = it.next() {
                return attach::run_attached(Path::new(&sp));
            }
        } else {
            dirs.push(PathBuf::from(a));
        }
    }
    if dirs.is_empty() && socket_path.is_none() {
        eprintln!("usage: caseforge-fleet <run-dir> [run-dir ...] [--socket <path>]");
        std::process::exit(2);
    }
    let shared: socket::Shared =
        std::sync::Arc::new(std::sync::Mutex::new(FleetState::scan(&dirs, now_secs())));
    if let Some(sp) = &socket_path {
        socket::serve(sp, std::sync::Arc::clone(&shared))?;
        eprintln!("caseforge-fleet: socket API on {}", sp.display());
    }
    let result = if io::stdout().is_terminal() {
        run_interactive(shared)
    } else {
        let st = shared.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        print_static(&st);
        Ok(())
    };
    if let Some(sp) = &socket_path {
        let _ = std::fs::remove_file(sp);
    }
    result
}
