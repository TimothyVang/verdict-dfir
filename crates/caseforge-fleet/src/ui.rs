//! ratatui render for the fleet grid. Pure: (state) -> widgets. Snapshot-testable
//! via TestBackend so the render itself is verified, not just the model.

use crate::fleet::{FleetState, Tab, View};
use crate::status::{Custody, RunState, Status};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Left (grid) pane width as a percent of the terminal; on_mouse mirrors this.
pub const LEFT_PANE_PCT: u16 = 54;

const LILAC: Color = Color::Rgb(184, 168, 255);
const SEAFOAM: Color = Color::Rgb(115, 217, 194);
const BUTTER: Color = Color::Rgb(255, 215, 106);
const COBALT: Color = Color::Rgb(120, 140, 255);
const CORAL: Color = Color::Rgb(255, 98, 87);

fn humanize_age(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

fn dot_color(state: RunState) -> Color {
    match state {
        RunState::Blocked => CORAL,
        RunState::Working => BUTTER,
        RunState::Done => COBALT,
        RunState::Idle => Color::DarkGray,
    }
}

fn state_label(state: RunState) -> &'static str {
    match state {
        RunState::Blocked => "blocked",
        RunState::Working => "working",
        RunState::Done => "done",
        RunState::Idle => "idle",
    }
}

fn custody_span(c: Custody) -> Span<'static> {
    let (txt, col) = match c {
        Custody::Complete => ("complete", SEAFOAM),
        Custody::CustodyInvalid => ("custody-invalid", CORAL),
        Custody::Incomplete => ("incomplete", BUTTER),
        Custody::Unknown => ("unknown", Color::DarkGray),
    };
    Span::styled(format!("{:<15}", txt), Style::default().fg(col))
}

fn dir_name(s: &Status) -> String {
    s.dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| s.dir.display().to_string())
}

fn row(i: usize, s: &Status, sel: bool, st_state: RunState) -> Line<'static> {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let arrow = if sel {
        Span::styled("\u{25b6} ", Style::default().fg(LILAC))
    } else {
        Span::raw("  ")
    };
    let label_style = if sel {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    Line::from(vec![
        arrow,
        Span::styled(format!("{:>2} ", i + 1), dim),
        Span::styled("\u{25cf} ", Style::default().fg(dot_color(st_state))),
        Span::styled(format!("{:<8}", state_label(st_state)), label_style),
        Span::raw(" "),
        custody_span(s.custody),
        Span::raw(" "),
        Span::styled(dir_name(s), dim),
        if s.custody == Custody::CustodyInvalid {
            Span::styled(" \u{26a0}", Style::default().fg(CORAL))
        } else {
            Span::raw("")
        },
    ])
}

fn list_lines(st: &FleetState) -> Vec<Line<'static>> {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let vis = st.visible();
    let mut tabs: Vec<Span> = Vec::new();
    for t in Tab::order() {
        let on = t == st.tab;
        tabs.push(Span::styled(
            format!(" {} ", t.label()),
            if on {
                Style::default()
                    .fg(LILAC)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                dim
            },
        ));
    }
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "FLEET \u{b7} caseforge",
                Style::default().fg(LILAC).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("   {} shown", vis.len()), dim),
        ]),
        Line::from(tabs),
        Line::from(""),
    ];
    if vis.is_empty() {
        lines.push(Line::from(Span::styled("  (no investigations in this tab)", dim)));
    } else {
        for (pos, &i) in vis.iter().enumerate() {
            let s = &st.entries[i];
            lines.push(row(pos, s, pos == st.cursor, st.effective_state(s)));
        }
    }
    lines.push(Line::from(""));
    if let Some(buf) = &st.input {
        lines.push(Line::from(vec![
            Span::styled("launch investigation: ", Style::default().fg(BUTTER)),
            Span::styled(format!("{buf}\u{2588}"), Style::default()),
        ]));
        lines.push(Line::from(Span::styled("enter launch \u{b7} esc cancel", dim)));
    } else {
        lines.push(Line::from(Span::styled(
            "\u{2191}\u{2193} move \u{b7} tab \u{b7} enter \u{b7} n launch \u{b7} o view \u{b7} q",
            dim,
        )));
    }
    lines
}

pub fn render(f: &mut Frame, st: &FleetState) {
    match st.view {
        // Zoomed: full-screen detail of the selected investigation.
        View::Detail => {
            f.render_widget(Paragraph::new(detail_lines(st)), f.area());
        }
        // Split: fleet grid (left) + live detail of the selected one (right).
        View::List => {
            let cols = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(LEFT_PANE_PCT), Constraint::Percentage(100 - LEFT_PANE_PCT)])
                .split(f.area());
            f.render_widget(Paragraph::new(list_lines(st)), cols[0]);
            let right = Paragraph::new(detail_lines(st)).block(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::default().add_modifier(Modifier::DIM)),
            );
            f.render_widget(right, cols[1]);
        }
    }
}

fn detail_lines(st: &FleetState) -> Vec<Line<'static>> {
    let dim = Style::default().add_modifier(Modifier::DIM);
    let s = match st.selected() {
        Some(s) => s,
        None => {
            return vec![Line::from(Span::styled(
                "(no investigation selected)",
                Style::default().add_modifier(Modifier::DIM),
            ))]
        }
    };
    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled(
                "INVESTIGATION",
                Style::default().fg(LILAC).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("   {}", crate::ui::name_of(s)), dim),
        ]),
        Line::from(vec![
            Span::styled("\u{25cf} ", Style::default().fg(dot_color(s.state))),
            Span::styled(format!("{:<8}", state_label(s.state)), Style::default()),
            Span::raw("  "),
            custody_span(s.custody),
            Span::styled(format!("  {} records", s.audit_records), dim),
        ]),
        Line::from(Span::styled(
            match (&s.last_kind, s.age_secs) {
                (Some(k), Some(a)) => format!("last: {k} \u{b7} {} ago", humanize_age(a)),
                (Some(k), None) => format!("last: {k}"),
                _ => "no audit records".to_string(),
            },
            dim,
        )),
    ];
    if s.custody == Custody::CustodyInvalid {
        lines.push(Line::from(Span::styled(
            "\u{26a0} custody not verified",
            Style::default().fg(CORAL).add_modifier(Modifier::BOLD),
        )));
    }
    lines.extend([
        Line::from(""),
        Line::from(Span::styled(
            "AUDIT TAIL",
            Style::default().fg(LILAC).add_modifier(Modifier::BOLD),
        )),
    ]);
    if let Some(out) = st.live_output(&s.dir, 16) {
        lines.pop(); // replace the "AUDIT TAIL" header with a LIVE header
        lines.push(Line::from(vec![
            Span::styled("LIVE OUTPUT", Style::default().fg(BUTTER).add_modifier(Modifier::BOLD)),
            Span::styled("  \u{25cf} attached", Style::default().fg(BUTTER)),
        ]));
        for l in out {
            lines.push(Line::from(Span::styled(format!("  {}", l), Style::default())));
        }
    } else {
        for rec in crate::status::audit_tail(&s.dir, 14) {
            let seq = rec.seq.map(|n| n.to_string()).unwrap_or_else(|| "?".into());
            lines.push(Line::from(vec![
                Span::styled(format!("  #{:<3}", seq), dim),
                Span::styled(format!("{:<18}", rec.kind), Style::default()),
                Span::styled(rec.ts, dim),
            ]));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "o open full viewer \u{b7} q back",
        dim,
    )));
    lines
}

pub(crate) fn name_of(s: &Status) -> String {
    dir_name(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status::derive_status;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::{Path, PathBuf};

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/synthetic")
    }

    fn buffer_text(st: &FleetState) -> String {
        let mut term = Terminal::new(TestBackend::new(90, 12)).unwrap();
        term.draw(|f| render(f, st)).unwrap();
        let buf = term.backend().buffer().clone();
        let area = *buf.area();
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn renders_fleet_header_and_rows() {
        let dirs = vec![
            fixtures().join("sample-run"),
            fixtures().join("custody-invalid-run"),
        ];
        let st = FleetState::scan(&dirs, 4_000_000_000);
        let text = buffer_text(&st);
        assert!(text.contains("FLEET"), "header present");
        assert!(text.contains("sample-run"), "row 1 present");
        assert!(text.contains("custody-invalid"), "invalid custody shown");
        assert!(text.contains("done"), "state shown");
        assert!(text.contains("\u{25b6}"), "cursor arrow present");
    }

    #[test]
    fn tab_bar_renders_and_filters() {
        let f = |n: &str| fixtures().join(n);
        let mut st = FleetState::scan(&[f("sample-run"), f("custody-invalid-run")], 4_000_000_000);
        let all = buffer_text(&st);
        assert!(all.contains("all") && all.contains("issues"));
        assert!(all.contains("sample-run"));
        st.tab = Tab::Issues;
        let issues = buffer_text(&st);
        assert!(issues.contains("custody-invalid-run"));
        assert!(!issues.contains("sample-run"));
    }

    #[test]
    fn input_prompt_renders() {
        let mut st = FleetState::scan(&[fixtures().join("sample-run")], 4_000_000_000);
        st.begin_input();
        st.input_push('a'); st.input_push('.'); st.input_push('E');
        let text = buffer_text(&st);
        assert!(text.contains("launch investigation"));
        assert!(text.contains("a.E"));
    }

    #[test]
    fn empty_fleet_degrades() {
        let st = FleetState::scan(&[], 0);
        assert!(buffer_text(&st).contains("no investigations"));
    }

    #[test]
    fn detail_shows_live_output_for_a_session() {
        let mut st = FleetState::scan(&[], 0);
        st.launch(std::path::PathBuf::from("/tmp/cf-live-x"), "sh",
            &["-c".into(), "printf 'RUNNING alpha beta\\n'".into()]).unwrap();
        st.cursor = 0;
        st.view = View::Detail;
        std::thread::sleep(std::time::Duration::from_millis(400));
        let text = buffer_text(&st);
        assert!(text.contains("LIVE OUTPUT"), "got: {text}");
        assert!(text.contains("alpha"));
    }

    #[test]
    fn detail_view_renders_audit_tail() {
        let mut st = FleetState::scan(&[fixtures().join("sample-run")], 4_000_000_000);
        st.view = View::Detail;
        let text = buffer_text(&st);
        assert!(text.contains("INVESTIGATION"));
        assert!(text.contains("AUDIT TAIL"));
        assert!(text.contains("manifest_verify"));
    }

    #[test]
    fn cursor_moves_highlight() {
        let dirs: Vec<_> = ["sample-run", "no-report-run", "custody-invalid-run"]
            .iter()
            .map(|d| fixtures().join(d))
            .collect();
        let mut st = FleetState::scan(&dirs, 4_000_000_000);
        st.cursor = 2;
        let _ = derive_status(&dirs[0], 0); // touch import
        let text = buffer_text(&st);
        // arrow should be on the 3rd data row -> the custody-invalid line
        let arrow_line = text.lines().find(|l| l.contains("\u{25b6}")).unwrap();
        assert!(arrow_line.contains("custody-invalid"));
    }
}
