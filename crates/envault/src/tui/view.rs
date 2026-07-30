use envault_protocol::ServiceState;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use super::app::{App, DaemonClient, Mode, PasswordPurpose, PortabilityPreviewState, Screen};

pub fn draw<C: DaemonClient>(frame: &mut Frame, app: &App<C>) {
    let area = frame.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(area);

    draw_tabs(frame, chunks[0], app);
    match app.screen() {
        Screen::Dashboard => draw_dashboard(frame, chunks[1], app),
        Screen::Profiles => draw_profiles(frame, chunks[1], app),
        Screen::Secrets => draw_secrets(frame, chunks[1], app),
        Screen::Versions => draw_versions(frame, chunks[1], app),
        Screen::Portability => draw_portability(frame, chunks[1], app),
    }
    draw_status_line(frame, chunks[2], app);

    match app.mode() {
        Mode::Normal => {}
        Mode::PasswordInput(purpose, buffer) => {
            let title = match purpose {
                PasswordPurpose::AdminUnlock => "Admin unlock",
                PasswordPurpose::PackageImportTransfer { .. } => {
                    "Transfer password (Enter with nothing typed to use an age identity instead)"
                }
                PasswordPurpose::PackageExportTransfer { .. } => "Transfer password",
            };
            draw_modal(
                frame,
                area,
                title,
                &format!(
                    "Password: {}\n\nEnter to submit, Esc to cancel.",
                    "*".repeat(buffer.len())
                ),
            );
        }
        Mode::TextInput(kind, buffer) => {
            draw_modal(
                frame,
                area,
                "Input",
                &format!(
                    "{}\n{buffer}\n\nEnter to continue, Esc to cancel.",
                    kind.prompt()
                ),
            );
        }
        Mode::Confirm(action) => {
            draw_modal(
                frame,
                area,
                "Confirm",
                &format!(
                    "{}?\n\ny/Enter to confirm, n/Esc to cancel.",
                    action.describe()
                ),
            );
        }
    }
}

fn draw_tabs<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let screen = app.screen();
    let label = |name: &str, current: bool| {
        if current {
            format!("[{name}]")
        } else {
            format!(" {name} ")
        }
    };
    let admin_hint = if app.admin_lease_active() {
        match screen {
            Screen::Profiles => "  admin: c/n/x/a, L:lock",
            Screen::Secrets => "  admin: c/e/n/x/g, L:lock",
            Screen::Portability => "  v:kind t:strategy i:preview x:export c:commit, L:lock",
            _ => "  admin: L:lock",
        }
    } else if screen == Screen::Portability {
        "  v:kind t:strategy, u:unlock admin"
    } else {
        "  u:unlock admin"
    };
    let line = Line::from(format!(
        "{}{}{}{}{}  (d/p/s/o, arrows, enter, esc, r, q){admin_hint}",
        label("Dashboard", screen == Screen::Dashboard),
        label("Profiles", screen == Screen::Profiles),
        label("Secrets", screen == Screen::Secrets),
        label("Versions", screen == Screen::Versions),
        label("Portability", screen == Screen::Portability),
    ));
    frame.render_widget(Paragraph::new(line), area);
}

/// Renders a centered overlay for password entry, a text-input wizard step,
/// or a confirmation prompt. Used only for these three modal interactions;
/// the read surface never uses a modal.
fn draw_modal(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let popup = centered_rect(60, 30, area);
    frame.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.to_string());
    frame.render_widget(
        Paragraph::new(body.to_string())
            .block(block)
            .alignment(Alignment::Left),
        popup,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn draw_dashboard<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let mut lines = Vec::new();
    if let Some(status) = app.status() {
        let service = match status.service {
            ServiceState::Unlocked => "unlocked",
            ServiceState::Locked => "locked",
        };
        lines.push(Line::from(format!(
            "daemon: {service} (pid {})",
            status.pid
        )));
        lines.push(Line::from(format!(
            "active profile: {}",
            status.active_profile.as_deref().unwrap_or("(none)")
        )));
        lines.push(Line::from(format!(
            "admin lease: {}",
            if status.admin_lease_active {
                "active"
            } else {
                "inactive"
            }
        )));
        lines.push(Line::from(format!(
            "agent sessions: {}",
            status.agent_session_count
        )));
    } else {
        lines.push(Line::from("daemon status unavailable"));
    }
    if let Some(admin) = app.admin_status() {
        let expiry = admin
            .expires_at
            .map_or_else(|| "n/a".to_string(), |timestamp| timestamp.to_string());
        lines.push(Line::from(format!(
            "admin lease detail: active={} expires_at={expiry}",
            admin.active
        )));
    }
    let block = Block::default().borders(Borders::ALL).title("Dashboard");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_profiles<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let items: Vec<ListItem> = app
        .profiles()
        .iter()
        .map(|profile| {
            ListItem::new(format!(
                "{}{}",
                profile.name,
                profile
                    .description
                    .as_deref()
                    .map(|description| format!(" - {description}"))
                    .unwrap_or_default()
            ))
        })
        .collect();
    let block = Block::default().borders(Borders::ALL).title("Profiles");
    let mut state = ListState::default();
    if !app.profiles().is_empty() {
        state.select(Some(app.profile_selected()));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
}

fn draw_secrets<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let items: Vec<ListItem> = app
        .secrets()
        .iter()
        .map(|secret| {
            ListItem::new(format!(
                "{} (v{}, {:?})",
                secret.name, secret.current_version, secret.status
            ))
        })
        .collect();
    let block = Block::default().borders(Borders::ALL).title("Secrets");
    let mut state = ListState::default();
    if !app.secrets().is_empty() {
        state.select(Some(app.secret_selected()));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
}

fn draw_versions<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let items: Vec<ListItem> = app
        .versions()
        .iter()
        .map(|version| {
            ListItem::new(format!(
                "v{} generator={:?} entropy_bits={:?}",
                version.version, version.generator, version.entropy_bits
            ))
        })
        .collect();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Secret versions");
    let mut state = ListState::default();
    if !app.versions().is_empty() {
        state.select(Some(app.version_selected()));
    }
    frame.render_stateful_widget(
        List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        area,
        &mut state,
    );
}

fn draw_portability<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let mut lines = vec![
        Line::from(format!("selected kind: {}", app.portability_kind_label())),
        Line::from(format!(
            "selected strategy: {}",
            app.portability_strategy_label()
        )),
        Line::from(""),
    ];
    match app.portability_preview() {
        None => lines.push(Line::from(
            "no preview yet - press 'i' to preview an import for the selected kind",
        )),
        Some(PortabilityPreviewState::Package { preview, .. }) => {
            lines.push(Line::from(format!("plan hash: {}", preview.plan_hash)));
            lines.push(Line::from(format!(
                "counts: scopes={} profiles={} secrets={} versions={} principals={} policy_rules={}",
                preview.counts.scopes,
                preview.counts.profiles,
                preview.counts.secrets,
                preview.counts.versions,
                preview.counts.principals,
                preview.counts.policy_rules
            )));
            for conflict in &preview.conflicts {
                lines.push(Line::from(format!(
                    "conflict: {} '{}' -> {:?}",
                    conflict.resource, conflict.name, conflict.action
                )));
            }
            for warning in &preview.warnings {
                lines.push(Line::from(format!("warning: {warning}")));
            }
            lines.push(Line::from("press 'c' to commit this exact plan"));
        }
        Some(PortabilityPreviewState::Env { preview, .. }) => {
            lines.push(Line::from(format!("plan hash: {}", preview.plan_hash)));
            for entry in &preview.entries {
                lines.push(Line::from(format!(
                    "{} ({} bytes) -> {:?}",
                    entry.name, entry.value_bytes, entry.action
                )));
            }
            for warning in &preview.warnings {
                lines.push(Line::from(format!("warning: {warning}")));
            }
            lines.push(Line::from("press 'c' to commit this exact plan"));
        }
    }
    let block = Block::default().borders(Borders::ALL).title("Portability");
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn draw_status_line<C: DaemonClient>(frame: &mut Frame, area: Rect, app: &App<C>) {
    let text = app.status_message().unwrap_or("ready");
    frame.render_widget(Paragraph::new(text), area);
}
