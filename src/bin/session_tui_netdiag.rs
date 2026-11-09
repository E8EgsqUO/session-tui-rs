//! `/net`: network diagnostics page.
//!
//! Everything shown comes from state the client already has — the
//! `Network`'s snode pool, onion paths, cached swarms and request metrics,
//! the outbox table and the last sync. Opening or refreshing the page sends
//! no request and builds no path; the snapshot is taken on a Tokio task so
//! the UI never waits for a lock. Node keys are cut to 4 characters and no
//! address, full Session ID or proxy credential is displayed. Values the
//! client does not have are shown as N/A.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use libsession::network::NetworkDiagnostics;
use libsession::network::metrics::METRICS_WINDOW;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::{App, LocalStore, SessionClient};

/// Local state is re-read this often while the page is open.
const AUTO_REFRESH: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OutboxCounts {
    /// Not tried yet / due.
    pub waiting: usize,
    /// Failed before, will be retried automatically.
    pub retrying: usize,
    /// Out of automatic attempts: waits for `/retry`.
    pub failed: usize,
}

pub struct NetView {
    pub snapshot: Option<NetworkDiagnostics>,
    pub outbox: Option<OutboxCounts>,
    pub last_sync: Option<SystemTime>,
    pub proxy: Option<String>,
    pub refreshed: Option<Instant>,
    pub loading: bool,
    pub scroll: u16,
}

/// Overall state from what the snapshot shows.
pub fn connection_state(snapshot: &NetworkDiagnostics) -> &'static str {
    let summary = &snapshot.summary;
    if snapshot.pool_size == 0 {
        return "Not connected yet (no service nodes known)";
    }
    if snapshot.standard_paths.is_empty() {
        return "No onion path built";
    }
    match summary.success_rate {
        None => "Idle (no requests in the last 5 minutes)",
        Some(rate) if rate >= 0.8 => "Connected",
        Some(rate) if rate > 0.0 => "Degraded (some requests fail)",
        Some(_) => "Failing (all recent requests failed)",
    }
}

/// `https_proxy` as "scheme://host:port", without credentials or path.
pub fn proxy_display(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    let (scheme, rest) = value.split_once("://").unwrap_or(("http", value));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    Some(format!("{scheme}://{host}"))
}

fn proxy_from_env() -> Option<String> {
    let value = std::env::var("https_proxy")
        .or_else(|_| std::env::var("HTTPS_PROXY"))
        .ok();
    proxy_display(value.as_deref())
}

fn start_snapshot(app: &mut App, client: &Arc<SessionClient>) {
    if app
        .net_task
        .as_ref()
        .is_some_and(|task| !task.is_finished())
    {
        return;
    }
    let client = client.clone();
    app.net_task = Some(tokio::spawn(
        async move { client.network.diagnostics().await },
    ));
    if let Some(view) = app.net_view.as_mut() {
        view.loading = true;
    }
}

/// Re-read the cheap local parts now and start a new network snapshot.
pub(super) fn refresh(app: &mut App, client: &Arc<SessionClient>, store: &LocalStore) {
    let outbox = store.outbox_counts();
    let last_sync = app.last_sync_ok;
    if let Some(view) = app.net_view.as_mut() {
        view.outbox = outbox;
        view.last_sync = last_sync;
        view.proxy = proxy_from_env();
        view.refreshed = Some(Instant::now());
    }
    start_snapshot(app, client);
}

pub(super) fn open(app: &mut App, client: &Arc<SessionClient>, store: &LocalStore) {
    app.net_view = Some(NetView {
        snapshot: None,
        outbox: None,
        last_sync: None,
        proxy: None,
        refreshed: None,
        loading: true,
        scroll: 0,
    });
    refresh(app, client, store);
}

/// Called every loop turn: collect a finished snapshot, auto-refresh.
pub(super) async fn poll(app: &mut App, client: &Arc<SessionClient>, store: &LocalStore) {
    if app.net_task.as_ref().is_some_and(|task| task.is_finished())
        && let Some(task) = app.net_task.take()
    {
        let snapshot = task.await.ok();
        if let Some(view) = app.net_view.as_mut() {
            view.loading = false;
            if snapshot.is_some() {
                view.snapshot = snapshot;
            }
        }
    }
    if app
        .net_view
        .as_ref()
        .is_some_and(|view| view.refreshed.is_none_or(|at| at.elapsed() >= AUTO_REFRESH))
    {
        refresh(app, client, store);
    }
}

/// Keys while the page is open. `true`: handled.
pub(super) fn handle_key(
    app: &mut App,
    client: &Arc<SessionClient>,
    store: &LocalStore,
    code: crossterm::event::KeyCode,
) {
    use crossterm::event::KeyCode;
    match code {
        KeyCode::Esc | KeyCode::Char('q') => app.net_view = None,
        KeyCode::Char('r' | 'R') => refresh(app, client, store),
        KeyCode::Up => {
            if let Some(view) = app.net_view.as_mut() {
                view.scroll = view.scroll.saturating_sub(1);
            }
        }
        KeyCode::Down => {
            if let Some(view) = app.net_view.as_mut() {
                view.scroll = view.scroll.saturating_add(1).min(200);
            }
        }
        _ => {}
    }
}

fn na() -> String {
    "N/A".into()
}

fn millis(duration: Option<Duration>) -> String {
    duration.map_or_else(na, |d| format!("{} ms", d.as_millis()))
}

fn ago(at: Option<SystemTime>) -> String {
    let Some(at) = at else {
        return na();
    };
    let seconds = SystemTime::now()
        .duration_since(at)
        .unwrap_or_default()
        .as_secs();
    let stamp = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or_else(|_| na(), |d| super::format_time(d.as_millis() as u64));
    match seconds {
        0..=59 => format!("{stamp} ({seconds} s ago)"),
        60..=3599 => format!("{stamp} ({} min ago)", seconds / 60),
        _ => format!("{stamp} ({} h ago)", seconds / 3600),
    }
}

fn path_lines(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    paths: &[libsession::network::network::PathSummary],
    target: u8,
    strike_limit: u8,
) {
    use super::{MUTED, TEAL, TEXT};
    lines.push(Line::from(vec![
        Span::styled(format!("  {label:<22}"), Style::default().fg(MUTED)),
        Span::styled(
            format!("{} of {target} wanted", paths.len()),
            Style::default().fg(TEXT),
        ),
    ]));
    for (index, path) in paths.iter().enumerate() {
        let hops = path
            .hops
            .iter()
            .map(|hop| {
                format!(
                    "{}… v{}.{}.{}",
                    hop.key_prefix, hop.version[0], hop.version[1], hop.version[2]
                )
            })
            .collect::<Vec<_>>()
            .join("  →  ");
        let (state, color) = if path.strikes == 0 {
            ("OK".to_owned(), TEAL)
        } else {
            (
                format!("{} of {strike_limit} strikes", path.strikes),
                super::UNREAD,
            )
        };
        lines.push(Line::from(vec![
            Span::styled(format!("    #{}  ", index + 1), Style::default().fg(MUTED)),
            Span::styled(
                format!("you → {hops} → destination  "),
                Style::default().fg(TEXT),
            ),
            Span::styled(state, Style::default().fg(color)),
        ]));
    }
}

pub(super) fn draw(frame: &mut ratatui::Frame<'_>, area: Rect, view: &NetView) {
    use super::{BG, MUTED, PANEL, TEAL, TEXT};
    frame.render_widget(Clear, area);
    let row = |label: &str, value: String| {
        Line::from(vec![
            Span::styled(format!("  {label:<22}"), Style::default().fg(MUTED)),
            Span::styled(value, Style::default().fg(TEXT)),
        ])
    };
    let heading = |text: &str| {
        Line::from(Span::styled(
            format!(" {text}"),
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        ))
    };
    let mut lines: Vec<Line<'static>> = vec![Line::from(" ")];
    let snapshot = view.snapshot.as_ref();
    lines.push(heading("Connection"));
    lines.push(row(
        "State",
        snapshot.map_or_else(
            || {
                if view.loading {
                    "Reading…".into()
                } else {
                    na()
                }
            },
            |s| connection_state(s).to_owned(),
        ),
    ));
    lines.push(row(
        "Last onion success",
        ago(snapshot.and_then(|s| s.last_success)),
    ));
    lines.push(row("Last successful sync", ago(view.last_sync)));
    lines.push(row(
        "HTTPS proxy",
        view.proxy
            .clone()
            .map_or_else(|| "Not set".into(), |p| format!("Enabled · {p}")),
    ));
    lines.push(Line::from(" "));
    lines.push(heading("Service nodes"));
    lines.push(row(
        "Known service nodes",
        snapshot.map_or_else(na, |s| s.pool_size.to_string()),
    ));
    match snapshot.map(|s| &s.swarms) {
        Some(swarms) if !swarms.is_empty() => {
            for (key, nodes, age) in swarms {
                lines.push(row(
                    "Cached swarm",
                    format!(
                        "{key}… · {nodes} nodes · looked up {} min ago",
                        age.as_secs() / 60
                    ),
                ));
            }
        }
        Some(_) => lines.push(row("Cached swarms", "None yet".into())),
        None => lines.push(row("Cached swarms", na())),
    }
    lines.push(Line::from(" "));
    lines.push(heading("Onion paths (3 hops: guard → relay → exit)"));
    match snapshot {
        Some(s) => {
            path_lines(
                &mut lines,
                "Messages",
                &s.standard_paths,
                s.target_paths,
                s.strike_limit,
            );
            path_lines(
                &mut lines,
                "Files",
                &s.file_paths,
                s.target_paths,
                s.strike_limit,
            );
        }
        None => lines.push(row("Paths", na())),
    }
    lines.push(Line::from(" "));
    lines.push(heading(&format!(
        "Requests · last {} min",
        METRICS_WINDOW.as_secs() / 60
    )));
    let summary = snapshot.map(|s| &s.summary);
    lines.push(row(
        "Round trips / failed",
        summary.map_or_else(na, |s| format!("{} / {}", s.requests, s.failures)),
    ));
    lines.push(row(
        "Round-trip success",
        summary
            .and_then(|s| s.success_rate)
            .map_or_else(na, |rate| format!("{:.0} %", rate * 100.0)),
    ));
    lines.push(row(
        "Round trip last",
        millis(summary.and_then(|s| s.last_round_trip)),
    ));
    lines.push(row(
        "Round trip avg / max",
        format!(
            "{} / {}",
            millis(summary.and_then(|s| s.average_round_trip)),
            millis(summary.and_then(|s| s.max_round_trip))
        ),
    ));
    lines.push(Line::from(Span::styled(
        "  Round trip = whole onion request: through all 3 hops to the destination and back,",
        Style::default().fg(MUTED),
    )));
    lines.push(Line::from(Span::styled(
        "  including its processing (and the proxy). Single-node latency: N/A (not measured).",
        Style::default().fg(MUTED),
    )));
    lines.push(Line::from(Span::styled(
        "  Success = a reply came back and decrypted; it does not mean a message was stored or delivered.",
        Style::default().fg(MUTED),
    )));
    lines.push(Line::from(" "));
    lines.push(heading("Outbox"));
    lines.push(row(
        "Waiting / retrying",
        view.outbox
            .map_or_else(na, |o| format!("{} / {}", o.waiting, o.retrying)),
    ));
    lines.push(row(
        "Failed (needs /retry)",
        view.outbox.map_or_else(na, |o| o.failed.to_string()),
    ));
    lines.push(Line::from(" "));
    lines.push(heading("Recent errors"));
    match snapshot.map(|s| &s.recent_errors) {
        Some(errors) if !errors.is_empty() => {
            for (at, error) in errors.iter().rev() {
                let stamp = at
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .map_or_else(|_| na(), |d| super::format_time(d.as_millis() as u64));
                lines.push(row(&stamp, error.clone()));
            }
        }
        Some(_) => lines.push(row("", "None".into())),
        None => lines.push(row("", na())),
    }
    let block = Block::default()
        .title(" Network diagnostics ")
        .title_bottom(if view.loading {
            " reading… · R refresh · ↑/↓ scroll · Esc back · no requests are sent "
        } else {
            " R refresh · ↑/↓ scroll · Esc back · no requests are sent "
        })
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TEAL))
        .style(Style::default().bg(PANEL));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .scroll((view.scroll, 0))
            .style(Style::default().bg(BG))
            .block(block),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsession::network::metrics::MetricsSummary;
    use libsession::network::network::{HopSummary, PathSummary};

    fn snapshot(pool: usize, paths: usize, rate: Option<f64>) -> NetworkDiagnostics {
        let path = PathSummary {
            hops: vec![
                HopSummary {
                    key_prefix: "abcd".into(),
                    version: [2, 11, 0],
                };
                3
            ],
            strikes: 0,
        };
        NetworkDiagnostics {
            pool_size: pool,
            standard_paths: vec![path; paths],
            file_paths: Vec::new(),
            target_paths: 2,
            strike_limit: 3,
            swarms: Vec::new(),
            summary: MetricsSummary {
                success_rate: rate,
                ..Default::default()
            },
            last_success: None,
            recent_errors: Vec::new(),
        }
    }

    #[test]
    fn connection_state_from_snapshot() {
        assert!(connection_state(&snapshot(0, 0, None)).starts_with("Not connected"));
        assert!(connection_state(&snapshot(30, 0, Some(1.0))).starts_with("No onion path"));
        assert!(connection_state(&snapshot(30, 2, None)).starts_with("Idle"));
        assert_eq!(connection_state(&snapshot(30, 2, Some(0.9))), "Connected");
        assert!(connection_state(&snapshot(30, 2, Some(0.5))).starts_with("Degraded"));
        assert!(connection_state(&snapshot(30, 2, Some(0.0))).starts_with("Failing"));
    }

    #[test]
    fn proxy_without_credentials() {
        assert_eq!(proxy_display(None), None);
        assert_eq!(proxy_display(Some("  ")), None);
        assert_eq!(
            proxy_display(Some("http://user:pa@ss@proxy.lan:3128/x")).as_deref(),
            Some("http://proxy.lan:3128")
        );
        assert_eq!(
            proxy_display(Some("10.0.0.1:8080")).as_deref(),
            Some("http://10.0.0.1:8080")
        );
    }
}
