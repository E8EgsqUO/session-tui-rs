//! Moving to a message, and the lists that lead to one: `/unread`, Alt+N,
//! `/goto`, bookmarks, `/media` and `/links`.
//!
//! Every jump — these and `/search` — goes through [`open_message`], which
//! finds the message by its stable key (chat, timestamp, direction, author),
//! never by list position, and only changes the view: the chat, the
//! selected message and a short highlight. The lists are built from the
//! messages in memory (the decrypted local history), skip deleted and
//! disappeared messages, download nothing and send nothing.

use std::time::{Duration, Instant};

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use super::session_tui_separators::{MessageKey, local_date};
use super::{App, FocusArea, LocalStore, Message, now_ms};

/// Most entries a list shows (newest first).
pub const MAX_ITEMS: usize = 1000;

fn live(message: &Message, now: u64) -> bool {
    !message.expires_at.is_some_and(|at| at <= now)
}

/// Position of a message that still exists (not deleted, not disappeared).
pub(super) fn locate(app: &App, conversation: &str, key: &MessageKey) -> Option<(usize, usize)> {
    let chat = app
        .conversations
        .iter()
        .position(|c| c.id == conversation)?;
    let c = &app.conversations[chat];
    let index = c.position_of(key, &app.local_id)?;
    live(&c.messages[index], now_ms()).then_some((chat, index))
}

/// Open `conversation` at the message `key`: selected, scrolled into view
/// and highlighted for a moment. Nothing is marked read or changed here.
pub(super) fn open_message(
    app: &mut App,
    conversation: &str,
    key: &MessageKey,
) -> Result<(), &'static str> {
    let (chat, index) =
        locate(app, conversation, key).ok_or("THAT MESSAGE IS NO LONGER AVAILABLE")?;
    app.selected = chat;
    let c = &mut app.conversations[chat];
    c.selected_message = index;
    c.scroll = None;
    c.follow_selection = true;
    app.focus = FocusArea::Messages;
    app.highlight = Some((
        conversation.to_owned(),
        key.clone(),
        Instant::now() + Duration::from_secs(3),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unread and dates
// ---------------------------------------------------------------------------

/// First unread message of the open chat: the boundary fixed for this
/// visit (messages may have been marked read since), else the first
/// unread one.
fn first_unread(app: &App) -> Option<MessageKey> {
    let c = app.conversations.get(app.selected)?;
    app.unread_marker
        .as_ref()
        .filter(|m| m.conversation == c.id)
        .and_then(|m| m.first_unread.clone())
        .filter(|key| locate(app, &c.id, key).is_some())
        .or_else(|| {
            c.messages
                .iter()
                .find(|m| !m.outgoing && !m.is_read && !m.system)
                .map(|m| m.key(&c.id, &app.local_id))
        })
}

/// `/unread`.
pub(super) fn unread(app: &mut App) {
    let Some(id) = app.conversations.get(app.selected).map(|c| c.id.clone()) else {
        app.status = "NO CHAT OPEN".into();
        return;
    };
    app.status = match first_unread(app) {
        Some(key) => match open_message(app, &id, &key) {
            Ok(()) => "FIRST UNREAD MESSAGE".into(),
            Err(error) => error.into(),
        },
        None => "NO UNREAD MESSAGES IN THIS CHAT".into(),
    };
}

/// Alt+N: the next chat (in list order, within the filter) with unread
/// messages, at its first unread message.
pub(super) fn next_unread_chat(app: &mut App) {
    let order = super::session_tui_chats::visible(app);
    let target = super::session_tui_chats::next_unread(&order, app.selected, |index| {
        app.conversations[index].unread() > 0
    });
    let Some(index) = target else {
        app.status = "NO OTHER CHAT HAS UNREAD MESSAGES".into();
        return;
    };
    app.selected = index;
    let c = &app.conversations[index];
    let id = c.id.clone();
    let key = c
        .messages
        .iter()
        .find(|m| !m.outgoing && !m.is_read && !m.system)
        .map(|m| m.key(&id, &app.local_id));
    let title = c.title(&app.local_id).to_owned();
    if let Some(key) = key {
        let _ = open_message(app, &id, &key);
    }
    app.status = format!("UNREAD · {title}");
}

/// Index of the first message of the open chat on `date` (local), by the
/// same date rule as the date lines.
pub fn first_on_date(
    timestamps: &[u64],
    date: time::Date,
    date_of: impl Fn(u64) -> Option<time::Date>,
) -> Option<usize> {
    // Messages are in time order, so dates are too.
    let start = timestamps.partition_point(|&ts| date_of(ts).is_some_and(|d| d < date));
    timestamps
        .get(start)
        .filter(|&&ts| date_of(ts) == Some(date))
        .map(|_| start)
}

/// `/goto YYYY-MM-DD`.
pub(super) fn goto(app: &mut App, args: &str) {
    let date = match super::session_tui_search::parse_date(args.trim()) {
        Ok(date) => date,
        Err(error) => {
            app.status = format!("{error} · /goto YYYY-MM-DD");
            return;
        }
    };
    let Some(c) = app.conversations.get(app.selected) else {
        app.status = "NO CHAT OPEN".into();
        return;
    };
    let now = now_ms();
    let timestamps: Vec<u64> = c.messages.iter().map(|m| m.timestamp_ms).collect();
    let target = first_on_date(&timestamps, date, local_date).and_then(|first| {
        // The first message of that day that still exists.
        c.messages[first..]
            .iter()
            .take_while(|m| local_date(m.timestamp_ms) == Some(date))
            .find(|m| live(m, now))
            .map(|m| m.key(&c.id, &app.local_id))
    });
    let id = c.id.clone();
    app.status = match target {
        Some(key) => match open_message(app, &id, &key) {
            Ok(()) => format!("{date}"),
            Err(error) => error.into(),
        },
        None => format!("NO MESSAGES ON {date} IN THIS CHAT"),
    };
}

// ---------------------------------------------------------------------------
// Bookmarks
// ---------------------------------------------------------------------------

/// `/bookmark` (`on`) or `/unbookmark` for the selected message.
pub(super) fn bookmark(app: &mut App, store: &LocalStore, on: bool) {
    let Some((id, key)) = app.conversations.get(app.selected).and_then(|c| {
        let m = c.messages.get(c.selected_message).filter(|m| !m.system)?;
        Some((c.id.clone(), m.key(&c.id, &app.local_id)))
    }) else {
        app.status = "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
        return;
    };
    app.status = match store.set_bookmark(&id, &key, on) {
        Ok(changed) => {
            if on {
                app.bookmarks.insert((id, key));
            } else {
                app.bookmarks.remove(&(id, key));
            }
            match (on, changed) {
                (true, true) => "BOOKMARKED · /bookmarks LISTS THEM",
                (true, false) => "ALREADY BOOKMARKED",
                (false, true) => "BOOKMARK REMOVED",
                (false, false) => "NOT BOOKMARKED",
            }
            .into()
        }
        Err(error) => format!("BOOKMARK NOT SAVED · {error}"),
    };
}

/// `/bookmarks`. References whose message is gone (deleted, unsent,
/// disappeared) are removed instead of listed; their text is never kept.
pub(super) fn open_bookmarks(app: &mut App, store: &LocalStore) {
    let mut stale = Vec::new();
    let mut items = Vec::new();
    for (chat, key) in &app.bookmarks {
        let Some((ci, mi)) = locate(app, chat, key) else {
            stale.push((chat.clone(), key.clone()));
            continue;
        };
        let c = &app.conversations[ci];
        let message = &c.messages[mi];
        items.push(Item {
            conversation: chat.clone(),
            key: key.clone(),
            head: format!(
                "★ {} · {} · {}",
                c.title(&app.local_id),
                app.sender_label(&key.author),
                super::format_time(key.timestamp_ms)
            ),
            detail: one_line(&message.preview_text(), 100),
            url: None,
            attachment: None,
        });
    }
    for (chat, key) in &stale {
        let _ = store.set_bookmark(chat, key, false);
        app.bookmarks.remove(&(chat.clone(), key.clone()));
    }
    items.sort_by_key(|item| std::cmp::Reverse(item.key.timestamp_ms));
    let mut view = BrowseView::new(Kind::Bookmarks, "Bookmarks".into(), items);
    if !stale.is_empty() {
        view.note = Some(format!(
            "{} bookmark(s) of deleted or disappeared messages removed",
            stale.len()
        ));
    }
    app.browse = Some(view);
}

// ---------------------------------------------------------------------------
// Media and links
// ---------------------------------------------------------------------------

/// Type label of an attachment from its MIME type.
pub fn media_kind(content_type: &str) -> &'static str {
    match content_type.split('/').next().unwrap_or_default() {
        "image" => "image",
        "audio" => "audio",
        "video" => "video",
        _ if content_type.contains("pdf")
            || content_type.contains("document")
            || content_type.starts_with("text/") =>
        {
            "document"
        }
        _ => "file",
    }
}

pub fn human_size(bytes: u32) -> String {
    match bytes {
        0 => "size N/A".into(),
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// The open chat's messages that still exist, newest first.
fn recent_messages(app: &App) -> Vec<(usize, &Message)> {
    let Some(c) = app.conversations.get(app.selected) else {
        return Vec::new();
    };
    let now = now_ms();
    c.messages
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, m)| !m.system && live(m, now))
        .collect()
}

/// `/media`: every attachment of the open chat (one entry each).
pub(super) fn open_media(app: &mut App) {
    let Some(c) = app.conversations.get(app.selected) else {
        app.status = "NO CHAT OPEN".into();
        return;
    };
    let id = c.id.clone();
    let mut items = Vec::new();
    'outer: for (_, message) in recent_messages(app) {
        let key = message.key(&id, &app.local_id);
        for (index, attachment) in message.attachments.iter().enumerate() {
            if items.len() == MAX_ITEMS {
                break 'outer;
            }
            items.push(Item {
                conversation: id.clone(),
                key: key.clone(),
                head: format!(
                    "{} · {} · {} · {} · {}",
                    attachment_name(&attachment.file_name),
                    media_kind(&attachment.content_type),
                    human_size(attachment.size),
                    app.sender_label(&key.author),
                    super::format_time(key.timestamp_ms)
                ),
                detail: if message.body.is_empty() {
                    format!("attachment {} of {}", index + 1, message.attachments.len())
                } else {
                    one_line(&message.body, 100)
                },
                url: None,
                attachment: Some((index, attachment.content_type.starts_with("image/"))),
            });
        }
    }
    let title = format!(
        "Media · {}",
        app.conversations[app.selected].title(&app.local_id)
    );
    app.browse = Some(BrowseView::new(Kind::Media, title, items));
}

fn attachment_name(name: &str) -> String {
    if name.is_empty() {
        "(no name)".into()
    } else {
        one_line(name, 60)
    }
}

/// HTTP(S) URLs in `text`, in order, without trailing punctuation or an
/// unbalanced closing bracket. Control characters end a URL.
pub fn extract_urls(text: &str) -> Vec<String> {
    let mut urls = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut from = 0;
    while from < text.len() {
        let next = ["http://", "https://"]
            .iter()
            .filter_map(|scheme| lower[from..].find(scheme).map(|i| from + i))
            .min();
        let Some(start) = next else {
            break;
        };
        let end = text[start..]
            .find(|c: char| {
                c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | '"' | '`')
            })
            .map_or(text.len(), |i| start + i);
        let mut url = &text[start..end];
        loop {
            let trimmed = url.trim_end_matches(['.', ',', ';', ':', '!', '?', '\'', '*']);
            let trimmed = match trimmed.chars().last() {
                Some(close @ (')' | ']' | '}')) => {
                    let open = match close {
                        ')' => '(',
                        ']' => '[',
                        _ => '{',
                    };
                    if trimmed.matches(close).count() > trimmed.matches(open).count() {
                        &trimmed[..trimmed.len() - 1]
                    } else {
                        trimmed
                    }
                }
                _ => trimmed,
            };
            if trimmed.len() == url.len() {
                break;
            }
            url = trimmed;
        }
        // Something after the scheme.
        if url.len() > url.find("//").map_or(0, |i| i + 2) {
            urls.push(url.to_owned());
        }
        from = end.max(start + 1);
    }
    urls
}

/// `/links`: URLs of the open chat's messages (one entry per URL).
pub(super) fn open_links(app: &mut App) {
    let Some(c) = app.conversations.get(app.selected) else {
        app.status = "NO CHAT OPEN".into();
        return;
    };
    let id = c.id.clone();
    let mut items = Vec::new();
    'outer: for (_, message) in recent_messages(app) {
        let mut urls = extract_urls(&message.body);
        for (url, _) in &message.links {
            for url in extract_urls(url) {
                if !urls.contains(&url) {
                    urls.push(url);
                }
            }
        }
        if urls.is_empty() {
            continue;
        }
        let key = message.key(&id, &app.local_id);
        for url in urls {
            if items.len() == MAX_ITEMS {
                break 'outer;
            }
            items.push(Item {
                conversation: id.clone(),
                key: key.clone(),
                head: format!(
                    "{} · {}",
                    app.sender_label(&key.author),
                    super::format_time(key.timestamp_ms)
                ),
                detail: one_line(&message.body, 100),
                url: Some(url),
                attachment: None,
            });
        }
    }
    let title = format!(
        "Links · {}",
        app.conversations[app.selected].title(&app.local_id)
    );
    app.browse = Some(BrowseView::new(Kind::Links, title, items));
}

fn one_line(text: &str, max: usize) -> String {
    let flat: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if flat.chars().count() > max {
        format!("{}…", flat.chars().take(max).collect::<String>())
    } else {
        flat
    }
}

// ---------------------------------------------------------------------------
// The list panel
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bookmarks,
    Media,
    Links,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub conversation: String,
    pub key: MessageKey,
    pub head: String,
    pub detail: String,
    pub url: Option<String>,
    /// (attachment index, is an image).
    pub attachment: Option<(usize, bool)>,
}

pub struct BrowseView {
    pub kind: Kind,
    pub title: String,
    pub items: Vec<Item>,
    pub selected: usize,
    pub scroll: usize,
    pub page: usize,
    pub note: Option<String>,
}

impl BrowseView {
    pub fn new(kind: Kind, title: String, items: Vec<Item>) -> Self {
        Self {
            kind,
            title,
            items,
            selected: 0,
            scroll: 0,
            page: 10,
            note: None,
        }
    }

    pub fn step(&mut self, delta: isize) {
        if self.items.is_empty() {
            return;
        }
        let last = self.items.len() as isize - 1;
        self.selected = (self.selected as isize)
            .saturating_add(delta)
            .clamp(0, last) as usize;
        let page = self.page.max(1);
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + page {
            self.scroll = self.selected + 1 - page;
        }
    }

    fn current(&self) -> Option<&Item> {
        self.items.get(self.selected)
    }

    fn keys_hint(&self) -> &'static str {
        match self.kind {
            Kind::Bookmarks => " ↑/↓ select · Enter open · Esc back ",
            Kind::Media => " ↑/↓ select · Enter open · V view · S save · Esc back ",
            Kind::Links => " ↑/↓ select · Enter open message · C copy URL · Esc back ",
        }
    }

    fn empty_text(&self) -> &'static str {
        match self.kind {
            Kind::Bookmarks => "No bookmarks. Select a message and use /bookmark.",
            Kind::Media => "No attachments in this chat.",
            Kind::Links => "No links in this chat.",
        }
    }
}

/// Keys while a list is open.
pub(super) fn handle_key(app: &mut App, code: crossterm::event::KeyCode) {
    use crossterm::event::KeyCode;
    let Some(view) = app.browse.as_mut() else {
        return;
    };
    let page = view.page.max(1) as isize;
    match code {
        KeyCode::Esc => app.browse = None,
        KeyCode::Up => view.step(-1),
        KeyCode::Down => view.step(1),
        KeyCode::PageUp => view.step(-page),
        KeyCode::PageDown => view.step(page),
        KeyCode::Home => view.step(isize::MIN),
        KeyCode::End => view.step(isize::MAX),
        KeyCode::Enter => {
            let Some(item) = view.current().cloned() else {
                return;
            };
            match open_message(app, &item.conversation, &item.key) {
                Ok(()) => app.browse = None,
                Err(error) => app.status = error.into(),
            }
        }
        KeyCode::Char('c' | 'C') if view.kind == Kind::Links => {
            if let Some(url) = view.current().and_then(|item| item.url.clone()) {
                app.clipboard = Some(url);
                app.status = "LINK COPIED".into();
            }
        }
        KeyCode::Char(c @ ('v' | 'V' | 's' | 'S')) if view.kind == Kind::Media => {
            let Some(item) = view.current().cloned() else {
                return;
            };
            let Some((index, image)) = item.attachment else {
                return;
            };
            if matches!(c, 'v' | 'V') && !image {
                app.status = "PREVIEW IS ONLY FOR IMAGES · S SAVES THE FILE".into();
                return;
            }
            if let Err(error) = open_message(app, &item.conversation, &item.key) {
                app.status = error.into();
                return;
            }
            app.browse = None;
            if matches!(c, 'v' | 'V') {
                // The image viewer of `/view`.
                if let Err(error) = super::open_selected_image(app, Some(index)) {
                    app.status = format!("IMAGE PREVIEW FAILED · {error}");
                }
            } else {
                // Same as typing `/save N` on that message.
                app.queued_command = Some(format!("/save {}", index + 1));
            }
        }
        _ => {}
    }
}

pub(super) fn draw(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    view: &mut BrowseView,
    exists: impl Fn(&Item) -> bool,
) {
    use super::{BG, MUTED, PANEL, TEAL, TEXT};
    let width = area.width.saturating_sub(6).clamp(20, 110).min(area.width);
    let height = area.height.saturating_sub(4).clamp(6, 40).min(area.height);
    let rect = super::centered_cells(width, height, area);
    frame.render_widget(Clear, rect);
    let count = match (view.items.len(), view.items.len() >= MAX_ITEMS) {
        (n, true) => format!("newest {n}"),
        (n, false) => format!("{n}"),
    };
    let block = Block::default()
        .title(format!(" {} · {count} ", view.title))
        .title_bottom(view.keys_hint())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TEAL))
        .style(Style::default().bg(PANEL));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(note) = &view.note {
        lines.push(Line::from(Span::styled(
            format!(" {note}"),
            Style::default().fg(MUTED),
        )));
    }
    if view.items.is_empty() {
        lines.push(Line::from(Span::styled(
            format!(" {}", view.empty_text()),
            Style::default().fg(MUTED),
        )));
    }
    let rows_per_item = if view.kind == Kind::Links { 3 } else { 2 };
    let available = (inner.height as usize).saturating_sub(lines.len());
    view.page = (available / rows_per_item).max(1);
    view.step(0);
    let end = (view.scroll + view.page).min(view.items.len());
    let text_width = inner.width.saturating_sub(5) as usize;
    let clip = |s: &str| -> String {
        let mut out = String::new();
        let mut used = 0;
        for c in s.chars() {
            let w = unicode_width::UnicodeWidthChar::width(c).unwrap_or(0);
            if used + w > text_width {
                out.push('…');
                break;
            }
            used += w;
            out.push(c);
        }
        out
    };
    for index in view.scroll..end {
        let item = &view.items[index];
        let selected = index == view.selected;
        let base = if selected {
            Style::default().bg(BG).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        let gone = !exists(item);
        lines.push(Line::from(vec![
            Span::styled(if selected { " ▸ " } else { "   " }, base.fg(TEAL)),
            Span::styled(
                clip(&if gone {
                    "(no longer available)".to_owned()
                } else {
                    item.head.clone()
                }),
                base.fg(if gone { MUTED } else { TEXT }),
            ),
        ]));
        if let Some(url) = &item.url {
            lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(clip(url), Style::default().fg(TEAL)),
            ]));
        }
        lines.push(Line::from(vec![
            Span::raw("     "),
            Span::styled(
                clip(if gone { "" } else { &item.detail }),
                Style::default().fg(MUTED),
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_split_and_trimmed() {
        let text = "see https://a.example/x, and (http://b.example/wiki/Foo_(bar)) \
                    then https://c.example/q?x=1&y=2.\nHTTPS://D.example/path!";
        assert_eq!(
            extract_urls(text),
            [
                "https://a.example/x",
                "http://b.example/wiki/Foo_(bar)",
                "https://c.example/q?x=1&y=2",
                "HTTPS://D.example/path",
            ]
        );
        assert_eq!(extract_urls("http:// nothing"), Vec::<String>::new());
        assert_eq!(
            extract_urls("<https://e.example/>\u{1b}[31m"),
            ["https://e.example/"]
        );
        assert_eq!(
            extract_urls("[x](https://f.example/a)"),
            ["https://f.example/a"]
        );
        assert_eq!(extract_urls("no links here"), Vec::<String>::new());
    }

    #[test]
    fn media_kinds_and_sizes() {
        assert_eq!(media_kind("image/png"), "image");
        assert_eq!(media_kind("audio/ogg"), "audio");
        assert_eq!(media_kind("video/mp4"), "video");
        assert_eq!(media_kind("application/pdf"), "document");
        assert_eq!(media_kind("application/octet-stream"), "file");
        assert_eq!(human_size(0), "size N/A");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(3 * 1024 * 1024), "3.0 MB");
    }

    #[test]
    fn first_message_of_a_local_date() {
        let day = 86_400_000;
        let date_of = |ms: u64| {
            time::OffsetDateTime::from_unix_timestamp((ms / 1000) as i64)
                .ok()
                .map(|t| t.date())
        };
        let d = |n: u8| time::Date::from_calendar_date(1970, time::Month::January, n).unwrap();
        let stamps = [day - 1, day, day + 5, 3 * day];
        assert_eq!(first_on_date(&stamps, d(1), date_of), Some(0));
        assert_eq!(first_on_date(&stamps, d(2), date_of), Some(1));
        // No message that day: no jump to a neighbour.
        assert_eq!(first_on_date(&stamps, d(3), date_of), None);
        assert_eq!(first_on_date(&stamps, d(4), date_of), Some(3));
        assert_eq!(first_on_date(&stamps, d(5), date_of), None);
        assert_eq!(first_on_date(&[], d(1), date_of), None);
    }

    #[test]
    fn list_selection_clamps() {
        let item = Item {
            conversation: "a".into(),
            key: MessageKey {
                timestamp_ms: 1,
                outgoing: false,
                author: "x".into(),
            },
            head: String::new(),
            detail: String::new(),
            url: None,
            attachment: None,
        };
        let mut view = BrowseView::new(Kind::Links, "t".into(), vec![item; 12]);
        view.page = 4;
        view.step(isize::MAX);
        assert_eq!((view.selected, view.scroll), (11, 8));
        view.step(isize::MIN);
        assert_eq!((view.selected, view.scroll), (0, 0));
        let mut empty = BrowseView::new(Kind::Media, "t".into(), Vec::new());
        empty.step(1);
        assert_eq!(empty.selected, 0);
    }
}
