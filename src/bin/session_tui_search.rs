//! `/search`: find messages in the local history.
//!
//! Message bodies are stored encrypted per row (on top of SQLCipher), so the
//! database cannot match text itself; the history is loaded and decrypted at
//! startup anyway, so the search runs over that copy. The caller snapshots
//! the messages in scope (already without deleted, unsent and disappeared
//! ones) and [`run`] matches them on a blocking worker thread, keeping the
//! UI responsive. Results are capped at [`MAX_HITS`], newest first, and
//! shown a page at a time. Nothing here changes, reads or sends a message.

use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use time::Date;

use super::session_tui_separators::MessageKey;

/// Most hits kept for one search.
pub const MAX_HITS: usize = 500;
/// Characters of context shown around a hit.
const SNIPPET_CHARS: usize = 64;

pub const USAGE: &str =
    "/search [--all | --chat ID|NAME] [--from YYYY-MM-DD] [--to YYYY-MM-DD] KEYWORD";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    Current,
    All,
    /// A chat by Session ID / group ID or by (part of) its name.
    Chat(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchQuery {
    pub scope: Scope,
    pub from: Option<Date>,
    pub to: Option<Date>,
    pub keyword: String,
}

pub fn parse_date(text: &str) -> Result<Date, String> {
    let bad = || format!("INVALID DATE {text} · USE YYYY-MM-DD");
    let mut parts = text.split('-');
    let (Some(y), Some(m), Some(d), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(bad());
    };
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return Err(bad());
    }
    let year: i32 = y.parse().map_err(|_| bad())?;
    let month: u8 = m.parse().map_err(|_| bad())?;
    let day: u8 = d.parse().map_err(|_| bad())?;
    let month = time::Month::try_from(month).map_err(|_| bad())?;
    Date::from_calendar_date(year, month, day).map_err(|_| bad())
}

/// Parse the text after `/search`. `Ok(None)`: no arguments.
pub fn parse(args: &str) -> Result<Option<SearchQuery>, String> {
    let words: Vec<&str> = args.split_whitespace().collect();
    if words.is_empty() {
        return Ok(None);
    }
    let mut scope = Scope::Current;
    let mut from = None;
    let mut to = None;
    let mut index = 0;
    while index < words.len() {
        let value = || {
            words
                .get(index + 1)
                .copied()
                .ok_or_else(|| format!("{} NEEDS A VALUE · {USAGE}", words[index]))
        };
        match words[index] {
            "--all" => {
                if matches!(scope, Scope::Chat(_)) {
                    return Err("USE --all OR --chat, NOT BOTH".into());
                }
                scope = Scope::All;
                index += 1;
            }
            "--chat" => {
                if scope == Scope::All {
                    return Err("USE --all OR --chat, NOT BOTH".into());
                }
                scope = Scope::Chat(value()?.to_owned());
                index += 2;
            }
            "--from" => {
                from = Some(parse_date(value()?)?);
                index += 2;
            }
            "--to" => {
                to = Some(parse_date(value()?)?);
                index += 2;
            }
            "--" => {
                index += 1;
                break;
            }
            word if word.starts_with("--") => {
                return Err(format!("UNKNOWN OPTION {word} · {USAGE}"));
            }
            _ => break,
        }
    }
    if let (Some(from), Some(to)) = (from, to)
        && from > to
    {
        return Err("--from IS AFTER --to".into());
    }
    let keyword = words[index.min(words.len())..].join(" ");
    if keyword.is_empty() {
        return Err(format!("KEYWORD MISSING · {USAGE}"));
    }
    Ok(Some(SearchQuery {
        scope,
        from,
        to,
        keyword,
    }))
}

/// Chat named by `--chat`: an exact ID, else an exact name (ignoring case),
/// else the only chat whose name or ID contains it.
pub fn resolve_chat(chats: &[(String, String)], wanted: &str) -> Result<String, String> {
    let lowered = wanted.to_lowercase();
    if let Some((id, _)) = chats.iter().find(|(id, _)| id.eq_ignore_ascii_case(wanted)) {
        return Ok(id.clone());
    }
    let exact: Vec<&String> = chats
        .iter()
        .filter(|(_, name)| name.to_lowercase() == lowered)
        .map(|(id, _)| id)
        .collect();
    if exact.len() == 1 {
        return Ok(exact[0].clone());
    }
    let partial: Vec<&String> = chats
        .iter()
        .filter(|(id, name)| {
            name.to_lowercase().contains(&lowered) || id.starts_with(&wanted.to_ascii_lowercase())
        })
        .map(|(id, _)| id)
        .collect();
    match partial.len() {
        1 => Ok(partial[0].clone()),
        0 => Err(format!("NO CHAT MATCHES {wanted}")),
        n => Err(format!("{n} CHATS MATCH {wanted} · BE MORE SPECIFIC")),
    }
}

/// One searchable message (a snapshot, so the search can run off the UI
/// thread).
#[derive(Clone, Debug)]
pub struct SearchDoc {
    pub conversation: String,
    pub conversation_name: String,
    pub key: MessageKey,
    pub sender_label: String,
    /// Body plus attachment file names.
    pub text: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchHit {
    pub conversation: String,
    pub conversation_name: String,
    pub key: MessageKey,
    pub sender_label: String,
    pub snippet: String,
    /// The matched text inside `snippet`, in characters.
    pub match_chars: (usize, usize),
}

/// Simple case folding of one character: Unicode lowercase per character,
/// plus ß → "ss" and final ς → σ. Not full Unicode case folding: other
/// multi-character foldings are not applied.
fn fold(c: char) -> impl Iterator<Item = char> {
    let mut out = Vec::with_capacity(2);
    for lower in c.to_lowercase() {
        match lower {
            'ß' => out.extend(['s', 's']),
            'ς' => out.push('σ'),
            other => out.push(other),
        }
    }
    out.into_iter()
}

/// Byte range of the first match of `needle`, ignoring case as [`fold`]
/// does ("ÄRGER" finds "ärger", "STRASSE" finds "Straße").
pub fn find_ci(haystack: &str, needle: &str) -> Option<(usize, usize)> {
    let needle: Vec<char> = needle.chars().flat_map(fold).collect();
    if needle.is_empty() {
        return None;
    }
    // Folded characters with the byte range of the source character.
    let mut lowered: Vec<(char, usize, usize)> = Vec::with_capacity(haystack.len());
    for (start, c) in haystack.char_indices() {
        let end = start + c.len_utf8();
        for folded in fold(c) {
            lowered.push((folded, start, end));
        }
    }
    if lowered.len() < needle.len() {
        return None;
    }
    (0..=lowered.len() - needle.len())
        .find(|&i| {
            lowered[i..i + needle.len()]
                .iter()
                .zip(&needle)
                .all(|((a, _, _), b)| a == b)
        })
        .map(|i| (lowered[i].1, lowered[i + needle.len() - 1].2))
}

/// One-line excerpt around the byte range `hit`, and the hit's character
/// range in it.
pub fn snippet(text: &str, hit: (usize, usize)) -> (String, (usize, usize)) {
    let flat = |s: &str| -> Vec<char> {
        s.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    };
    let before = flat(&text[..hit.0]);
    let matched = flat(&text[hit.0..hit.1]);
    let after = flat(&text[hit.1..]);
    let lead = SNIPPET_CHARS
        .saturating_sub(matched.len())
        .min(20)
        .min(before.len());
    let mut out = String::new();
    let mut offset = 0;
    if lead < before.len() {
        out.push('…');
        offset += 1;
    }
    out.extend(&before[before.len() - lead..]);
    offset += lead;
    out.extend(&matched);
    let tail = SNIPPET_CHARS
        .saturating_sub(lead + matched.len())
        .min(after.len());
    out.extend(&after[..tail]);
    if tail < after.len() {
        out.push('…');
    }
    (out, (offset, offset + matched.len()))
}

/// Match `docs` against `query`, newest first. `date_of` gives a
/// timestamp's local date (the `--from`/`--to` days are local, and `--to`
/// includes its whole day). Returns the hits and whether more were cut off.
pub fn run(
    docs: &[SearchDoc],
    query: &SearchQuery,
    date_of: impl Fn(u64) -> Option<Date>,
) -> (Vec<SearchHit>, bool) {
    let mut order: Vec<&SearchDoc> = docs.iter().collect();
    order.sort_by_key(|doc| std::cmp::Reverse(doc.key.timestamp_ms));
    let mut hits = Vec::new();
    for doc in order {
        if query.from.is_some() || query.to.is_some() {
            let Some(date) = date_of(doc.key.timestamp_ms) else {
                continue;
            };
            if query.from.is_some_and(|from| date < from) || query.to.is_some_and(|to| date > to) {
                continue;
            }
        }
        let Some(range) = find_ci(&doc.text, &query.keyword) else {
            continue;
        };
        if hits.len() == MAX_HITS {
            return (hits, true);
        }
        let (snippet, match_chars) = snippet(&doc.text, range);
        hits.push(SearchHit {
            conversation: doc.conversation.clone(),
            conversation_name: doc.conversation_name.clone(),
            key: doc.key.clone(),
            sender_label: doc.sender_label.clone(),
            snippet,
            match_chars,
        });
    }
    (hits, false)
}

/// The search panel.
pub struct SearchView {
    /// What was searched, for the title.
    pub title: String,
    pub hits: Vec<SearchHit>,
    pub truncated: bool,
    pub running: bool,
    /// Usage or error text instead of results.
    pub notice: Option<String>,
    pub selected: usize,
    pub scroll: usize,
    /// Result rows on screen at the last draw (for paging).
    pub page: usize,
}

impl SearchView {
    pub fn notice(text: impl Into<String>) -> Self {
        Self {
            title: "Search".into(),
            hits: Vec::new(),
            truncated: false,
            running: false,
            notice: Some(text.into()),
            selected: 0,
            scroll: 0,
            page: 10,
        }
    }

    pub fn running(title: String) -> Self {
        Self {
            title,
            running: true,
            notice: None,
            ..Self::notice("")
        }
    }

    pub fn finish(&mut self, hits: Vec<SearchHit>, truncated: bool) {
        self.hits = hits;
        self.truncated = truncated;
        self.running = false;
        self.selected = 0;
        self.scroll = 0;
    }

    /// Move the selection by `delta` rows, keeping it on screen.
    pub fn step(&mut self, delta: isize) {
        if self.hits.is_empty() {
            return;
        }
        let last = self.hits.len() - 1;
        self.selected = (self.selected as isize + delta).clamp(0, last as isize) as usize;
        let page = self.page.max(1);
        if self.selected < self.scroll {
            self.scroll = self.selected;
        } else if self.selected >= self.scroll + page {
            self.scroll = self.selected + 1 - page;
        }
    }

    pub fn current(&self) -> Option<&SearchHit> {
        self.hits.get(self.selected)
    }
}

/// Draw the panel over `area`. `format_time` renders a timestamp;
/// `exists` says whether a hit's message is still there (it may have
/// disappeared or been deleted since the search).
pub fn draw(
    frame: &mut ratatui::Frame<'_>,
    area: Rect,
    view: &mut SearchView,
    format_time: impl Fn(u64) -> String,
    exists: impl Fn(&SearchHit) -> bool,
) {
    use super::{BG, MUTED, PANEL, TEAL, TEXT};
    let width = area.width.saturating_sub(6).clamp(30, 110);
    let height = area.height.saturating_sub(4).clamp(8, 40);
    let rect = super::centered_cells(width, height, area);
    frame.render_widget(Clear, rect);
    let count = if view.running {
        "searching…".to_owned()
    } else if view.notice.is_some() {
        String::new()
    } else if view.truncated {
        format!("newest {} hits", view.hits.len())
    } else {
        format!("{} hits", view.hits.len())
    };
    let block = Block::default()
        .title(format!(" {} · {count} ", view.title))
        .title_bottom(" ↑/↓ PgUp/PgDn select · Enter open · Esc close ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(TEAL))
        .style(Style::default().bg(PANEL));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if let Some(notice) = &view.notice {
        for line in notice.lines() {
            lines.push(Line::from(Span::styled(
                format!(" {line}"),
                Style::default().fg(TEXT),
            )));
        }
    } else if !view.running && view.hits.is_empty() {
        lines.push(Line::from(Span::styled(
            " No messages found.",
            Style::default().fg(MUTED),
        )));
    }
    // Two rows per hit: chat · sender · time, then the excerpt.
    view.page = (inner.height as usize / 2).max(1);
    if view.notice.is_none() {
        let end = (view.scroll + view.page).min(view.hits.len());
        for index in view.scroll..end {
            let hit = &view.hits[index];
            let selected = index == view.selected;
            let gone = !exists(hit);
            let base = if selected {
                Style::default().bg(BG).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            lines.push(Line::from(vec![
                Span::styled(if selected { " ▸ " } else { "   " }, base.fg(TEAL)),
                Span::styled(hit.conversation_name.clone(), base.fg(TEXT)),
                Span::styled(format!(" · {}", hit.sender_label), base.fg(TEAL)),
                Span::styled(
                    format!(" · {}", format_time(hit.key.timestamp_ms)),
                    base.fg(MUTED),
                ),
                Span::styled(
                    if gone { "  (no longer available)" } else { "" },
                    base.fg(MUTED),
                ),
            ]));
            let chars: Vec<char> = hit.snippet.chars().collect();
            let (start, end) = hit.match_chars;
            let text_style = Style::default().fg(if gone { MUTED } else { TEXT });
            lines.push(Line::from(vec![
                Span::raw("     "),
                Span::styled(chars[..start].iter().collect::<String>(), text_style),
                Span::styled(
                    chars[start..end].iter().collect::<String>(),
                    Style::default()
                        .fg(BG)
                        .bg(TEAL)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(chars[end..].iter().collect::<String>(), text_style),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

// ---------------------------------------------------------------------------
// Glue to the app state.
// ---------------------------------------------------------------------------

use super::{App, now_ms};

/// `/search ARGS`. Opens the panel and starts the search off the UI thread.
pub(super) fn command(app: &mut App, args: &str) {
    let query = match parse(args) {
        Ok(Some(query)) => query,
        Ok(None) => {
            // Back to the last results, or the usage.
            app.search = app.last_search.take().or_else(|| {
                Some(SearchView::notice(format!(
                    "Usage: {USAGE}\n\n\
                     /search WORD                 this chat\n\
                     /search --all WORD           all chats\n\
                     /search --chat NAME|ID WORD  one chat\n\
                     --from / --to YYYY-MM-DD     local dates, both inclusive\n\n\
                     Case-insensitive. Disappeared and deleted messages are never found."
                )))
            });
            return;
        }
        Err(error) => {
            app.search = Some(SearchView::notice(error));
            return;
        }
    };
    let chats: Vec<(String, String)> = app
        .conversations
        .iter()
        .map(|c| (c.id.clone(), c.title(&app.local_id).to_owned()))
        .collect();
    let scope: Option<String> = match &query.scope {
        Scope::All => None,
        Scope::Current => match app.conversations.get(app.selected) {
            Some(c) => Some(c.id.clone()),
            None => {
                app.search = Some(SearchView::notice("NO CHAT OPEN · USE --all OR --chat"));
                return;
            }
        },
        Scope::Chat(wanted) => match resolve_chat(&chats, wanted) {
            Ok(id) => Some(id),
            Err(error) => {
                app.search = Some(SearchView::notice(error));
                return;
            }
        },
    };
    let now = now_ms();
    let mut docs = Vec::new();
    for conversation in &app.conversations {
        if scope.as_ref().is_some_and(|id| *id != conversation.id) {
            continue;
        }
        let name = conversation.title(&app.local_id).to_owned();
        for message in &conversation.messages {
            // Notices aren't conversation text; a message past its
            // disappearing deadline must not come back through search.
            if message.system || message.expires_at.is_some_and(|at| at <= now) {
                continue;
            }
            let mut text = message.body.clone();
            for attachment in &message.attachments {
                if !text.is_empty() {
                    text.push(' ');
                }
                text.push_str(&attachment.file_name);
            }
            if text.is_empty() {
                continue;
            }
            let key = message.key(&conversation.id, &app.local_id);
            docs.push(SearchDoc {
                conversation: conversation.id.clone(),
                conversation_name: name.clone(),
                sender_label: app.sender_label(&key.author),
                key,
                text,
            });
        }
    }
    let where_ = match &scope {
        None => "all chats".to_owned(),
        Some(id) => chats
            .iter()
            .find(|(chat, _)| chat == id)
            .map_or_else(String::new, |(_, name)| name.clone()),
    };
    let mut title = format!("“{}” in {where_}", query.keyword);
    if query.from.is_some() || query.to.is_some() {
        let show = |d: Option<Date>| d.map_or_else(|| "…".to_owned(), |d| d.to_string());
        title.push_str(&format!(" · {} → {}", show(query.from), show(query.to)));
    }
    if let Some(task) = app.search_task.take() {
        task.abort();
    }
    app.search = Some(SearchView::running(title));
    app.search_task = Some(tokio::task::spawn_blocking(move || {
        run(&docs, &query, super::session_tui_separators::local_date)
    }));
}

pub(super) fn exists(app: &App, hit: &SearchHit) -> bool {
    super::session_tui_browse::locate(app, &hit.conversation, &hit.key).is_some()
}

/// Open the chat of the selected hit at that message (the shared jump).
pub(super) fn jump(app: &mut App) -> Result<(), String> {
    let hit = app
        .search
        .as_ref()
        .and_then(SearchView::current)
        .cloned()
        .ok_or("NO RESULT SELECTED")?;
    super::session_tui_browse::open_message(app, &hit.conversation, &hit.key)?;
    app.last_search = app.search.take();
    Ok(())
}

/// Keys while the panel is open.
pub(super) fn handle_key(app: &mut App, code: crossterm::event::KeyCode) {
    use crossterm::event::KeyCode;
    let Some(view) = app.search.as_mut() else {
        return;
    };
    let page = view.page.max(1) as isize;
    match code {
        KeyCode::Esc => {
            let view = app.search.take();
            // Keep results (not a usage/error notice) for `/search`.
            if view.as_ref().is_some_and(|v| v.notice.is_none()) {
                app.last_search = view;
            }
        }
        KeyCode::Up => view.step(-1),
        KeyCode::Down => view.step(1),
        KeyCode::PageUp => view.step(-page),
        KeyCode::PageDown => view.step(page),
        KeyCode::Home => view.step(isize::MIN / 2),
        KeyCode::End => view.step(isize::MAX / 2),
        KeyCode::Enter if view.notice.is_some() => app.search = None,
        KeyCode::Enter => {
            if let Err(error) = jump(app) {
                app.status = error.to_owned();
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(y: i32, m: u8, day: u8) -> Date {
        Date::from_calendar_date(y, time::Month::try_from(m).unwrap(), day).unwrap()
    }

    #[test]
    fn parses_scopes_dates_and_keywords() {
        assert_eq!(parse("").unwrap(), None);
        let q = parse("hello world").unwrap().unwrap();
        assert_eq!(q.scope, Scope::Current);
        assert_eq!(q.keyword, "hello world");
        let q = parse("--all --from 2026-01-02 --to 2026-01-31 Ärger")
            .unwrap()
            .unwrap();
        assert_eq!(q.scope, Scope::All);
        assert_eq!(q.from, Some(d(2026, 1, 2)));
        assert_eq!(q.to, Some(d(2026, 1, 31)));
        assert_eq!(q.keyword, "Ärger");
        let q = parse("--chat Alice --to 2026-02-28 x").unwrap().unwrap();
        assert_eq!(q.scope, Scope::Chat("Alice".into()));
        assert_eq!(parse("-- --all").unwrap().unwrap().keyword, "--all");
        assert!(parse("--all --chat a x").is_err());
        assert!(parse("--from 2026-02-30 x").is_err());
        assert!(parse("--from 2026-3-01 x").is_err());
        assert!(parse("--from 2026-03-02 --to 2026-03-01 x").is_err());
        assert!(parse("--all").is_err());
        assert!(parse("--chat").is_err());
        assert!(parse("--bogus x").is_err());
    }

    #[test]
    fn resolves_chats_by_id_or_name() {
        let chats = vec![
            ("05aa11".to_owned(), "Alice".to_owned()),
            ("05bb22".to_owned(), "Alicia".to_owned()),
            ("03cc33".to_owned(), "Team 群".to_owned()),
        ];
        assert_eq!(resolve_chat(&chats, "05BB22").unwrap(), "05bb22");
        assert_eq!(resolve_chat(&chats, "alice").unwrap(), "05aa11");
        assert_eq!(resolve_chat(&chats, "群").unwrap(), "03cc33");
        assert_eq!(resolve_chat(&chats, "03c").unwrap(), "03cc33");
        assert!(resolve_chat(&chats, "ali").is_err());
        assert!(resolve_chat(&chats, "zed").is_err());
    }

    #[test]
    fn case_insensitive_unicode_matching() {
        assert_eq!(find_ci("Hello World", "world"), Some((6, 11)));
        assert_eq!(find_ci("ÄRGER im Büro", "ärger"), Some((0, 6)));
        assert_eq!(find_ci("Ελληνικά ΣΟΦΙΑ", "σοφια"), Some((17, 27)));
        assert_eq!(find_ci("时间太短", "太短"), Some((6, 12)));
        assert_eq!(find_ci("abc", ""), None);
        // ß folds to "ss" both ways; final sigma matches σ.
        assert_eq!(find_ci("Die Straße", "STRASSE"), Some((4, 11)));
        assert_eq!(find_ci("STRASSE", "straße"), Some((0, 7)));
        assert_eq!(find_ci("ΟΔΟΣ", "οδος"), Some((0, 8)));
        // Half of a folded ß is no match boundary problem: it maps back to ß.
        let (s, e) = find_ci("Maß", "s").unwrap();
        assert_eq!(&"Maß"[s..e], "ß");
        assert_eq!(find_ci("ab", "abc"), None);
        // Multi-char lowercase (İ → i̇) keeps byte ranges on char boundaries.
        let (s, e) = find_ci("xİy", "i\u{307}").unwrap();
        assert_eq!(&"xİy"[s..e], "İ");
    }

    #[test]
    fn snippet_is_one_line_and_marks_the_hit() {
        let text = format!("{}\nneedle here\n{}", "a".repeat(100), "b".repeat(100));
        let range = find_ci(&text, "NEEDLE").unwrap();
        let (snippet, (s, e)) = snippet(&text, range);
        let chars: Vec<char> = snippet.chars().collect();
        assert_eq!(chars[s..e].iter().collect::<String>(), "needle");
        assert!(!snippet.contains('\n'));
        assert!(snippet.starts_with('…') && snippet.ends_with('…'));
        assert!(chars.len() <= SNIPPET_CHARS + 2);
        let (short, range) = snippet_of("短消息", "消息");
        assert_eq!(short, "短消息");
        assert_eq!(range, (1, 3));
    }

    fn snippet_of(text: &str, needle: &str) -> (String, (usize, usize)) {
        snippet(text, find_ci(text, needle).unwrap())
    }

    fn doc(conversation: &str, ts: u64, author: &str, text: &str) -> SearchDoc {
        SearchDoc {
            conversation: conversation.into(),
            conversation_name: conversation.into(),
            key: MessageKey {
                timestamp_ms: ts,
                outgoing: false,
                author: author.into(),
            },
            sender_label: author.into(),
            text: text.into(),
        }
    }

    #[test]
    fn newest_first_with_inclusive_local_dates() {
        let day = 86_400_000;
        let docs = vec![
            doc("a", day, "x", "foo one"),
            doc("a", 3 * day - 1, "x", "foo two"),
            doc("g", 3 * day - 1, "y", "FOO group, same ms other sender"),
            doc("a", 3 * day, "x", "foo three"),
            doc("a", 3 * day + 5, "x", "nothing"),
        ];
        let query = parse("foo").unwrap().unwrap();
        let date_of = |ms: u64| {
            time::OffsetDateTime::from_unix_timestamp((ms / 1000) as i64)
                .ok()
                .map(|t| t.date())
        };
        let (hits, cut) = run(&docs, &query, date_of);
        assert!(!cut);
        assert_eq!(hits.len(), 4);
        assert_eq!(hits[0].key.timestamp_ms, 3 * day);
        // Same millisecond, different groups/senders: distinct keys.
        assert_ne!(hits[1].key, hits[2].key);
        // Both ends inclusive: 1970-01-03 runs to 3d-1 ms; 3d is the 4th.
        let query = parse("--from 1970-01-03 --to 1970-01-03 foo")
            .unwrap()
            .unwrap();
        let (hits, _) = run(&docs, &query, date_of);
        let stamps: Vec<u64> = hits.iter().map(|h| h.key.timestamp_ms).collect();
        assert_eq!(stamps, [3 * day - 1, 3 * day - 1]);
        let query = parse("--from 1970-01-02 foo").unwrap().unwrap();
        assert_eq!(run(&docs, &query, date_of).0.len(), 4);
        let query = parse("--to 1970-01-02 foo").unwrap().unwrap();
        let (hits, _) = run(&docs, &query, date_of);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].key.timestamp_ms, day);
    }

    #[test]
    fn caps_hits() {
        let docs: Vec<SearchDoc> = (0..MAX_HITS as u64 + 10)
            .map(|i| doc("a", i, "x", "hit"))
            .collect();
        let (hits, cut) = run(&docs, &parse("hit").unwrap().unwrap(), |_| None);
        assert!(cut);
        assert_eq!(hits.len(), MAX_HITS);
        assert_eq!(hits[0].key.timestamp_ms, MAX_HITS as u64 + 9);
    }

    #[test]
    fn view_selection_stays_on_page() {
        let mut view = SearchView::running("t".into());
        let hits: Vec<SearchHit> = (0..30)
            .map(|i| SearchHit {
                conversation: "a".into(),
                conversation_name: "a".into(),
                key: MessageKey {
                    timestamp_ms: i,
                    outgoing: false,
                    author: "x".into(),
                },
                sender_label: "x".into(),
                snippet: "s".into(),
                match_chars: (0, 1),
            })
            .collect();
        view.finish(hits, false);
        view.page = 5;
        view.step(7);
        assert_eq!((view.selected, view.scroll), (7, 3));
        view.step(-100);
        assert_eq!((view.selected, view.scroll), (0, 0));
        view.step(100);
        assert_eq!((view.selected, view.scroll), (29, 25));
    }
}
