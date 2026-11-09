//! Local UI state kept in the encrypted history database: per-chat drafts,
//! pinned chats and bookmarks. None of it is synced to other devices or sent
//! anywhere, and none of it changes a message.
//!
//! Schema changes are versioned (`settings.local_ui_schema`) and applied in
//! one transaction, so an old database is upgraded completely or not at all.
//! The tables are new; existing tables and rows are not touched. A database
//! opened by this version still works with older versions of the client,
//! which simply ignore the extra tables.
//!
//! Draft text is encrypted like message bodies (on top of SQLCipher).
//! Bookmarks store only a reference to the message, never its text.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rusqlite::{Connection, params};

use super::session_tui_separators::MessageKey;
use super::{App, InputMode, LocalStore};

/// Current version of the local UI tables.
pub const LOCAL_UI_SCHEMA: i64 = 1;

/// Typing pauses this long before a draft is written.
const DRAFT_DEBOUNCE: Duration = Duration::from_millis(800);

/// Bring the local UI tables up to [`LOCAL_UI_SCHEMA`].
pub fn migrate(connection: &Connection) -> Result<(), String> {
    let version: i64 = connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'local_ui_schema'",
            [],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if version >= LOCAL_UI_SCHEMA {
        return Ok(());
    }
    connection
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE IF NOT EXISTS drafts (
                peer TEXT PRIMARY KEY,
                body BLOB NOT NULL,
                cursor INTEGER NOT NULL DEFAULT 0,
                updated_ms INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS pinned_chats (
                peer TEXT PRIMARY KEY,
                pinned_ms INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS bookmarks (
                peer TEXT NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                outgoing INTEGER NOT NULL,
                author TEXT NOT NULL,
                created_ms INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(peer, timestamp_ms, outgoing, author)
             );
             INSERT INTO settings(key, value) VALUES ('local_ui_schema', '1')
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
             COMMIT;",
        )
        .map_err(|e| {
            let _ = connection.execute_batch("ROLLBACK");
            format!("local UI schema upgrade: {e}")
        })
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

impl LocalStore {
    pub(super) fn load_drafts(&self) -> HashMap<String, (String, usize)> {
        let Ok(mut statement) = self
            .connection
            .prepare("SELECT peer, body, cursor FROM drafts")
        else {
            return HashMap::new();
        };
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        });
        let mut drafts = HashMap::new();
        for (peer, body, cursor) in rows.into_iter().flatten().flatten() {
            if let Ok(text) = self.decrypt_body(&body)
                && !text.is_empty()
            {
                let cursor = super::session_tui_input::clamp(&text, cursor.max(0) as usize);
                drafts.insert(peer, (text, cursor));
            }
        }
        drafts
    }

    /// Save (or, for empty text, remove) the draft of `peer`.
    pub(super) fn save_draft(&self, peer: &str, text: &str, cursor: usize) -> Result<(), String> {
        if text.is_empty() {
            return self
                .exec("DELETE FROM drafts WHERE peer = ?1", params![peer])
                .map(|_| ())
                .map_err(|e| e.to_string());
        }
        let body = self.encrypt_body(text)?;
        self.exec(
            "INSERT INTO drafts(peer, body, cursor, updated_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer) DO UPDATE SET body = excluded.body, cursor = excluded.cursor,
                updated_ms = excluded.updated_ms",
            params![peer, body, cursor as i64, super::now_ms() as i64],
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
    }

    pub(super) fn load_pins(&self) -> HashSet<String> {
        let Ok(mut statement) = self.connection.prepare("SELECT peer FROM pinned_chats") else {
            return HashSet::new();
        };
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    pub(super) fn set_pinned(&self, peer: &str, pinned: bool) -> Result<(), String> {
        let result = if pinned {
            self.exec(
                "INSERT OR IGNORE INTO pinned_chats(peer, pinned_ms) VALUES (?1, ?2)",
                params![peer, super::now_ms() as i64],
            )
        } else {
            self.exec("DELETE FROM pinned_chats WHERE peer = ?1", params![peer])
        };
        result.map(|_| ()).map_err(|e| e.to_string())
    }

    pub(super) fn load_bookmarks(&self) -> HashSet<(String, MessageKey)> {
        let Ok(mut statement) = self
            .connection
            .prepare("SELECT peer, timestamp_ms, outgoing, author FROM bookmarks")
        else {
            return HashSet::new();
        };
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    MessageKey {
                        timestamp_ms: row.get::<_, i64>(1)? as u64,
                        outgoing: row.get(2)?,
                        author: row.get(3)?,
                    },
                ))
            })
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    /// `Ok(false)`: it was already in that state.
    pub(super) fn set_bookmark(
        &self,
        peer: &str,
        key: &MessageKey,
        bookmarked: bool,
    ) -> Result<bool, String> {
        let changed = if bookmarked {
            self.exec(
                "INSERT OR IGNORE INTO bookmarks(peer, timestamp_ms, outgoing, author, created_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    peer,
                    key.timestamp_ms as i64,
                    key.outgoing,
                    key.author,
                    super::now_ms() as i64
                ],
            )
        } else {
            self.exec(
                "DELETE FROM bookmarks WHERE peer = ?1 AND timestamp_ms = ?2 AND outgoing = ?3 AND author = ?4",
                params![peer, key.timestamp_ms as i64, key.outgoing, key.author],
            )
        };
        changed.map(|n| n > 0).map_err(|e| e.to_string())
    }

    /// Remove drafts, pin and bookmarks of a chat that is gone.
    pub(super) fn forget_chat_state(&self, peer: &str) {
        for sql in [
            "DELETE FROM drafts WHERE peer = ?1",
            "DELETE FROM pinned_chats WHERE peer = ?1",
            "DELETE FROM bookmarks WHERE peer = ?1",
        ] {
            let _ = self.exec(sql, params![peer]);
        }
    }
}

// ---------------------------------------------------------------------------
// Drafts in the app
// ---------------------------------------------------------------------------

/// Composer drafts per chat. The composer always shows the open chat's
/// draft; switching chats stores it and brings back the other one.
#[derive(Default)]
pub struct Drafts {
    /// Drafts by chat, as last stored (text, cursor).
    saved: HashMap<String, (String, usize)>,
    /// Chat the composer text belongs to.
    current: Option<String>,
    /// The composer changed at this instant and isn't written yet.
    dirty_since: Option<Instant>,
    /// The composer last held a command: the emptying that follows running
    /// it is not the user clearing the draft.
    command_typed: bool,
    /// Chats whose draft failed to save, retried until written.
    unsaved: HashSet<String>,
    retry_at: Option<Instant>,
}

impl Drafts {
    pub fn new(saved: HashMap<String, (String, usize)>) -> Self {
        Self {
            saved,
            ..Self::default()
        }
    }
}

/// What the composer holds counts as a draft unless it is a command
/// being typed (e.g. `/1` to switch chats must not replace the draft).
fn is_draft_text(text: &str) -> bool {
    !text.starts_with('/')
}

/// Write `peer`'s draft as held in memory. A failure keeps it in memory
/// and marks it for retry (every turn after a pause, and on quit).
fn persist(app: &mut App, store: &LocalStore, peer: &str, now: Instant) -> bool {
    let (text, cursor) = app.drafts.saved.get(peer).cloned().unwrap_or_default();
    match store.save_draft(peer, &text, cursor) {
        Ok(()) => {
            app.drafts.unsaved.remove(peer);
            true
        }
        Err(error) => {
            app.drafts.unsaved.insert(peer.to_owned());
            app.drafts.retry_at = Some(now + DRAFT_DEBOUNCE);
            app.status = format!("DRAFT NOT SAVED · WILL RETRY · {error}");
            false
        }
    }
}

fn retry_unsaved(app: &mut App, store: &LocalStore, now: Instant) {
    if app.drafts.unsaved.is_empty() || app.drafts.retry_at.is_some_and(|at| now < at) {
        return;
    }
    let peers: Vec<String> = app.drafts.unsaved.iter().cloned().collect();
    for peer in peers {
        if !persist(app, store, &peer, now) {
            break;
        }
    }
}

/// Run every loop turn: follow the open chat and write drafts.
pub(super) fn sync_drafts(app: &mut App, store: &LocalStore) {
    sync_drafts_at(app, store, Instant::now());
}

pub(super) fn sync_drafts_at(app: &mut App, store: &LocalStore, now: Instant) {
    if app.input_mode != InputMode::Message {
        return;
    }
    let open = app.conversations.get(app.selected).map(|c| c.id.clone());
    if open != app.drafts.current {
        // The chat we left was recorded on the previous turn (switching is
        // its own key or click; a command like `/2` clears the composer
        // first, which must not count). Write it if pending, then show the
        // new chat's draft.
        if let Some(previous) = app.drafts.current.take()
            && app.drafts.dirty_since.take().is_some()
        {
            persist(app, store, &previous, now);
        }
        app.drafts.command_typed = false;
        let (text, cursor) = open
            .as_ref()
            .and_then(|id| app.drafts.saved.get(id).cloned())
            .unwrap_or_default();
        // Don't throw away a command being typed while switching (`/2`).
        if is_draft_text(&app.input) || !text.is_empty() {
            app.input = text;
            app.cursor = cursor;
        }
        app.drafts.current = open;
        return;
    }
    retry_unsaved(app, store, now);
    let Some(peer) = open else {
        return;
    };
    if record(app, &peer) {
        if app.input.is_empty() {
            // Sent or cleared: remove it right away.
            app.drafts.dirty_since = None;
            persist(app, store, &peer, now);
        } else {
            app.drafts.dirty_since.get_or_insert(now);
        }
    }
    if app
        .drafts
        .dirty_since
        .is_some_and(|since| now.saturating_duration_since(since) >= DRAFT_DEBOUNCE)
    {
        app.drafts.dirty_since = None;
        persist(app, store, &peer, now);
    }
}

/// Take the composer into `saved` for `peer`. `true` if it changed.
fn record(app: &mut App, peer: &str) -> bool {
    if !is_draft_text(&app.input) {
        app.drafts.command_typed = true;
        return false;
    }
    if std::mem::take(&mut app.drafts.command_typed) && app.input.is_empty() {
        // A command ran and cleared the composer: the draft stays.
        return false;
    }
    let entry = (app.input.clone(), app.cursor);
    if app.drafts.saved.get(peer) == Some(&entry)
        || (app.input.is_empty() && !app.drafts.saved.contains_key(peer))
    {
        return false;
    }
    if app.input.is_empty() {
        app.drafts.saved.remove(peer);
    } else {
        app.drafts.saved.insert(peer.to_owned(), entry);
    }
    true
}

/// Write the open chat's draft and any unsaved ones now (quit).
pub(super) fn flush_drafts(app: &mut App, store: &LocalStore) {
    let now = Instant::now();
    if let Some(peer) = app.drafts.current.clone() {
        if app.input_mode == InputMode::Message {
            record(app, &peer);
        }
        app.drafts.dirty_since = None;
        persist(app, store, &peer, now);
    }
    app.drafts.retry_at = None;
    retry_unsaved(app, store, now);
}

/// A chat was deleted: drop its draft, pin and bookmarks.
pub(super) fn forget_chat(app: &mut App, store: &LocalStore, peer: &str) {
    app.drafts.saved.remove(peer);
    app.drafts.unsaved.remove(peer);
    if app.drafts.current.as_deref() == Some(peer) {
        app.drafts.current = None;
        app.drafts.dirty_since = None;
        app.input.clear();
        app.cursor = 0;
    }
    app.pinned.remove(peer);
    app.bookmarks.retain(|(chat, _)| chat != peer);
    store.forget_chat_state(peer);
}

/// Load drafts, pins and bookmarks into the app.
pub(super) fn load(app: &mut App, store: &LocalStore) {
    app.drafts = Drafts::new(store.load_drafts());
    app.pinned = store.load_pins();
    app.bookmarks = store.load_bookmarks();
}
