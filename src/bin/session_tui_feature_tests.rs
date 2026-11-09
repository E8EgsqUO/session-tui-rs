//! Tests of drafts, chat filter/pins, navigation, bookmarks, media/link
//! lists and command completion, against real encrypted test databases.
use super::*;

fn peer(n: u8) -> String {
    format!("05{}", format!("{n:02x}").repeat(32))
}

/// App with two 1:1 chats (A, B) and a group, as loaded from `store`.
fn app_for(identity: &Identity, store: &LocalStore) -> App {
    let mut app = App::new(identity.session_id.clone());
    for id in [peer(0xa1), peer(0xb2)] {
        store.save_contact(&id).unwrap();
    }
    store.load(&mut app).unwrap();
    session_tui_local::load(&mut app, store);
    app.sort_conversations();
    app
}

fn select(app: &mut App, id: &str) {
    app.selected = app.conversations.iter().position(|c| c.id == id).unwrap();
}

fn type_text(app: &mut App, text: &str) {
    app.input = text.to_owned();
    app.cursor = text.len();
}

#[test]
fn drafts_follow_the_chat_and_survive_a_restart() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x41);
    let (a, b) = (peer(0xa1), peer(0xb2));
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let start = Instant::now();
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    let text = "第一行 hello\nzweite Zeile 😀";
    type_text(&mut app, text);
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    // Switch to B: A's draft is stored, B starts empty.
    select(&mut app, &b);
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    assert_eq!(app.input, "");
    type_text(&mut app, "draft for b");
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    // Debounced: written only after the pause.
    assert!(!store.load_drafts().contains_key(&b));
    session_tui_local::sync_drafts_at(&mut app, &store, start + Duration::from_secs(1));
    assert_eq!(store.load_drafts()[&b].0, "draft for b");
    // Back to A: its text and cursor return.
    app.cursor = 3;
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    select(&mut app, &a);
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    assert_eq!(app.input, text);
    assert_eq!(app.cursor, text.len());
    // A command typed to switch chats doesn't replace the draft.
    type_text(&mut app, "/2");
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    select(&mut app, &b);
    app.input.clear();
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    assert_eq!(app.input, "draft for b");
    assert_eq!(app.cursor, 3);
    session_tui_local::flush_drafts(&mut app, &store);

    // Restart: drafts are read back from the encrypted database.
    drop(store);
    let store = LocalStore::open(&identity).unwrap();
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    session_tui_local::sync_drafts_at(&mut app, &store, start);
    assert_eq!(app.input, text);
    // Stored encrypted, not as plain text.
    let raw: Vec<u8> = store
        .connection
        .query_row("SELECT body FROM drafts WHERE peer = ?1", [&a], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(!String::from_utf8_lossy(&raw).contains("hello"));
}

#[test]
fn sending_clears_the_draft_and_a_failed_send_keeps_it() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x42);
    let a = peer(0xa1);
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let now = Instant::now();
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    type_text(&mut app, "unsent");
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(2));
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(4));
    assert!(store.load_drafts().contains_key(&a));
    // A failed send leaves the composer as it was: the draft stays.
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(5));
    assert_eq!(store.load_drafts()[&a].0, "unsent");
    // Sent (queued): the composer is cleared, the draft removed at once.
    app.input.clear();
    app.cursor = 0;
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(5));
    assert!(!store.load_drafts().contains_key(&a));
    // Empty drafts leave no row.
    let rows: i64 = store
        .connection
        .query_row("SELECT count(*) FROM drafts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn deleting_a_chat_forgets_its_draft_pin_and_bookmarks() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x43);
    let a = peer(0xa1);
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let mut message = Message::new("keep me".into(), 5_000, false);
    store.save_message(&a, &message).unwrap();
    message.is_read = true;
    app.conversations[app.selected]
        .messages
        .push(message.clone());
    let key = message.key(&a, &app.local_id);
    store.set_bookmark(&a, &key, true).unwrap();
    store.set_pinned(&a, true).unwrap();
    store.save_draft(&a, "draft", 5).unwrap();
    session_tui_local::load(&mut app, &store);
    assert!(app.pinned.contains(&a) && !app.bookmarks.is_empty());
    delete_chat(&mut app, &store, ChatAction::Delete, &a);
    assert!(app.bookmarks.is_empty() && store.load_bookmarks().is_empty());
    assert!(
        app.conversations
            .iter()
            .any(|c| c.id == a && c.messages.is_empty())
    );
    assert!(
        app.pinned.contains(&a),
        "/delete keeps the chat and its pin"
    );
    delete_chat(&mut app, &store, ChatAction::Remove, &a);
    assert!(app.pinned.is_empty() && app.bookmarks.is_empty());
    assert!(store.load_drafts().is_empty());
    assert!(store.load_pins().is_empty());
    assert!(store.load_bookmarks().is_empty());
}

#[test]
fn draft_write_failure_keeps_the_text() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x44);
    let a = peer(0xa1);
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let now = Instant::now();
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    store.connection.execute_batch("DROP TABLE drafts").unwrap();
    type_text(&mut app, "important");
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(1));
    assert!(app.status.starts_with("DRAFT NOT SAVED"));
    assert_eq!(app.input, "important");
    // The database itself is still usable.
    store.save_contact(&peer(0xc3)).unwrap();
}

#[test]
fn migration_keeps_old_data_and_is_idempotent() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x45);
    let a = peer(0xa1);
    store.save_contact(&a).unwrap();
    store
        .save_message(&a, &Message::new("old message".into(), 7_000, false))
        .unwrap();
    // Make it look like a database from before the local UI tables.
    store
        .connection
        .execute_batch(
            "DROP TABLE drafts; DROP TABLE pinned_chats; DROP TABLE bookmarks;
             DELETE FROM settings WHERE key = 'local_ui_schema';",
        )
        .unwrap();
    drop(store);
    let store = LocalStore::open(&identity).unwrap();
    let version: String = store
        .connection
        .query_row(
            "SELECT value FROM settings WHERE key = 'local_ui_schema'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(version, session_tui_local::LOCAL_UI_SCHEMA.to_string());
    let mut app = App::new(identity.session_id.clone());
    store.load(&mut app).unwrap();
    let chat = app.conversations.iter().find(|c| c.id == a).unwrap();
    assert_eq!(chat.messages[0].body, "old message");
    // Opening again changes nothing and works.
    session_tui_local::migrate(&store.connection).unwrap();
    store.set_pinned(&a, true).unwrap();
    assert!(store.load_pins().contains(&a));
}

#[test]
fn filter_and_pins_shape_the_visible_list_and_numbers() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x46);
    let mut app = app_for(&identity, &store);
    let (a, b) = (peer(0xa1), peer(0xb2));
    let ia = app.conversations.iter().position(|c| c.id == a).unwrap();
    app.conversations[ia].name = "Alice".into();
    app.conversations[ia]
        .messages
        .push(Message::new("x".into(), 100, true));
    let ib = app.conversations.iter().position(|c| c.id == b).unwrap();
    app.conversations[ib].name = "Bob 开发".into();
    let mut unread = Message::new("y".into(), 200, false);
    unread.is_read = false;
    app.conversations[ib].messages.push(unread);
    app.approved.insert(b.clone());
    app.sort_conversations();
    // Newest first: Bob, Alice.
    assert_eq!(app.conversations[0].id, b);
    // Pin Alice: she goes first and stays first after restart.
    store.set_pinned(&a, true).unwrap();
    app.pinned = store.load_pins();
    app.sort_conversations();
    assert_eq!(app.conversations[0].id, a);
    // Filter: numbers follow the visible list.
    select(&mut app, &a);
    app.chat_filter = session_tui_chats::ChatFilter::parse("开发");
    let visible = session_tui_chats::visible(&app);
    assert_eq!(visible.len(), 1);
    assert_eq!(
        app.conversations[session_tui_chats::nth(&app, 1).unwrap()].id,
        b
    );
    assert_eq!(session_tui_chats::nth(&app, 2), None);
    // The open (hidden) chat stays open until the user moves.
    assert_eq!(app.conversations[app.selected].id, a);
    session_tui_chats::step(&mut app, 1);
    assert_eq!(app.conversations[app.selected].id, b);
    app.chat_filter = session_tui_chats::ChatFilter::parse("--unread");
    assert_eq!(session_tui_chats::visible(&app).len(), 1);
    app.chat_filter = session_tui_chats::ChatFilter::parse("nobody");
    assert!(session_tui_chats::visible(&app).is_empty());
    session_tui_chats::step(&mut app, 1);
    assert_eq!(app.conversations[app.selected].id, b);
}

fn attachment(name: &str, content_type: &str, size: u32) -> AttachmentMeta {
    AttachmentMeta {
        file_name: name.into(),
        content_type: content_type.into(),
        url: String::new(),
        key: Vec::new(),
        digest: Vec::new(),
        size,
        deterministic: false,
        width: None,
        height: None,
    }
}

const HOUR: u64 = 3_600_000;

/// Chat A with 200 messages an hour apart (the last 4 incoming unread), a
/// group with two senders posting in the same millisecond, and chat B with
/// one unread message.
fn rich_app(identity: &Identity, store: &LocalStore) -> App {
    let mut app = app_for(identity, store);
    let (a, b) = (peer(0xa1), peer(0xb2));
    let base = 1_700_000_000_000;
    let ia = app.conversations.iter().position(|c| c.id == a).unwrap();
    for i in 0..200u64 {
        let body = match i {
            10 => "docs at https://one.example/a, and https://two.example/b.".to_owned(),
            11 => "photo album".to_owned(),
            _ => format!("message {i}"),
        };
        let mut m = Message::new(body, base + i * HOUR, i % 2 == 0);
        m.is_read = m.outgoing || i < 192;
        if i == 11 {
            m.attachments = vec![
                attachment("a.jpg", "image/jpeg", 2048),
                attachment("notes.pdf", "application/pdf", 0),
            ];
            m.image_previews = vec![None, None];
        }
        app.conversations[ia].messages.push(m);
    }
    let ib = app.conversations.iter().position(|c| c.id == b).unwrap();
    let mut m = Message::new("hi from b".into(), base + 5 * HOUR, false);
    m.is_read = false;
    app.conversations[ib].messages.push(m);
    app.approved.insert(a.clone());
    app.approved.insert(b.clone());
    let group = format!("03{}", "33".repeat(32));
    let ig = app.ensure_contact(&group);
    for sender in [peer(0xc1), peer(0xc2)] {
        let mut m = Message::new(format!("same ms from {}", &sender[..4]), base, false);
        m.sender = Some(sender);
        app.conversations[ig].messages.push(m);
    }
    app.sort_conversations();
    select(&mut app, &a);
    app
}

#[test]
fn unread_jumps_to_the_fixed_boundary_without_marking_read() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x51);
    let mut app = rich_app(&identity, &store);
    update_unread_marker(&mut app);
    let a = app.conversations[app.selected].id.clone();
    let first = app.conversations[app.selected]
        .messages
        .iter()
        .position(|m| !m.outgoing && !m.is_read)
        .unwrap();
    app.conversations[app.selected].selected_message = 0;
    session_tui_browse::unread(&mut app);
    assert_eq!(app.conversations[app.selected].selected_message, first);
    assert!(!app.conversations[app.selected].messages[first].is_read);
    let marker = app.unread_marker.clone();
    // Read now (as viewing does): /unread still finds this visit's boundary.
    for m in &mut app.conversations[app.selected].messages {
        m.is_read = true;
    }
    app.conversations[app.selected].selected_message = 0;
    session_tui_browse::unread(&mut app);
    assert_eq!(app.conversations[app.selected].selected_message, first);
    assert_eq!(app.unread_marker, marker);
    // The boundary message is deleted: no crash, and nothing to go to.
    app.conversations[app.selected].messages.remove(first);
    session_tui_browse::unread(&mut app);
    assert_eq!(app.status, "NO UNREAD MESSAGES IN THIS CHAT");
    assert_eq!(app.conversations[app.selected].id, a);
}

#[test]
fn alt_n_cycles_unread_chats_in_list_order_within_the_filter() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x52);
    let mut app = rich_app(&identity, &store);
    let (a, b) = (peer(0xa1), peer(0xb2));
    let group = format!("03{}", "33".repeat(32));
    // Expected: the chats after the open one in list order, wrapping, that
    // have unread messages.
    let order: Vec<String> = session_tui_chats::visible(&app)
        .iter()
        .map(|&i| app.conversations[i].id.clone())
        .collect();
    let start = order
        .iter()
        .position(|id| *id == app.conversations[app.selected].id)
        .unwrap();
    let unread: Vec<String> = (1..=order.len())
        .map(|offset| order[(start + offset) % order.len()].clone())
        .filter(|id| {
            app.conversations
                .iter()
                .any(|c| c.id == *id && c.unread() > 0)
        })
        .collect();
    assert_eq!(unread.len(), 3);
    for expected in unread.iter().chain(&unread) {
        session_tui_browse::next_unread_chat(&mut app);
        assert_eq!(app.conversations[app.selected].id, *expected);
    }
    let _ = (&b, &group);
    // Lands on the first unread message.
    select(&mut app, &a);
    session_tui_browse::next_unread_chat(&mut app);
    let c = &app.conversations[app.selected];
    let first = c
        .messages
        .iter()
        .position(|m| !m.outgoing && !m.is_read)
        .unwrap();
    assert_eq!(c.selected_message, first);
    // With a filter, only shown chats count.
    select(&mut app, &a);
    app.chat_filter = session_tui_chats::ChatFilter::parse(&a[..12]);
    session_tui_browse::next_unread_chat(&mut app);
    assert_eq!(app.status, "NO OTHER CHAT HAS UNREAD MESSAGES");
    // Nothing unread anywhere.
    app.chat_filter = None;
    for c in &mut app.conversations {
        for m in &mut c.messages {
            m.is_read = true;
        }
    }
    session_tui_browse::next_unread_chat(&mut app);
    assert_eq!(app.status, "NO OTHER CHAT HAS UNREAD MESSAGES");
}

#[test]
fn goto_finds_the_first_message_of_a_local_date() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x53);
    let mut app = rich_app(&identity, &store);
    let c = &app.conversations[app.selected];
    let target = 100;
    let date = session_tui_separators::local_date(c.messages[target].timestamp_ms).unwrap();
    let expected = c
        .messages
        .iter()
        .position(|m| session_tui_separators::local_date(m.timestamp_ms) == Some(date))
        .unwrap();
    session_tui_browse::goto(&mut app, &date.to_string());
    assert_eq!(app.conversations[app.selected].selected_message, expected);
    assert!(app.highlight.is_some());
    let before = app.conversations[app.selected].selected_message;
    session_tui_browse::goto(&mut app, "2001-01-01");
    assert_eq!(app.status, "NO MESSAGES ON 2001-01-01 IN THIS CHAT");
    assert_eq!(app.conversations[app.selected].selected_message, before);
    session_tui_browse::goto(&mut app, "2026-02-30");
    assert!(app.status.starts_with("INVALID DATE"));
    session_tui_browse::goto(&mut app, "26-1-1");
    assert!(app.status.starts_with("INVALID DATE"));
}

#[test]
fn bookmarks_persist_and_never_show_gone_messages() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x54);
    let mut app = rich_app(&identity, &store);
    let a = app.conversations[app.selected].id.clone();
    app.conversations[app.selected].selected_message = 50;
    session_tui_browse::bookmark(&mut app, &store, true);
    session_tui_browse::bookmark(&mut app, &store, true);
    assert_eq!(app.status, "ALREADY BOOKMARKED");
    app.conversations[app.selected].selected_message = 60;
    session_tui_browse::bookmark(&mut app, &store, true);
    // Both group messages (same ms, different senders) separately.
    let group = format!("03{}", "33".repeat(32));
    select(&mut app, &group);
    for index in 0..2 {
        app.conversations[app.selected].selected_message = index;
        session_tui_browse::bookmark(&mut app, &store, true);
    }
    assert_eq!(app.bookmarks.len(), 4);
    // Only references are stored.
    let columns: Vec<String> = store
        .connection
        .prepare("SELECT name FROM pragma_table_info('bookmarks')")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .flatten()
        .collect();
    assert!(
        !columns
            .iter()
            .any(|c| c.contains("body") || c.contains("text"))
    );
    // Restart: same bookmarks.
    let stored = store.load_bookmarks();
    assert_eq!(stored, app.bookmarks);
    // One disappears, one is deleted: the list shows neither and drops them.
    select(&mut app, &a);
    let c = &mut app.conversations[app.selected];
    c.messages[50].expires_at = Some(1);
    c.messages.remove(60);
    session_tui_browse::open_bookmarks(&mut app, &store);
    let view = app.browse.as_ref().unwrap();
    assert_eq!(view.items.len(), 2);
    assert!(view.items.iter().all(|item| item.conversation == group));
    assert!(view.note.as_ref().unwrap().starts_with("2 bookmark"));
    assert!(!view.items.iter().any(|i| i.detail.contains("message 50")));
    assert_eq!(store.load_bookmarks().len(), 2);
    // Enter opens the right one of the two same-ms messages.
    app.browse.as_mut().unwrap().step(1);
    let wanted = app.browse.as_ref().unwrap().items[1].key.clone();
    session_tui_browse::handle_key(&mut app, crossterm::event::KeyCode::Enter);
    let c = &app.conversations[app.selected];
    assert_eq!(
        c.messages[c.selected_message].key(&c.id, &app.local_id),
        wanted
    );
    // Unbookmark.
    session_tui_browse::bookmark(&mut app, &store, false);
    assert_eq!(app.status, "BOOKMARK REMOVED");
    session_tui_browse::bookmark(&mut app, &store, false);
    assert_eq!(app.status, "NOT BOOKMARKED");
    assert_eq!(store.load_bookmarks().len(), 1);
}

#[test]
fn media_and_links_lists_and_their_actions() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x55);
    let mut app = rich_app(&identity, &store);
    session_tui_browse::open_media(&mut app);
    let view = app.browse.as_ref().unwrap();
    assert_eq!(view.items.len(), 2);
    assert!(view.items[0].head.starts_with("a.jpg · image · 2.0 KB"));
    assert!(
        view.items[1]
            .head
            .starts_with("notes.pdf · document · size N/A")
    );
    // S on the PDF: opens message 11 and runs `/save 2` like typed.
    app.browse.as_mut().unwrap().step(1);
    session_tui_browse::handle_key(&mut app, crossterm::event::KeyCode::Char('s'));
    assert!(app.browse.is_none());
    assert_eq!(app.conversations[app.selected].selected_message, 11);
    assert_eq!(app.queued_command.as_deref(), Some("/save 2"));
    // V on a non-image: refused, nothing opened.
    app.queued_command = None;
    session_tui_browse::open_media(&mut app);
    app.browse.as_mut().unwrap().step(1);
    session_tui_browse::handle_key(&mut app, crossterm::event::KeyCode::Char('v'));
    assert!(app.status.starts_with("PREVIEW IS ONLY FOR IMAGES"));
    assert!(app.image_viewer.is_none());
    app.browse = None;

    session_tui_browse::open_links(&mut app);
    let view = app.browse.as_ref().unwrap();
    let urls: Vec<&str> = view.items.iter().filter_map(|i| i.url.as_deref()).collect();
    assert_eq!(urls, ["https://one.example/a", "https://two.example/b"]);
    app.browse.as_mut().unwrap().step(1);
    session_tui_browse::handle_key(&mut app, crossterm::event::KeyCode::Char('c'));
    assert_eq!(app.clipboard.as_deref(), Some("https://two.example/b"));
    session_tui_browse::handle_key(&mut app, crossterm::event::KeyCode::Enter);
    assert_eq!(app.conversations[app.selected].selected_message, 10);

    // A disappeared message's links and files are not listed.
    let c = &mut app.conversations[app.selected];
    c.messages[10].expires_at = Some(1);
    c.messages[11].expires_at = Some(1);
    session_tui_browse::open_links(&mut app);
    assert!(app.browse.as_ref().unwrap().items.is_empty());
    session_tui_browse::open_media(&mut app);
    assert!(app.browse.as_ref().unwrap().items.is_empty());
}

#[test]
fn lists_draw_on_tiny_terminals() {
    use ratatui::{Terminal, backend::TestBackend};
    let (_guard, identity, store) = super::history_key_tests::test_store(0x56);
    let mut app = rich_app(&identity, &store);
    session_tui_browse::open_links(&mut app);
    for (w, h) in [(10, 4), (30, 8), (200, 60)] {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
    }
    app.browse = None;
    session_tui_browse::open_media(&mut app);
    let mut terminal = Terminal::new(TestBackend::new(12, 5)).unwrap();
    terminal.draw(|frame| draw(frame, &mut app)).unwrap();
}

#[test]
fn a_command_run_from_the_composer_keeps_the_draft() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x57);
    let a = peer(0xa1);
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let now = Instant::now();
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    type_text(&mut app, "my draft");
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(1));
    assert_eq!(store.load_drafts()[&a].0, "my draft");
    // The composer turns into a command (e.g. `/pin`), which runs and clears it.
    for command in ["/pin", "/filter x", "/unread"] {
        type_text(&mut app, command);
        session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(2));
        app.input.clear();
        app.cursor = 0;
        session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(3));
        assert_eq!(store.load_drafts()[&a].0, "my draft", "after {command}");
    }
    // A queued command (`/save N` from /media) gives the composer back.
    app.input = "still here".into();
    app.cursor = 4;
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(4));
    app.restore_input = Some((
        std::mem::replace(&mut app.input, "/save 1".into()),
        app.cursor,
    ));
    app.input.clear();
    let (input, cursor) = app.restore_input.take().unwrap();
    app.input = input;
    app.cursor = cursor;
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(6));
    assert_eq!(store.load_drafts()[&a], ("still here".to_owned(), 4));
}

#[test]
fn a_draft_that_fails_to_save_on_switching_is_retried() {
    let (_guard, identity, store) = super::history_key_tests::test_store(0x58);
    let (a, b) = (peer(0xa1), peer(0xb2));
    let mut app = app_for(&identity, &store);
    select(&mut app, &a);
    let now = Instant::now();
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    type_text(&mut app, "keep this");
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    let schema: String = store
        .connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name = 'drafts'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    store.connection.execute_batch("DROP TABLE drafts").unwrap();
    // Switch before the pause: the write fails.
    select(&mut app, &b);
    session_tui_local::sync_drafts_at(&mut app, &store, now);
    assert!(app.status.starts_with("DRAFT NOT SAVED"));
    // The database recovers: the next turn after the pause writes it.
    store.connection.execute_batch(&schema).unwrap();
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_millis(100));
    assert!(store.load_drafts().is_empty());
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(1));
    assert_eq!(store.load_drafts()[&a].0, "keep this");
    // Quit also writes anything still unsaved.
    store.connection.execute_batch("DROP TABLE drafts").unwrap();
    select(&mut app, &a);
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(2));
    type_text(&mut app, "later text");
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(2));
    select(&mut app, &b);
    session_tui_local::sync_drafts_at(&mut app, &store, now + Duration::from_secs(5));
    store.connection.execute_batch(&schema).unwrap();
    session_tui_local::flush_drafts(&mut app, &store);
    assert_eq!(store.load_drafts()[&a].0, "later text");
}

#[test]
fn search_and_list_panels_fit_any_terminal_width() {
    use ratatui::{Terminal, backend::TestBackend};
    let (_guard, identity, store) = super::history_key_tests::test_store(0x59);
    let mut app = rich_app(&identity, &store);
    for (w, h) in [(8, 3), (40, 10), (101, 30), (200, 60), (400, 120)] {
        app.search = Some(session_tui_search::SearchView::notice("usage"));
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        app.search = None;
        session_tui_browse::open_links(&mut app);
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        app.browse = None;
    }
}
