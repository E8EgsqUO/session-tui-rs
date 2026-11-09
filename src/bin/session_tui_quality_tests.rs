//! Failure-boundary tests. All databases and files belong to a private temp dir.
use super::*;

struct Fixture(
    std::path::PathBuf,
    #[allow(dead_code)] std::sync::MutexGuard<'static, ()>,
);
impl Fixture {
    fn new() -> Self {
        let guard = super::history_key_tests::STORE_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "session-quality-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        Self(dir, guard)
    }
    fn store(&self) -> LocalStore {
        let path = self.0.join("history.sqlite3");
        let new = !path.exists();
        let connection = Connection::open(path).unwrap();
        connection
            .execute_batch(&format!(
                "PRAGMA key = \"x'{}'\"; PRAGMA cipher_compatibility = 4;",
                hex::encode([7; 32])
            ))
            .unwrap();
        if new {
            // A previous schema: migration must keep encrypted message bodies intact.
            create_history_schema(&connection).unwrap();
            connection.execute_batch("ALTER TABLE contacts ADD COLUMN display_name TEXT NOT NULL DEFAULT '';
                CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE profiles(session_id TEXT PRIMARY KEY, display_name TEXT NOT NULL);
                CREATE TABLE outbox(id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, peer TEXT NOT NULL, timestamp_ms INTEGER NOT NULL, payload BLOB NOT NULL DEFAULT x'', attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '');
                CREATE TABLE node_cursors(key TEXT PRIMARY KEY, hash TEXT NOT NULL);
                CREATE TABLE pending_receipts(peer TEXT NOT NULL, timestamp_ms INTEGER NOT NULL, status INTEGER NOT NULL, received_ms INTEGER NOT NULL, PRIMARY KEY(peer,timestamp_ms));").unwrap();
        }
        LocalStore {
            connection,
            key: [7; 32],
            batch: std::cell::RefCell::new(None),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn ids() -> (String, String) {
    (
        format!("05{}", "11".repeat(32)),
        format!("05{}", "22".repeat(32)),
    )
}
fn retrieved(message: IncomingMessage) -> RetrieveResult {
    RetrieveResult {
        messages: vec![message],
        queued: 1,
        undecryptable: 0,
        bad_envelope: 0,
        bad_content: 0,
        last_hash: Some("cursor".into()),
        groups: vec![],
        group_cursors: HashMap::new(),
        node_cursors: vec![("node".into(), "cursor".into())],
        invite_responses: vec![],
        account: None,
    }
}
#[test]
fn encrypted_legacy_history_migrates_idempotently_and_reopens() {
    let f = Fixture::new();
    let (me, group) = ids();
    {
        let s = f.store();
        let mut old = Message::new("old encrypted body".into(), 123, false);
        old.sender = Some("alice".into());
        let body = s.encrypted_payload(&old).unwrap();
        s.connection
            .execute(
                "INSERT INTO messages(peer_id,timestamp_ms,outgoing,body) VALUES (?1,123,0,?2)",
                params![group, body],
            )
            .unwrap();
    }
    {
        let s = f.store();
        s.add_sender_to_message_key().unwrap();
        s.add_sender_to_message_key().unwrap();
        let mut other = Message::new("same timestamp, other author".into(), 123, false);
        other.sender = Some("bob".into());
        s.save_message(&group, &other).unwrap();
    }
    let s = f.store();
    let mut app = App::new(me);
    s.load(&mut app).unwrap();
    let messages = &app
        .conversations
        .iter()
        .find(|c| c.id == group)
        .unwrap()
        .messages;
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .any(|m| m.body == "old encrypted body" && m.sender.as_deref() == Some("alice"))
    );
    assert_ne!(
        &std::fs::read(f.0.join("history.sqlite3")).unwrap()[..16],
        b"SQLite format 3\0"
    );
    let wrong = Connection::open(f.0.join("history.sqlite3")).unwrap();
    wrong.execute_batch("PRAGMA key = 'wrong key';").unwrap();
    assert!(
        wrong
            .query_row("SELECT count(*) FROM messages", [], |r| r.get::<_, i64>(0))
            .is_err()
    );
}
#[test]
fn restart_recovers_each_outbox_stage_without_requeueing_the_text() {
    let f = Fixture::new();
    let (me, peer) = ids();
    {
        let s = f.store();
        s.add_sender_to_message_key().unwrap();
        let mut m = Message::new("queued".into(), 123, true);
        m.send_state = SendState::Sending;
        queue_outgoing(&s, &peer, &m).unwrap();
    }
    {
        let s = f.store();
        let mut app = App::new(me.clone());
        s.load(&mut app).unwrap();
        let entry = s.outbox_due(now_ms()).pop().unwrap();
        assert_eq!(entry.kind, OutboxKind::Text);
        finish_outbox(&mut app, &s, &entry, Ok(None));
    }
    let s = f.store();
    let mut app = App::new(me);
    s.load(&mut app).unwrap();
    let due = s.outbox_due(now_ms());
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].kind, OutboxKind::SyncCopy);
    assert_eq!(
        app.conversations
            .iter()
            .find(|c| c.id == peer)
            .unwrap()
            .messages[0]
            .send_state,
        SendState::Sent
    );
}
#[test]
fn unmatched_receipt_survives_restart_and_is_applied_once() {
    let f = Fixture::new();
    let (me, peer) = ids();
    {
        let s = f.store();
        s.add_sender_to_message_key().unwrap();
        let mut app = App::new(me.clone());
        let mut r = IncomingMessage::control("receipt".into(), peer.clone(), peer.clone(), 200);
        r.receipt = Some((1, vec![100]));
        finish_sync(
            &mut app,
            &s,
            &me,
            Ok(retrieved(r)),
            &mut Default::default(),
            None,
        );
    }
    let s = f.store();
    let mut app = App::new(me.clone());
    s.load(&mut app).unwrap();
    let make = || {
        let mut m = IncomingMessage::control("copy".into(), me.clone(), peer.clone(), 100);
        m.outgoing = true;
        m.body = Some("phone message".into());
        m
    };
    for _ in 0..2 {
        finish_sync(
            &mut app,
            &s,
            &me,
            Ok(retrieved(make())),
            &mut Default::default(),
            None,
        );
    }
    let messages = &app
        .conversations
        .iter()
        .find(|c| c.id == peer)
        .unwrap()
        .messages;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].receipt_status, 2);
    assert_eq!(
        s.connection
            .query_row("SELECT count(*) FROM pending_receipts", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}
#[test]
fn deferred_commit_failure_rolls_back_messages_seen_and_node_cursors() {
    let f = Fixture::new();
    let s = f.store();
    s.add_sender_to_message_key().unwrap();
    let (me, peer) = ids();
    s.connection.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_commit AFTER INSERT ON messages BEGIN INSERT INTO child VALUES(1); END;").unwrap();
    let mut app = App::new(me.clone());
    let cursors = Mutex::new(HashMap::new());
    let make = || {
        let mut m = IncomingMessage::control("message".into(), peer.clone(), peer.clone(), 100);
        m.body = Some("must retry".into());
        m
    };
    finish_sync(
        &mut app,
        &s,
        &me,
        Ok(retrieved(make())),
        &mut Default::default(),
        Some(&cursors),
    );
    assert!(app.status.contains("WILL RETRY"));
    assert!(app.conversations.iter().all(|c| c.messages.is_empty()));
    assert!(cursors.lock().unwrap().is_empty());
    assert_eq!(
        s.connection
            .query_row("SELECT count(*) FROM seen_hashes", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    s.connection
        .execute_batch("DROP TRIGGER fail_commit;")
        .unwrap();
    finish_sync(
        &mut app,
        &s,
        &me,
        Ok(retrieved(make())),
        &mut Default::default(),
        Some(&cursors),
    );
    assert_eq!(
        cursors.lock().unwrap().get("node").map(String::as_str),
        Some("cursor")
    );
}
#[test]
fn attachment_cleanup_is_deferred_until_transaction_commits() {
    let f = Fixture::new();
    let s = f.store();
    let path = f.0.join("encrypted.blob");
    std::fs::write(&path, b"encrypted fixture").unwrap();
    s.begin_batch().unwrap();
    s.delete_file_after_commit(path.clone());
    let _ = s.exec("INSERT INTO missing_table VALUES (1)", []);
    assert!(s.end_batch().is_err());
    assert!(path.exists());
    s.begin_batch().unwrap();
    s.delete_file_after_commit(path.clone());
    s.end_batch().unwrap();
    assert!(!path.exists());
}
#[test]
fn forged_unsend_never_removes_another_authors_message() {
    let f = Fixture::new();
    let s = f.store();
    s.add_sender_to_message_key().unwrap();
    let (me, peer) = ids();
    let mut app = App::new(me.clone());
    let i = app.ensure_contact(&peer);
    let m = Message::new("keep".into(), 123, false);
    s.save_message(&peer, &m).unwrap();
    app.conversations[i].messages.push(m);
    assert!(!apply_unsend(
        &mut app, &s, &me, "attacker", &peer, 123, &peer
    ));
    assert_eq!(app.conversations[i].messages.len(), 1);
}
