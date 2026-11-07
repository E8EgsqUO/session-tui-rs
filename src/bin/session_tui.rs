mod session_tui_media;

use std::time::Instant;
use std::{
    collections::{HashMap, HashSet},
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use prost::Message as ProstMessage;
use serde_json::Value;

use libsession::{
    config::{
        config_base::ConfigBase,
        groups::info::GroupInfo as SharedGroupInfo,
        user_groups::{GroupInfo as UserGroupInfo, UserGroups},
    },
    crypto::{curve25519, ed25519, random, session_encrypt},
    network::{
        HttpTransport, Network, NetworkConfig,
        rpc::{self, RetrieveParams, StoreParams},
    },
    proto::{
        session_protos::{
            AttachmentPointer, Content, DataMessage, Envelope, LokiProfile, envelope,
        },
        web_socket_protos::{WebSocketMessage, web_socket_message},
    },
    protocol::protocol::{DecodeEnvelopeKey, decode_envelope, encode_for_1o1, encode_for_group},
};

use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste,
        EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseButton, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use ratatui_image::{
    FilterType, Resize, StatefulImage,
    picker::{Picker, ProtocolType},
    protocol::StatefulProtocol,
};
use rusqlite::{Connection, OptionalExtension, params};
use session_tui_media::{AttachmentMeta, ImagePreview};

const BG: Color = Color::Rgb(10, 17, 23);
const PANEL: Color = Color::Rgb(16, 27, 34);
const MUTED: Color = Color::Rgb(114, 139, 146);
const TEXT: Color = Color::Rgb(220, 233, 231);
const TEAL: Color = Color::Rgb(71, 216, 185);
const BLUE: Color = Color::Rgb(91, 176, 233);

static DEBUG_LOG: OnceLock<Option<Mutex<File>>> = OnceLock::new();

fn init_debug_log(enabled: bool) -> io::Result<()> {
    let log = if enabled {
        Some(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open("session-tui-debug.log")?,
        ))
    } else {
        None
    };
    let _ = DEBUG_LOG.set(log);
    if enabled {
        debug_log(
            "startup",
            "debug logging enabled; secrets and message bodies are redacted",
        );
    }
    Ok(())
}

fn debug_log(event: &str, detail: &str) {
    if let Some(Some(file)) = DEBUG_LOG.get() {
        if let Ok(mut file) = file.lock() {
            let _ = writeln!(file, "{} {} {}", now_ms(), event, detail);
            let _ = file.flush();
        }
    }
}

#[derive(Clone)]
struct Message {
    /// Text body; for attachment messages this is the caption, as in Session.
    body: String,
    timestamp_ms: u64,
    outgoing: bool,
    receipt_status: u8,
    is_read: bool,
    /// Session ID of the author for incoming group messages.
    sender: Option<String>,
    /// All attachments of the message (Session sends albums as one
    /// DataMessage with several AttachmentPointers).
    attachments: Vec<AttachmentMeta>,
    /// One preview slot per attachment.
    image_previews: Vec<Option<ImagePreview>>,
}

impl Message {
    fn new(body: String, timestamp_ms: u64, outgoing: bool) -> Self {
        Self {
            body,
            timestamp_ms,
            outgoing,
            receipt_status: 0,
            is_read: outgoing,
            sender: None,
            attachments: Vec::new(),
            image_previews: Vec::new(),
        }
    }

    fn preview_text(&self) -> String {
        message_preview_text(&self.body, &self.attachments)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct StoredMessage {
    body: String,
    /// Legacy single-attachment fields (read for old rows, never written).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    attachment: Option<AttachmentMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    image_preview: Option<ImagePreview>,
    #[serde(default)]
    attachments: Vec<AttachmentMeta>,
    #[serde(default)]
    image_previews: Vec<Option<ImagePreview>>,
    #[serde(default)]
    sender: Option<String>,
}

const STORED_MESSAGE_PREFIX: &str = "\0session-tui-message-v1:";

/// Session clients accept at most 32 attachments in one message.
const MAX_ATTACHMENTS: usize = 32;

/// Upper bound on `more` pages fetched per namespace in one sync.
const MAX_RETRIEVE_PAGES: usize = 20;

struct Conversation {
    name: String,
    id: String,
    preview: String,
    messages: Vec<Message>,
    selected_message: usize,
}

impl Conversation {
    fn unread(&self) -> usize {
        self.messages
            .iter()
            .filter(|m| !m.outgoing && !m.is_read)
            .count()
    }

    fn last_activity(&self) -> u64 {
        self.messages.last().map_or(0, |m| m.timestamp_ms)
    }

    fn refresh_preview(&mut self) {
        self.preview = self
            .messages
            .last()
            .map(Message::preview_text)
            .unwrap_or_else(|| "Start a conversation".into());
    }

    fn clamp_selection(&mut self) {
        self.selected_message = self
            .selected_message
            .min(self.messages.len().saturating_sub(1));
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMode {
    Message,
    ContactId,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FocusArea {
    Contacts,
    Messages,
    Composer,
}

struct App {
    conversations: Vec<Conversation>,
    selected: usize,
    input: String,
    input_mode: InputMode,
    seen_hashes: HashSet<String>,
    status: String,
    show_help: bool,
    recovery_seed: Option<String>,
    focus: FocusArea,
    profile_name: String,
    image_viewer: Option<ImageViewer>,
    contact_list_area: Option<Rect>,
    contact_list_offset: usize,
    message_viewport: Option<Rect>,
    /// (first row, last row, message index, attachment index)
    message_hitboxes: Vec<(u16, u16, usize, Option<usize>)>,
    /// Display names of group members and other senders, by Session ID.
    display_names: HashMap<String, String>,
}

impl App {
    fn new(local_id: String) -> Self {
        Self {
            conversations: Vec::new(),
            selected: 0,
            input: String::new(),
            input_mode: InputMode::Message,
            seen_hashes: HashSet::new(),
            status: format!("{}… · READY", &local_id[..10]),
            show_help: false,
            recovery_seed: None,
            focus: FocusArea::Composer,
            profile_name: String::new(),
            image_viewer: None,
            contact_list_area: None,
            contact_list_offset: 0,
            message_viewport: None,
            message_hitboxes: Vec::new(),
            display_names: HashMap::new(),
        }
    }

    /// Order chats by latest activity (newest first) like Session, keeping
    /// the currently selected chat selected.
    fn sort_conversations(&mut self) {
        let selected_id = self.conversations.get(self.selected).map(|c| c.id.clone());
        self.conversations
            .sort_by_key(|c| std::cmp::Reverse(c.last_activity()));
        if let Some(id) = selected_id
            && let Some(index) = self.conversations.iter().position(|c| c.id == id)
        {
            self.selected = index;
        }
    }

    fn sender_label(&self, sender: &str) -> String {
        self.display_names
            .get(sender)
            .cloned()
            .unwrap_or_else(|| short_id(sender))
    }

    fn selected_message(&self) -> Option<&Message> {
        let conversation = self.conversations.get(self.selected)?;
        conversation.messages.get(conversation.selected_message)
    }

    fn remove_selected_message(&mut self) -> Option<Message> {
        let conversation = self.conversations.get_mut(self.selected)?;
        if conversation.selected_message >= conversation.messages.len() {
            return None;
        }
        let removed = conversation.messages.remove(conversation.selected_message);
        conversation.clamp_selection();
        conversation.refresh_preview();
        Some(removed)
    }

    fn ensure_contact(&mut self, id: &str) -> usize {
        if let Some(index) = self.conversations.iter().position(|c| c.id == id) {
            return index;
        }
        self.conversations.push(Conversation {
            name: short_id(id),
            id: id.to_owned(),
            preview: "Start a conversation".into(),
            messages: Vec::new(),
            selected_message: 0,
        });
        self.conversations.len() - 1
    }

    fn submit_contact_id(&mut self) {
        let id = self.input.trim().to_ascii_lowercase();
        if !libsession::util::types::session_id_is_valid(&id) {
            self.status = "INVALID SESSION ID · EXPECTED 66 HEX CHARACTERS STARTING WITH 05".into();
            return;
        }
        self.selected = self.ensure_contact(&id);
        self.status = "CONTACT READY · INBOX AUTO-SYNC EVERY 30 SECONDS".into();
        self.input.clear();
        self.input_mode = InputMode::Message;
    }
}

/// Open an image of the selected message. `index` is the 0-based attachment
/// index; `None` opens the first image of the message.
fn open_selected_image(app: &mut App, index: Option<usize>) -> Result<(), String> {
    let (peer, timestamp, attachment_index, metadata) = {
        let conversation = app
            .conversations
            .get(app.selected)
            .ok_or("no conversation selected")?;
        let message = conversation
            .messages
            .get(conversation.selected_message)
            .ok_or("select an image message with ↑/↓ first")?;
        if message.attachments.is_empty() {
            return Err("selected message has no attachment".into());
        }
        let attachment_index = match index {
            Some(index) => index,
            None => message
                .attachments
                .iter()
                .position(|a| a.content_type.starts_with("image/"))
                .ok_or("selected message has no image")?,
        };
        let metadata = message
            .attachments
            .get(attachment_index)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "message has {} attachment(s); use /view 1-{}",
                    message.attachments.len(),
                    message.attachments.len()
                )
            })?;
        if !metadata.content_type.starts_with("image/") {
            return Err("selected attachment is not an image".into());
        }
        (
            conversation.id.clone(),
            message.timestamp_ms,
            attachment_index,
            metadata,
        )
    };
    let root = session_data_dir()?;
    let cache_path =
        session_tui_media::attachment_blob_path(&root, &peer, timestamp, attachment_index);
    let encrypted = std::fs::read(&cache_path)
        .map_err(|_| "image is still downloading; try again shortly".to_string())?;
    let plaintext = session_tui_media::decrypt_attachment(
        &encrypted,
        &metadata.key,
        &metadata.digest,
        metadata.deterministic,
    )?;
    let image = image::load_from_memory(&plaintext).map_err(|e| format!("decode image: {e}"))?;

    let mut picker = Picker::from_fontsize((8, 16));
    let protocol = std::env::var("SESSION_TUI_IMAGE_PROTOCOL")
        .ok()
        .map(|value| value.trim().to_ascii_lowercase());
    let selected_protocol = match protocol.as_deref() {
        Some("sixel") => Some(ProtocolType::Sixel),
        Some("kitty") => Some(ProtocolType::Kitty),
        Some("iterm2") | Some("iterm") => Some(ProtocolType::Iterm2),
        _ if std::env::var_os("WT_SESSION").is_some() => Some(ProtocolType::Sixel),
        _ => None,
    };
    if let Some(protocol) = selected_protocol {
        picker.set_protocol_type(protocol);
    }
    let protocol = picker.new_resize_protocol(image);
    let count = app
        .selected_message()
        .map_or(1, |message| message.attachments.len());
    app.image_viewer = Some(ImageViewer {
        title: if count > 1 {
            format!("{} ({}/{count})", metadata.file_name, attachment_index + 1)
        } else {
            metadata.file_name
        },
        protocol,
    });
    Ok(())
}

fn handle_mouse(app: &mut App, mouse: crossterm::event::MouseEvent) {
    if app.image_viewer.is_some() {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            app.image_viewer = None;
        }
        return;
    }
    let in_rect = |rect: Rect| {
        mouse.column >= rect.x
            && mouse.column < rect.x.saturating_add(rect.width)
            && mouse.row >= rect.y
            && mouse.row < rect.y.saturating_add(rect.height)
    };
    if app.contact_list_area.is_some_and(in_rect) {
        app.focus = FocusArea::Contacts;
        let area = app.contact_list_area.expect("checked above");
        let row = (mouse.row.saturating_sub(area.y) / 3) as usize + app.contact_list_offset;
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if row < app.conversations.len() {
                    app.selected = row;
                }
            }
            MouseEventKind::ScrollUp => app.selected = app.selected.saturating_sub(1),
            MouseEventKind::ScrollDown => {
                if !app.conversations.is_empty() {
                    app.selected = (app.selected + 1).min(app.conversations.len() - 1);
                }
            }
            _ => {}
        }
        return;
    }
    if app.message_viewport.is_some_and(in_rect) {
        app.focus = FocusArea::Messages;
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if let Some(conversation) = app.conversations.get_mut(app.selected) {
                    conversation.selected_message = conversation.selected_message.saturating_sub(1);
                }
            }
            MouseEventKind::ScrollDown => {
                if let Some(conversation) = app.conversations.get_mut(app.selected) {
                    if !conversation.messages.is_empty() {
                        conversation.selected_message = (conversation.selected_message + 1)
                            .min(conversation.messages.len() - 1);
                    }
                }
            }
            MouseEventKind::Down(MouseButton::Left) => {
                // Attachment hitboxes are pushed after their message's
                // hitbox, so search from the end to prefer the most specific.
                if let Some((_, _, index, attachment)) = app
                    .message_hitboxes
                    .iter()
                    .rev()
                    .find(|(start, end, _, _)| mouse.row >= *start && mouse.row <= *end)
                {
                    let (index, attachment) = (*index, *attachment);
                    if let Some(conversation) = app.conversations.get_mut(app.selected) {
                        conversation.selected_message = index;
                    }
                    let is_image = attachment.is_some_and(|attachment| {
                        app.conversations
                            .get(app.selected)
                            .and_then(|conversation| conversation.messages.get(index))
                            .and_then(|message| message.attachments.get(attachment))
                            .is_some_and(|meta| meta.content_type.starts_with("image/"))
                    });
                    if is_image {
                        app.status = match open_selected_image(app, attachment) {
                            Ok(()) => "IMAGE PREVIEW · PRESS ESC TO CLOSE".into(),
                            Err(error) => format!("IMAGE PREVIEW FAILED · {error}"),
                        };
                    }
                }
            }
            _ => {}
        }
    }
}

fn short_id(id: &str) -> String {
    if id.len() < 12 {
        return id.to_owned();
    }
    format!("{}…{}", &id[..8], &id[id.len() - 4..])
}

fn attachment_label(attachment: &AttachmentMeta) -> String {
    let kind = if attachment.content_type.starts_with("image/") {
        "Photo"
    } else if attachment.content_type.starts_with("audio/") {
        "Audio"
    } else if attachment.content_type.starts_with("video/") {
        "Video"
    } else {
        "File"
    };
    format!("[{kind}] {}", attachment.file_name)
}

/// Single-line summary used for the chat list.
fn message_preview_text(body: &str, attachments: &[AttachmentMeta]) -> String {
    if !body.trim().is_empty() {
        return body.lines().next().unwrap_or_default().to_owned();
    }
    match attachments {
        [] => String::new(),
        [only] => attachment_label(only),
        _ if attachments
            .iter()
            .all(|a| a.content_type.starts_with("image/")) =>
        {
            format!("[{} Photos]", attachments.len())
        }
        [first, rest @ ..] => format!("{} +{}", attachment_label(first), rest.len()),
    }
}

fn mime_type_for_name(name: &str) -> &'static str {
    match std::path::Path::new(name)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "heic" | "heif" => "image/heic",
        "pdf" => "application/pdf",
        "txt" | "md" | "log" => "text/plain",
        "zip" => "application/zip",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "aac" => "audio/aac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "mp4" => "video/mp4",
        "mov" => "video/quicktime",
        _ => "application/octet-stream",
    }
}

fn default_attachment_extension(content_type: &str) -> Option<&'static str> {
    match content_type.to_ascii_lowercase().as_str() {
        "image/jpeg" => Some("jpg"),
        "image/png" => Some("png"),
        "image/gif" => Some("gif"),
        "image/webp" => Some("webp"),
        "image/heic" | "image/heif" => Some("heic"),
        "audio/mpeg" => Some("mp3"),
        "audio/mp4" | "audio/x-m4a" => Some("m4a"),
        "audio/aac" => Some("aac"),
        "audio/ogg" => Some("ogg"),
        "audio/opus" => Some("opus"),
        "audio/flac" => Some("flac"),
        "audio/wav" | "audio/x-wav" => Some("wav"),
        "image/bmp" => Some("bmp"),
        "application/pdf" => Some("pdf"),
        "text/plain" => Some("txt"),
        "application/zip" => Some("zip"),
        "video/mp4" => Some("mp4"),
        "video/quicktime" => Some("mov"),
        _ => None,
    }
}

fn attachment_meta_from_pointer(pointer: &AttachmentPointer) -> AttachmentMeta {
    let url = pointer.url.clone().unwrap_or_default();
    let deterministic = libsession::network::backends::file_server::parse_download_url(&url)
        .is_some_and(|details| details.wants_stream_decryption);
    let file_name = pointer
        .file_name
        .clone()
        .unwrap_or_else(|| "attachment".into());
    AttachmentMeta {
        content_type: pointer
            .content_type
            .clone()
            .unwrap_or_else(|| mime_type_for_name(&file_name).into()),
        file_name,
        url,
        key: pointer.key.clone().unwrap_or_default(),
        digest: pointer.digest.clone().unwrap_or_default(),
        size: pointer.size.unwrap_or_default(),
        deterministic,
        width: pointer.width,
        height: pointer.height,
    }
}

fn attachment_pointer_from_meta(meta: &AttachmentMeta) -> AttachmentPointer {
    AttachmentPointer {
        id: 0,
        content_type: Some(meta.content_type.clone()),
        key: Some(meta.key.clone()),
        size: Some(meta.size),
        thumbnail: None,
        digest: (!meta.digest.is_empty()).then(|| meta.digest.clone()),
        file_name: Some(meta.file_name.clone()),
        flags: None,
        width: meta.width,
        height: meta.height,
        caption: None,
        url: Some(meta.url.clone()),
    }
}

fn profile_for(profile_name: &str, timestamp_ms: u64) -> Option<LokiProfile> {
    let name = profile_name.trim();
    (!name.is_empty()).then(|| LokiProfile {
        display_name: Some(name.to_owned()),
        last_update_seconds: Some(timestamp_ms / 1000),
        ..Default::default()
    })
}

fn split_host_port(host: &str) -> (&str, Option<u16>) {
    if let Some((name, port)) = host.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (name, Some(port));
    }
    (host, None)
}

#[derive(Clone)]
struct Identity {
    session_id: String,
    ed_public: [u8; 32],
    ed_secret: [u8; 64],
    recovery_phrase: Option<String>,
}

struct IncomingMessage {
    hash: String,
    sender_id: String,
    contact_id: String,
    outgoing: bool,
    sender_name: Option<String>,
    body: Option<String>,
    timestamp_ms: u64,
    unsend: Option<(u64, String)>,
    receipt: Option<(i32, Vec<u64>)>,
    /// Attachment pointers only; the files are fetched by a separate
    /// background download queue after the message is stored.
    attachments: Vec<AttachmentMeta>,
}

impl IncomingMessage {
    fn control(hash: String, sender_id: String, contact_id: String, timestamp_ms: u64) -> Self {
        Self {
            hash,
            sender_id,
            contact_id,
            outgoing: false,
            sender_name: None,
            body: None,
            timestamp_ms,
            unsend: None,
            receipt: None,
            attachments: Vec::new(),
        }
    }
}

struct RetrieveResult {
    messages: Vec<IncomingMessage>,
    queued: usize,
    undecryptable: usize,
    bad_envelope: usize,
    bad_content: usize,
    last_hash: Option<String>,
    groups: Vec<DiscoveredGroup>,
    /// Updated per-group message cursors (group id → last hash).
    group_cursors: HashMap<String, String>,
}

/// One attachment waiting to be downloaded into the local cache.
#[derive(Clone)]
struct PendingDownload {
    peer: String,
    timestamp_ms: u64,
    outgoing: bool,
    index: usize,
    meta: AttachmentMeta,
}

struct DownloadedAttachment {
    job: PendingDownload,
    encrypted: Vec<u8>,
    preview: Option<ImagePreview>,
}

#[derive(Clone)]
struct DiscoveredGroup {
    id: String,
    name: String,
}

#[derive(Clone)]
struct GroupRuntime {
    id: String,
    public_key: [u8; 32],
    secret_key: Vec<u8>,
    encryption_key: [u8; 32],
}

struct SessionClient {
    identity: Identity,
    network: Network<HttpTransport>,
    groups: Mutex<HashMap<String, GroupRuntime>>,
}

struct SentAttachments {
    timestamp_ms: u64,
    caption: String,
    /// (metadata, encrypted blob, preview) per attachment, in send order.
    files: Vec<(AttachmentMeta, Vec<u8>, Option<ImagePreview>)>,
    sync_copy_sent: bool,
}

struct ImageViewer {
    title: String,
    protocol: StatefulProtocol,
}

struct LocalStore {
    connection: Connection,
    key: [u8; 32],
}

impl LocalStore {
    fn open(identity: &Identity) -> Result<Self, String> {
        let root = session_data_dir()?;
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let path = root.join(format!("{}.sqlite3", identity.session_id));
        let key = history_key(&identity.ed_secret[..32])?;
        migrate_plain_database(&path, &key)?;
        let connection = Connection::open(&path).map_err(|e| e.to_string())?;
        let key_hex = hex::encode(key);
        connection
            .execute_batch(&format!(
                "PRAGMA key = \"x'{key_hex}'\"; PRAGMA cipher_compatibility = 4;"
            ))
            .map_err(|e| format!("open encrypted local history: {e}"))?;
        connection
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| {
                row.get::<_, i64>(0)
            })
            .map_err(|e| format!("local history key is invalid or database is damaged: {e}"))?;
        connection
            .execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS contacts (session_id TEXT PRIMARY KEY, display_name TEXT NOT NULL DEFAULT '');
                 CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS messages (
                    peer_id TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL,
                    outgoing INTEGER NOT NULL,
                    body BLOB NOT NULL,
                    receipt_status INTEGER NOT NULL DEFAULT 0,
                    is_read INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(peer_id, timestamp_ms, outgoing)
                 );
                 CREATE TABLE IF NOT EXISTS seen_hashes (hash TEXT PRIMARY KEY);
                 CREATE TABLE IF NOT EXISTS sync_state (id INTEGER PRIMARY KEY CHECK(id = 1), last_hash TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS profiles (session_id TEXT PRIMARY KEY, display_name TEXT NOT NULL);",
            )
            .map_err(|e| e.to_string())?;
        let _ = connection.execute(
            "ALTER TABLE contacts ADD COLUMN display_name TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE messages ADD COLUMN receipt_status INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE messages ADD COLUMN is_read INTEGER NOT NULL DEFAULT 1",
            [],
        );
        let route_version: Option<String> = connection
            .query_row(
                "SELECT value FROM settings WHERE key = 'sync_target_route_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?;
        if route_version.as_deref() != Some("2") {
            let known_messages: i64 = connection
                .query_row("SELECT count(*) FROM seen_hashes", [], |row| row.get(0))
                .map_err(|e| e.to_string())?;
            if known_messages > 0 || route_version.is_some() {
                connection
                    .execute("DELETE FROM seen_hashes", [])
                    .map_err(|e| e.to_string())?;
                connection
                    .execute("DELETE FROM sync_state", [])
                    .map_err(|e| e.to_string())?;
                debug_log(
                    "sync.reindex",
                    "reason=receipt_order_and_sync_target_upgrade",
                );
            }
            connection.execute(
                "INSERT INTO settings(key, value) VALUES ('sync_target_route_version', '2') ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [],
            ).map_err(|e| e.to_string())?;
        }
        Ok(Self { connection, key })
    }

    fn encrypt_body(&self, body: &str) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let nonce = random::random(24);
        let encrypted = cipher
            .encrypt(XNonce::from_slice(&nonce), body.as_bytes())
            .map_err(|_| "could not encrypt local message".to_string())?;
        Ok([nonce, encrypted].concat())
    }

    fn decrypt_body(&self, encrypted: &[u8]) -> Result<String, String> {
        if encrypted.len() < 24 {
            return Err("invalid encrypted local message".into());
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&encrypted[..24]), &encrypted[24..])
            .map_err(|_| "could not decrypt local message".to_string())?;
        String::from_utf8(plaintext).map_err(|e| e.to_string())
    }

    fn load(&self, app: &mut App) -> Result<(), String> {
        let mut statement = self
            .connection
            .prepare("SELECT session_id, display_name FROM contacts ORDER BY session_id")
            .map_err(|e| e.to_string())?;
        let contacts = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        for contact in contacts {
            let (id, name) = contact.map_err(|e| e.to_string())?;
            let index = app.ensure_contact(&id);
            if !name.is_empty() {
                app.conversations[index].name = name;
            }
        }
        app.profile_name = self
            .connection
            .query_row(
                "SELECT value FROM settings WHERE key = 'profile_name'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| e.to_string())?
            .unwrap_or_default();
        drop(statement);

        let mut statement = self
            .connection
            .prepare(
                "SELECT peer_id, timestamp_ms, outgoing, body, receipt_status, is_read FROM messages ORDER BY timestamp_ms",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, bool>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u8>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        let root = session_data_dir().ok();
        for row in rows {
            let (peer, timestamp_ms, outgoing, encrypted, receipt_status, is_read) =
                row.map_err(|e| e.to_string())?;
            let stored = self.decrypt_body(&encrypted)?;
            let mut message = Message::new(String::new(), timestamp_ms, outgoing);
            message.receipt_status = receipt_status;
            message.is_read = is_read;
            if let Some(json) = stored.strip_prefix(STORED_MESSAGE_PREFIX) {
                let payload: StoredMessage =
                    serde_json::from_str(json).map_err(|e| e.to_string())?;
                message.body = payload.body;
                message.sender = payload.sender;
                message.attachments = payload.attachments;
                message.image_previews = payload.image_previews;
                if let Some(legacy) = payload.attachment {
                    message.attachments.insert(0, legacy);
                    message.image_previews.insert(0, payload.image_preview);
                }
            } else {
                message.body = stored;
            }
            message
                .image_previews
                .resize(message.attachments.len(), None);
            // Rebuild missing previews from cached image blobs.
            for (index, meta) in message.attachments.iter().enumerate() {
                if message.image_previews[index].is_some()
                    || !meta.content_type.starts_with("image/")
                {
                    continue;
                }
                let Some(root) = root.as_deref() else { break };
                let path =
                    session_tui_media::attachment_blob_path(root, &peer, timestamp_ms, index);
                message.image_previews[index] = std::fs::read(path).ok().and_then(|blob| {
                    session_tui_media::decrypt_attachment(
                        &blob,
                        &meta.key,
                        &meta.digest,
                        meta.deterministic,
                    )
                    .ok()
                    .and_then(|plaintext| session_tui_media::image_preview(&plaintext))
                });
            }
            let index = app.ensure_contact(&peer);
            let convo = &mut app.conversations[index];
            convo.preview = message.preview_text();
            convo.messages.push(message);
            convo.selected_message = convo.messages.len() - 1;
        }
        drop(statement);

        let mut statement = self
            .connection
            .prepare("SELECT session_id, display_name FROM profiles")
            .map_err(|e| e.to_string())?;
        let profiles = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        for profile in profiles {
            let (id, name) = profile.map_err(|e| e.to_string())?;
            app.display_names.insert(id, name);
        }
        drop(statement);
        app.sort_conversations();
        app.selected = 0;

        let mut statement = self
            .connection
            .prepare("SELECT hash FROM seen_hashes")
            .map_err(|e| e.to_string())?;
        let hashes = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| e.to_string())?;
        for hash in hashes {
            app.seen_hashes.insert(hash.map_err(|e| e.to_string())?);
        }
        Ok(())
    }

    fn save_profile_name(&self, name: &str) -> Result<(), String> {
        self.connection.execute(
            "INSERT INTO settings(key, value) VALUES ('profile_name', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_contact_name(&self, id: &str, name: &str) -> Result<(), String> {
        self.connection.execute(
            "INSERT INTO contacts(session_id, display_name) VALUES (?1, ?2) ON CONFLICT(session_id) DO UPDATE SET display_name=excluded.display_name",
            params![id, name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_contact(&self, id: &str) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT OR IGNORE INTO contacts(session_id) VALUES (?1)",
                [id],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn encrypted_payload(&self, message: &Message) -> Result<Vec<u8>, String> {
        let payload = serde_json::to_string(&StoredMessage {
            body: message.body.clone(),
            attachment: None,
            image_preview: None,
            attachments: message.attachments.clone(),
            image_previews: message.image_previews.clone(),
            sender: message.sender.clone(),
        })
        .map_err(|e| e.to_string())?;
        self.encrypt_body(&format!("{STORED_MESSAGE_PREFIX}{payload}"))
    }

    fn save_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        let body = self.encrypted_payload(message)?;
        self.connection.execute(
            "INSERT OR IGNORE INTO messages(peer_id, timestamp_ms, outgoing, body, receipt_status, is_read) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![peer, message.timestamp_ms as i64, message.outgoing, body, message.receipt_status, message.is_read],
        ).map_err(|e| e.to_string())?;
        self.save_contact(peer)
    }

    /// Rewrite the stored payload (e.g. after an attachment preview arrives).
    fn update_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        let body = self.encrypted_payload(message)?;
        self.connection.execute(
            "UPDATE messages SET body = ?4 WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = ?3",
            params![peer, message.timestamp_ms as i64, message.outgoing, body],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_display_name(&self, id: &str, name: &str) -> Result<(), String> {
        self.connection.execute(
            "INSERT INTO profiles(session_id, display_name) VALUES (?1, ?2) ON CONFLICT(session_id) DO UPDATE SET display_name=excluded.display_name",
            params![id, name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_attachment_blob(
        &self,
        peer: &str,
        timestamp: u64,
        index: usize,
        bytes: &[u8],
    ) -> Result<(), String> {
        let root = session_data_dir()?;
        let path = session_tui_media::attachment_blob_path(&root, peer, timestamp, index);
        let parent = path.parent().ok_or("invalid attachment cache path")?;
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        std::fs::write(path, bytes).map_err(|e| e.to_string())
    }

    fn get_group_cursors(&self) -> Result<HashMap<String, String>, String> {
        let mut statement = self
            .connection
            .prepare("SELECT key, value FROM settings WHERE key LIKE 'group_cursor:%'")
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| e.to_string())?;
        let mut cursors = HashMap::new();
        for row in rows {
            let (key, value) = row.map_err(|e| e.to_string())?;
            if let Some(group) = key.strip_prefix("group_cursor:") {
                cursors.insert(group.to_owned(), value);
            }
        }
        Ok(cursors)
    }

    fn set_group_cursor(&self, group: &str, hash: &str) -> Result<(), String> {
        self.connection.execute(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![format!("group_cursor:{group}"), hash],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn update_receipt_status(&self, peer: &str, timestamp: u64, status: u8) -> Result<(), String> {
        self.connection.execute(
            "UPDATE messages SET receipt_status = MAX(receipt_status, ?3) WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = 1",
            params![peer, timestamp as i64, status],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_message_read(&self, peer: &str, timestamp: u64) -> Result<(), String> {
        self.connection.execute(
            "UPDATE messages SET is_read = 1 WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = 0",
            params![peer, timestamp as i64],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_seen(&self, hash: &str) -> Result<bool, String> {
        let inserted = self
            .connection
            .execute(
                "INSERT OR IGNORE INTO seen_hashes(hash) VALUES (?1)",
                [hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(inserted > 0)
    }

    fn get_last_hash(&self) -> Result<Option<String>, String> {
        self.connection
            .query_row("SELECT last_hash FROM sync_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())
    }

    fn set_last_hash(&self, hash: &str) -> Result<(), String> {
        self.connection
            .execute(
                "INSERT INTO sync_state(id, last_hash) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET last_hash = excluded.last_hash",
                [hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn delete_empty_contact(&self, peer: &str) -> Result<(), String> {
        self.connection.execute(
            "DELETE FROM contacts WHERE session_id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE peer_id = ?1)",
            [peer],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Delete one stored message and its cached attachment files.
    fn delete_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        self.connection
            .execute(
                "DELETE FROM messages WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = ?3",
                params![peer, message.timestamp_ms as i64, message.outgoing],
            )
            .map_err(|e| e.to_string())?;
        if let Ok(root) = session_data_dir() {
            for index in 0..message.attachments.len() {
                let _ = std::fs::remove_file(session_tui_media::attachment_blob_path(
                    &root,
                    peer,
                    message.timestamp_ms,
                    index,
                ));
            }
        }
        Ok(())
    }
}

fn session_data_dir() -> Result<std::path::PathBuf, String> {
    let root = if let Some(path) = std::env::var_os("APPDATA") {
        std::path::PathBuf::from(path).join("SessionTUI")
    } else if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        std::path::PathBuf::from(path).join("session-tui")
    } else if let Some(path) = std::env::var_os("HOME") {
        std::path::PathBuf::from(path).join(".local/share/session-tui")
    } else if let Some(path) = std::env::var_os("USERPROFILE") {
        std::path::PathBuf::from(path).join("AppData/Roaming/SessionTUI")
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(".session-tui")
    };
    std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    Ok(root)
}

fn history_key(seed: &[u8]) -> Result<[u8; 32], String> {
    let mut params = blake2b_simd::Params::new();
    params.hash_length(32).key(b"SessionTuiLocalHistory");
    params
        .hash(seed)
        .as_bytes()
        .try_into()
        .map_err(|_| "invalid history key".into())
}

fn migrate_plain_database(path: &std::path::Path, key: &[u8; 32]) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    let mut header = [0u8; 16];
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.read_exact(&mut header).is_err() || &header != b"SQLite format 3\0" {
        return Ok(());
    }

    // Import the earlier TUI database (which encrypted message bodies but not
    // SQLite pages) into a fully encrypted SQLCipher file.
    let plain = Connection::open(path).map_err(|e| e.to_string())?;
    let tables: HashSet<String> = plain
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .and_then(|mut s| s.query_map([], |row| row.get(0))?.collect())
        .map_err(|e| e.to_string())?;
    let mut contacts = Vec::<String>::new();
    let mut messages = Vec::<(String, i64, bool, Vec<u8>)>::new();
    let mut hashes = Vec::<String>::new();
    let mut cursor = None::<String>;
    if tables.contains("contacts") {
        contacts = plain
            .prepare("SELECT session_id FROM contacts")
            .and_then(|mut s| s.query_map([], |row| row.get(0))?.collect())
            .map_err(|e| e.to_string())?;
    }
    if tables.contains("messages") {
        messages = plain
            .prepare("SELECT peer_id, timestamp_ms, outgoing, body FROM messages")
            .and_then(|mut s| {
                s.query_map([], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?
                .collect()
            })
            .map_err(|e| e.to_string())?;
    }
    if tables.contains("seen_hashes") {
        hashes = plain
            .prepare("SELECT hash FROM seen_hashes")
            .and_then(|mut s| s.query_map([], |row| row.get(0))?.collect())
            .map_err(|e| e.to_string())?;
    }
    if tables.contains("sync_state") {
        cursor = plain
            .query_row("SELECT last_hash FROM sync_state WHERE id=1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|e| e.to_string())?;
    }
    drop(plain);

    let suffix = now_ms();
    let encrypted_path = path.with_extension(format!("{suffix}.encrypted.tmp"));
    let backup_path = path.with_extension(format!("{suffix}.plaintext.bak"));
    let encrypted = Connection::open(&encrypted_path).map_err(|e| e.to_string())?;
    let key_hex = hex::encode(key);
    encrypted
        .execute_batch(&format!(
            "PRAGMA key = \"x'{key_hex}'\"; PRAGMA cipher_compatibility = 4;"
        ))
        .map_err(|e| e.to_string())?;
    create_history_schema(&encrypted)?;
    for id in contacts {
        encrypted
            .execute(
                "INSERT OR IGNORE INTO contacts(session_id) VALUES (?1)",
                [id],
            )
            .map_err(|e| e.to_string())?;
    }
    for (peer, timestamp, outgoing, body) in messages {
        encrypted.execute(
            "INSERT OR IGNORE INTO messages(peer_id, timestamp_ms, outgoing, body) VALUES (?1, ?2, ?3, ?4)",
            params![peer, timestamp, outgoing, body],
        ).map_err(|e| e.to_string())?;
    }
    for hash in hashes {
        encrypted
            .execute(
                "INSERT OR IGNORE INTO seen_hashes(hash) VALUES (?1)",
                [hash],
            )
            .map_err(|e| e.to_string())?;
    }
    if let Some(cursor) = cursor {
        encrypted
            .execute(
                "INSERT INTO sync_state(id, last_hash) VALUES (1, ?1)",
                [cursor],
            )
            .map_err(|e| e.to_string())?;
    }
    drop(encrypted);

    for suffix in ["-wal", "-shm"] {
        let mut sidecar = path.as_os_str().to_os_string();
        sidecar.push(suffix);
        let _ = std::fs::remove_file(std::path::PathBuf::from(sidecar));
    }
    std::fs::rename(path, &backup_path).map_err(|e| e.to_string())?;
    if let Err(error) = std::fs::rename(&encrypted_path, path) {
        let _ = std::fs::rename(&backup_path, path);
        return Err(error.to_string());
    }
    std::fs::remove_file(backup_path).map_err(|e| e.to_string())?;
    Ok(())
}

fn create_history_schema(connection: &Connection) -> Result<(), String> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS contacts (session_id TEXT PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS messages (
            peer_id TEXT NOT NULL,
            timestamp_ms INTEGER NOT NULL,
            outgoing INTEGER NOT NULL,
            body BLOB NOT NULL,
            receipt_status INTEGER NOT NULL DEFAULT 0,
            is_read INTEGER NOT NULL DEFAULT 1,
            UNIQUE(peer_id, timestamp_ms, outgoing)
         );
         CREATE TABLE IF NOT EXISTS seen_hashes (hash TEXT PRIMARY KEY);
         CREATE TABLE IF NOT EXISTS sync_state (id INTEGER PRIMARY KEY CHECK(id = 1), last_hash TEXT NOT NULL);",
    ).map_err(|e| e.to_string())
}

impl SessionClient {
    fn new(identity: Identity) -> Result<Self, String> {
        let transport = HttpTransport::new().map_err(|e| e.to_string())?;
        Ok(Self {
            identity,
            network: Network::new(NetworkConfig::default(), transport),
            groups: Mutex::new(HashMap::new()),
        })
    }

    async fn retrieve_namespace_raw(
        &self,
        pubkey: &str,
        pubkey_ed25519: &str,
        namespace: i32,
        signing_key: &[u8],
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.retrieve_namespace_since(pubkey, pubkey_ed25519, namespace, signing_key, None)
            .await
            .map(|(messages, _)| messages)
    }

    /// Retrieve every message after `cursor`, following the swarm's `more`
    /// flag. Returns the messages and the hash of the newest one seen.
    async fn retrieve_namespace_since(
        &self,
        pubkey: &str,
        pubkey_ed25519: &str,
        namespace: i32,
        signing_key: &[u8],
        cursor: Option<&str>,
    ) -> Result<(Vec<(String, Vec<u8>)>, Option<String>), String> {
        let mut all = Vec::new();
        let mut last_hash = cursor.map(str::to_owned);
        for _ in 0..MAX_RETRIEVE_PAGES {
            let (page, more) = self
                .retrieve_namespace_page(
                    pubkey,
                    pubkey_ed25519,
                    namespace,
                    signing_key,
                    last_hash.as_deref(),
                )
                .await?;
            let empty = page.is_empty();
            if let Some((hash, _)) = page.last() {
                last_hash = Some(hash.clone());
            }
            all.extend(page);
            if !more || empty {
                break;
            }
        }
        Ok((all, last_hash))
    }

    async fn retrieve_namespace_page(
        &self,
        pubkey: &str,
        pubkey_ed25519: &str,
        namespace: i32,
        signing_key: &[u8],
        last_hash: Option<&str>,
    ) -> Result<(Vec<(String, Vec<u8>)>, bool), String> {
        let response = if pubkey.starts_with("03") {
            // Group namespace requests use the group signature format: pubkey,
            // namespace, timestamp and signature. They do not include the
            // user-request-only pubkey_ed25519 field.
            let timestamp_ms = now_ms();
            let signature = libsession::network::auth::sign_request_b64(
                "retrieve",
                namespace,
                timestamp_ms,
                signing_key,
            )
            .map_err(|error| error.to_string())?;
            let mut params = serde_json::Map::new();
            params.insert("pubkey".to_owned(), Value::String(pubkey.to_owned()));
            params.insert("namespace".to_owned(), Value::from(namespace));
            params.insert("timestamp".to_owned(), Value::from(timestamp_ms));
            params.insert("signature".to_owned(), Value::String(signature));
            params.insert("max_size".to_owned(), Value::from(1_000_000u32));
            if let Some(last_hash) = last_hash {
                params.insert("last_hash".to_owned(), Value::String(last_hash.to_owned()));
            }
            self.network
                .send_rpc("retrieve", Value::Object(params), Some(pubkey))
                .await
                .map_err(|error| error.to_string())?
        } else {
            self.network
                .send_retrieve(&RetrieveParams {
                    pubkey,
                    pubkey_ed25519,
                    namespace,
                    timestamp_ms: now_ms(),
                    last_hash,
                    max_size: Some(1_000_000),
                    signing_key,
                })
                .await
                .map_err(|error| error.to_string())?
        };
        if response.status_code != 200 {
            let detail = response
                .body
                .as_deref()
                .and_then(|body| serde_json::from_str::<Value>(body).ok())
                .and_then(|value| {
                    ["message", "error", "result", "reason"]
                        .iter()
                        .find_map(|key| {
                            value
                                .get(*key)
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        })
                })
                .unwrap_or_else(|| "no_json_error_detail".to_owned());
            let detail: String = detail.chars().take(240).collect();
            debug_log(
                "namespace.retrieve.rejected",
                &format!("namespace={namespace} status={} detail={detail:?}", response.status_code),
            );
            return Err(format!(
                "namespace {namespace} retrieve HTTP {}",
                response.status_code
            ));
        }
        let value: Value = serde_json::from_str(
            response
                .body
                .as_deref()
                .ok_or("retrieve returned no body")?,
        )
        .map_err(|error| format!("invalid namespace {namespace} response: {error}"))?;
        let messages = value
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| format!("namespace {namespace} response has no messages"))?;
        let more = value.get("more").and_then(Value::as_bool).unwrap_or(false);
        let mut result = Vec::new();
        for item in messages {
            let (Some(hash), Some(data)) = (
                item.get("hash").and_then(Value::as_str),
                item.get("data").and_then(Value::as_str),
            ) else {
                continue;
            };
            let Ok(mut bytes) = STANDARD.decode(data) else {
                continue;
            };
            if namespace != 5
                && let Ok(ws) = WebSocketMessage::decode(bytes.as_slice())
                && ws.r#type == Some(web_socket_message::Type::Request as i32)
                && let Some(body) = ws.request.and_then(|request| request.body)
            {
                bytes = body;
            }
            result.push((hash.to_owned(), bytes));
        }
        debug_log(
            "namespace.retrieve",
            &format!(
                "namespace={namespace} pubkey_prefix={} messages={} total_bytes={}",
                &pubkey[..pubkey.len().min(8)],
                result.len(),
                result.iter().map(|(_, bytes)| bytes.len()).sum::<usize>()
            ),
        );
        Ok((result, more))
    }

    async fn discover_groups(&self) -> Result<Vec<DiscoveredGroup>, String> {
        let account_pubkey = hex::encode(self.identity.ed_public);
        let messages = self
            .retrieve_namespace_raw(
                &self.identity.session_id,
                &account_pubkey,
                5,
                &self.identity.ed_secret,
            )
            .await?;
        let mut unwrapped_messages = Vec::new();
        let mut unwrap_failures = 0usize;
        let mut double_wrapped = 0usize;
        for (hash, wire) in &messages {
            match self.unwrap_user_groups_config(wire) {
                Ok(mut config_data) => {
                    if let Ok(inner_config_data) = self.unwrap_user_groups_config(&config_data) {
                        config_data = inner_config_data;
                        double_wrapped += 1;
                    }
                    unwrapped_messages.push((hash.clone(), config_data));
                }
                Err(error) => {
                    unwrap_failures += 1;
                    debug_log("group.config.unwrap_failed", &error);
                }
            }
        }
        debug_log(
            "group.config.unwrapped",
            &format!(
                "messages={} successful={} failed={unwrap_failures} double_wrapped={double_wrapped} payload_bytes={}",
                messages.len(),
                unwrapped_messages.len(),
                unwrapped_messages
                    .iter()
                    .map(|(_, data)| data.len())
                    .sum::<usize>()
            ),
        );
        let mut payload_decrypted = 0usize;
        let mut payload_bencode_dicts = 0usize;
        let mut payload_compressed = 0usize;
        let mut payload_multipart = 0usize;
        let mut payload_other = 0usize;
        let account_seed: [u8; 32] = self.identity.ed_secret[..32]
            .try_into()
            .map_err(|error: std::array::TryFromSliceError| error.to_string())?;
        for (_, payload) in &unwrapped_messages {
            if let Ok(plaintext) = libsession::config::encrypt::config_decrypt(
                payload,
                &account_seed,
                "UserGroups",
            ) {
                payload_decrypted += 1;
                let first_nonzero = plaintext.iter().copied().find(|byte| *byte != 0);
                match first_nonzero {
                    Some(b'd') => payload_bencode_dicts += 1,
                    Some(b'z') => payload_compressed += 1,
                    Some(b'm') => payload_multipart += 1,
                    _ => payload_other += 1,
                }
            }
        }
        debug_log(
            "group.config.payload_probe",
            &format!(
                "messages={} decrypted={} bencode_dicts={} compressed={} multipart={} other={}",
                unwrapped_messages.len(),
                payload_decrypted,
                payload_bencode_dicts,
                payload_compressed,
                payload_multipart,
                payload_other
            ),
        );
        let mut config = ConfigBase::<UserGroups>::new(&self.identity.ed_secret, None)?;
        let merge: Vec<(&str, &[u8])> = unwrapped_messages
            .iter()
            .map(|(hash, bytes)| (hash.as_str(), bytes.as_slice()))
            .collect();
        let merged_hashes = config.merge(&merge)?;

        let user_groups: Vec<UserGroupInfo> = config.config_type.iter_groups().cloned().collect();
        debug_log(
            "group.user_config.parsed",
            &format!(
                "groups={} config_messages={} merged_messages={}",
                user_groups.len(),
                messages.len(),
                merged_hashes.len()
            ),
        );
        let mut runtime_groups = HashMap::new();
        let mut discovered_groups = Vec::new();
        for group in user_groups {
            debug_log(
                "group.config.record",
                &format!(
                    "id_len={} id_prefix={} seed_bytes={} auth_bytes={} removed_status={}",
                    group.id.len(),
                    &group.id[..group.id.len().min(8)],
                    group.secretkey.len(),
                    group.auth_data.len(),
                    group.removed_status
                ),
            );
            if group.removed_status != 0 {
                debug_log(
                    "group.config.skipped",
                    &format!("reason=removed status={}", group.removed_status),
                );
                continue;
            }
            if group.id.len() != 66 || !group.id.starts_with("03") {
                debug_log(
                    "group.config.skipped",
                    &format!(
                        "reason=invalid_group_id id_len={} starts_with_03={}",
                        group.id.len(),
                        group.id.starts_with("03")
                    ),
                );
                continue;
            }
            let display_name = if group.base.name.is_empty() {
                format!("Group {}", &group.id[2..10])
            } else {
                group.base.name.clone()
            };
            discovered_groups.push(DiscoveredGroup {
                id: group.id.clone(),
                name: display_name,
            });
            if group.secretkey.len() != 32 {
                debug_log(
                    "group.config.no_admin_seed",
                    &format!(
                        "group_prefix={} seed_bytes={}",
                        &group.id[..8],
                        group.secretkey.len()
                    ),
                );
                continue;
            }
            let (public_key, secret_key) =
                ed25519::ed25519_key_pair_from_seed(&group.secretkey).map_err(|e| e.to_string())?;
            if hex::encode(public_key) != group.id[2..] {
                debug_log(
                    "group.config.invalid",
                    "admin_seed_does_not_match_group_id=true",
                );
                continue;
            }
            let group_pubkey = format!("03{}", hex::encode(public_key));
            let key_messages = match self
                .retrieve_namespace_raw(&group_pubkey, &hex::encode(public_key), 12, &secret_key)
                .await
            {
                Ok(messages) => messages,
                Err(error) => {
                    debug_log(
                        "group.keys.retrieve_failed",
                        &format!("group_prefix={} error={error}", &group.id[..8]),
                    );
                    continue;
                }
            };
            let mut selected_key: Option<(i64, [u8; 32])> = None;
            let mut decrypted_key_count = 0usize;
            let key_message_count = key_messages.len();
            for (_, message) in key_messages {
                let Ok(libsession::util::bencode::BtValue::Dict(dict)) =
                    libsession::util::bencode::decode(&message)
                else {
                    continue;
                };
                let (
                    Some(libsession::util::bencode::BtValue::String(nonce)),
                    Some(libsession::util::bencode::BtValue::String(encrypted_key)),
                    Some(libsession::util::bencode::BtValue::Integer(generation)),
                ) = (
                    dict.get(b"#".as_slice()),
                    dict.get(b"K".as_slice()),
                    dict.get(b"G".as_slice()),
                )
                else {
                    continue;
                };
                let Ok(nonce) = <[u8; 24]>::try_from(nonce.as_slice()) else {
                    continue;
                };
                if encrypted_key.len() != 48 {
                    continue;
                }
                let admin_key = blake2b_simd::Params::new()
                    .hash_length(32)
                    .key(b"SessionGroupKeyAdminKey")
                    .hash(&group.secretkey);
                let cipher = XChaCha20Poly1305::new_from_slice(admin_key.as_bytes())
                    .map_err(|error| error.to_string())?;
                let nonce = XNonce::from(nonce);
                let Ok(decrypted) = cipher.decrypt(&nonce, encrypted_key.as_slice()) else {
                    continue;
                };
                let Ok(group_key) = <[u8; 32]>::try_from(decrypted.as_slice()) else {
                    continue;
                };
                decrypted_key_count += 1;
                if selected_key
                    .as_ref()
                    .is_none_or(|(old, _)| generation > old)
                {
                    selected_key = Some((*generation, group_key));
                }
            }
            let Some((_, encryption_key)) = selected_key else {
                debug_log(
                    "group.keys.unavailable",
                    &format!(
                        "group_prefix={} key_messages={key_message_count} decrypted_keys={decrypted_key_count}",
                        &group.id[..8]
                    ),
                );
                continue;
            };

            let info_messages = match self
                .retrieve_namespace_raw(&group_pubkey, &hex::encode(public_key), 13, &secret_key)
                .await
            {
                Ok(messages) => messages,
                Err(error) => {
                    debug_log(
                        "group.info.retrieve_failed",
                        &format!("group_prefix={} error={error}", &group.id[..8]),
                    );
                    Vec::new()
                }
            };
            let mut info =
                ConfigBase::<SharedGroupInfo>::new_group(&public_key, Some(&secret_key), None)?;
            info.add_key(encryption_key, true);
            let info_merge: Vec<(&str, &[u8])> = info_messages
                .iter()
                .map(|(hash, bytes)| (hash.as_str(), bytes.as_slice()))
                .collect();
            let _ = info.merge(&info_merge);
            let name = info
                .config_type
                .name
                .clone()
                .filter(|name| !name.is_empty())
                .or_else(|| (!group.base.name.is_empty()).then(|| group.base.name.clone()))
                .unwrap_or_else(|| format!("Group {}", &group.id[2..10]));
            if let Some(discovered) = discovered_groups.iter_mut().find(|item| item.id == group.id) {
                discovered.name = name.clone();
            }
            debug_log(
                "group.config.runtime_ready",
                &format!("group_prefix={} name_bytes={}", &group.id[..8], name.len()),
            );
            runtime_groups.insert(
                group.id.clone(),
                GroupRuntime {
                    id: group.id,
                    public_key,
                    secret_key: secret_key.to_vec(),
                    encryption_key,
                },
            );
        }
        *self.groups.lock().map_err(|error| error.to_string())? = runtime_groups;
        Ok(discovered_groups)
    }

    fn unwrap_user_groups_config(&self, wire: &[u8]) -> Result<Vec<u8>, String> {
        let ws = WebSocketMessage::decode(wire)
            .map_err(|error| format!("invalid config websocket frame: {error}"))?;
        if ws.r#type != Some(web_socket_message::Type::Request as i32) {
            return Err("config websocket frame is not a request".to_owned());
        }
        let envelope_bytes = ws
            .request
            .and_then(|request| request.body)
            .ok_or_else(|| "config websocket request has no body".to_owned())?;
        let envelope = Envelope::decode(envelope_bytes.as_slice())
            .map_err(|error| format!("invalid config envelope: {error}"))?;
        let ciphertext = envelope
            .content
            .as_deref()
            .ok_or_else(|| "config envelope has no encrypted content".to_owned())?;
        let (plaintext, sender_id) =
            session_encrypt::decrypt_incoming_session_id(&self.identity.ed_secret, ciphertext)
                .map_err(|error| format!("config envelope decrypt failed: {error}"))?;
        if sender_id != self.identity.session_id {
            return Err("config envelope sender is not this account".to_owned());
        }
        let content = Content::decode(strip_session_padding(&plaintext))
            .map_err(|error| format!("invalid shared config content: {error}"))?;
        let shared = content
            .shared_config_message
            .ok_or_else(|| "config content has no SharedConfigMessage".to_owned())?;
        if shared.kind != 4 {
            return Err(format!(
                "shared config kind mismatch: expected UserGroups (4), got {}",
                shared.kind
            ));
        }
        Ok(shared.data)
    }

    async fn retrieve_group_messages(
        &self,
        group: &GroupRuntime,
        cursor: Option<&str>,
    ) -> Result<(Vec<IncomingMessage>, Option<String>), String> {
        let group_pubkey = format!("03{}", hex::encode(group.public_key));
        let (raw_messages, last_hash) = self
            .retrieve_namespace_since(
                &group_pubkey,
                &hex::encode(group.public_key),
                11,
                &group.secret_key,
                cursor,
            )
            .await?;
        let key_refs: [&[u8]; 1] = [&group.encryption_key];
        let decode_keys = DecodeEnvelopeKey {
            group_ed25519_pubkey: Some(&group.public_key),
            decrypt_keys: &key_refs,
        };
        let mut incoming = Vec::new();
        for (hash, payload) in raw_messages {
            let decoded = match decode_envelope(&decode_keys, &payload, &[0u8; 32]) {
                Ok(decoded) => decoded,
                Err(error) => {
                    debug_log("group.message.decrypt_failed", &format!("error={error}"));
                    continue;
                }
            };
            let Ok(content) = Content::decode(decoded.content_plaintext.as_slice()) else {
                continue;
            };
            let sender_id = format!("05{}", hex::encode(decoded.sender_x25519_pubkey));
            let outgoing = sender_id == self.identity.session_id;
            if let Some(unsend) = content.unsend_request {
                let mut message = IncomingMessage::control(
                    hash,
                    sender_id,
                    group.id.clone(),
                    decoded.envelope.timestamp,
                );
                message.unsend = Some((unsend.timestamp, unsend.author));
                incoming.push(message);
                continue;
            }
            if content.receipt_message.is_some() {
                continue;
            }
            let Some(data_message) = content.data_message else {
                continue;
            };
            let timestamp_ms = data_message.timestamp.unwrap_or(decoded.envelope.timestamp);
            let attachments: Vec<AttachmentMeta> = data_message
                .attachments
                .iter()
                .map(attachment_meta_from_pointer)
                .collect();
            let text = data_message.body.unwrap_or_default();
            if text.is_empty() && attachments.is_empty() {
                continue;
            }
            let sender_name = data_message
                .profile
                .and_then(|profile| profile.display_name)
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty());
            incoming.push(IncomingMessage {
                hash,
                sender_id,
                contact_id: group.id.clone(),
                outgoing,
                sender_name,
                body: Some(text),
                timestamp_ms,
                unsend: None,
                receipt: None,
                attachments,
            });
        }
        Ok((incoming, last_hash))
    }

    async fn send_message(
        &self,
        recipient_id: &str,
        body: &str,
        profile_name: &str,
    ) -> Result<(u64, bool), String> {
        let timestamp_ms = now_ms();
        let data_message = DataMessage {
            body: Some(body.to_owned()),
            timestamp: Some(timestamp_ms),
            profile: profile_for(profile_name, timestamp_ms),
            ..Default::default()
        };
        let content = Content {
            data_message: Some(data_message.clone()),
            sig_timestamp: Some(timestamp_ms),
            ..Default::default()
        };
        self.send_content(recipient_id, content, timestamp_ms)
            .await?;
        let sync_copy_sent = self.send_sync_copy(recipient_id, data_message, timestamp_ms).await;
        Ok((timestamp_ms, sync_copy_sent))
    }

    /// Encrypt and upload one file to the Session file server.
    async fn upload_attachment(
        &self,
        path: &std::path::Path,
    ) -> Result<(AttachmentPointer, AttachmentMeta, Vec<u8>, Option<ImagePreview>), String> {
        debug_log("attachment.begin", "reading local file");
        let plaintext = std::fs::read(path).map_err(|e| {
            debug_log("attachment.read_failed", &format!("error={e}"));
            format!("read {}: {e}", path.display())
        })?;
        if plaintext.is_empty() {
            debug_log("attachment.read_failed", "reason=empty_file");
            return Err(format!("{} is empty", path.display()));
        }
        let mut config = libsession::network::backends::file_server::default_config();
        // Use the AES-CBC/HMAC attachment format accepted by current mobile
        // clients. The stream format is not yet interoperable with them.
        config.use_stream_encryption = false;
        let (encrypted, key, digest) =
            session_tui_media::encrypt_attachment(&plaintext).map_err(|e| {
                debug_log("attachment.encrypt_failed", &format!("error={e}"));
                e.to_string()
            })?;
        if encrypted.len() as u64 > config.max_file_size {
            return Err(format!(
                "{} exceeds Session's {} MB file limit",
                path.display(),
                config.max_file_size / 1_000_000
            ));
        }
        debug_log(
            "attachment.upload.begin",
            &format!(
                "encrypted_bytes={} scheme={} host={} port={}",
                encrypted.len(),
                config.scheme,
                config.host,
                config.port
            ),
        );
        let upload = self
            .network
            .send_server_request(
                "POST",
                &config.scheme,
                &config.host,
                Some(config.port),
                &config.pubkey_hex,
                libsession::network::backends::file_server::ENDPOINT_FILE,
                vec![("Content-Type".into(), "application/octet-stream".into())],
                Some(&encrypted),
            )
            .await
            .map_err(|e| {
                debug_log("attachment.upload_failed", &format!("error={e}"));
                format!("attachment upload failed: {e}")
            })?;
        if upload.status_code != 200 {
            debug_log(
                "attachment.upload_failed",
                &format!("http_status={}", upload.status_code),
            );
            return Err(format!("file server returned HTTP {}", upload.status_code));
        }
        let response = upload
            .body
            .ok_or("file server returned no upload response")?;
        let file_id = serde_json::from_str::<Value>(&response)
            .map_err(|e| format!("invalid file server response: {e}"))?
            .get("id")
            .and_then(Value::as_str)
            .ok_or("file server response has no file id")?
            .to_owned();
        let url =
            libsession::network::backends::file_server::generate_download_url(&file_id, &config);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("attachment")
            .to_owned();
        let content_type = mime_type_for_name(&file_name).to_owned();
        let dimensions = session_tui_media::image_dimensions(&plaintext);
        let metadata = AttachmentMeta {
            file_name,
            content_type,
            url,
            key: key.to_vec(),
            digest,
            size: plaintext.len() as u32,
            deterministic: false,
            width: dimensions.map(|d| d.0),
            height: dimensions.map(|d| d.1),
        };
        let mut pointer = attachment_pointer_from_meta(&metadata);
        pointer.id = u64::from_le_bytes(random::random(8).try_into().expect("8 random bytes"));
        let preview = session_tui_media::image_preview(&plaintext);
        Ok((pointer, metadata, encrypted, preview))
    }

    /// Send one or more files as a single Session message (an album when
    /// there are several), with `caption` as the message body.
    async fn send_attachments(
        &self,
        recipient_id: &str,
        paths: &[std::path::PathBuf],
        caption: &str,
        profile_name: &str,
    ) -> Result<SentAttachments, String> {
        if paths.is_empty() {
            return Err("no files given".into());
        }
        if paths.len() > MAX_ATTACHMENTS {
            return Err(format!("Session allows at most {MAX_ATTACHMENTS} files per message"));
        }
        let mut pointers = Vec::with_capacity(paths.len());
        let mut files = Vec::with_capacity(paths.len());
        for path in paths {
            let (pointer, metadata, encrypted, preview) = self.upload_attachment(path).await?;
            pointers.push(pointer);
            files.push((metadata, encrypted, preview));
        }
        let timestamp_ms = now_ms();
        let caption = caption.trim().to_owned();
        let data_message = DataMessage {
            body: (!caption.is_empty()).then(|| caption.clone()),
            timestamp: Some(timestamp_ms),
            attachments: pointers,
            profile: profile_for(profile_name, timestamp_ms),
            ..Default::default()
        };
        self.send_content(
            recipient_id,
            Content {
                data_message: Some(data_message.clone()),
                sig_timestamp: Some(timestamp_ms),
                ..Default::default()
            },
            timestamp_ms,
        )
        .await?;
        let sync_copy_sent = self.send_sync_copy(recipient_id, data_message, timestamp_ms).await;
        debug_log(
            "attachment.sent",
            &format!("files={} sync_copy_sent={sync_copy_sent}", files.len()),
        );
        Ok(SentAttachments {
            timestamp_ms,
            caption,
            files,
            sync_copy_sent,
        })
    }

    /// Mirror an outgoing 1:1 DataMessage to this account's own swarm with
    /// syncTarget set, so linked devices file it in the right chat. Group
    /// messages need no copy: every linked device polls the group swarm.
    async fn send_sync_copy(
        &self,
        recipient_id: &str,
        data_message: DataMessage,
        timestamp_ms: u64,
    ) -> bool {
        if recipient_id.starts_with("03") || recipient_id == self.identity.session_id {
            return true;
        }
        let sync_content = Content {
            data_message: Some(DataMessage {
                sync_target: Some(recipient_id.to_owned()),
                ..data_message
            }),
            sig_timestamp: Some(timestamp_ms),
            ..Default::default()
        };
        match self
            .send_content(&self.identity.session_id, sync_content, timestamp_ms)
            .await
        {
            Ok(()) => true,
            Err(error) => {
                debug_log("send.sync_copy", &format!("sent=false error={error}"));
                false
            }
        }
    }

    async fn download_attachment(
        &self,
        pointer: &AttachmentPointer,
    ) -> Result<(AttachmentMeta, Vec<u8>, Option<ImagePreview>), String> {
        let url = pointer.url.as_deref().ok_or("attachment has no URL")?;
        let download = libsession::network::backends::file_server::parse_download_url(url)
            .ok_or("attachment URL is invalid")?;
        let (host, explicit_port) = split_host_port(&download.host);
        let port = explicit_port.or_else(|| match download.scheme.as_str() {
            "https" => Some(443),
            _ => Some(80),
        });
        let server_key = download
            .custom_pubkey_hex
            .as_deref()
            .unwrap_or(&libsession::network::backends::file_server::default_config().pubkey_hex)
            .to_owned();
        let key = pointer
            .key
            .clone()
            .ok_or("attachment has no decryption key")?;
        let digest = pointer.digest.clone().unwrap_or_default();
        debug_log(
            "attachment.download.begin",
            &format!(
                "scheme={} host={} stream={} key_bytes={} digest_bytes={} expected_bytes={}",
                download.scheme,
                host,
                download.wants_stream_decryption,
                key.len(),
                digest.len(),
                pointer.size.unwrap_or_default()
            ),
        );
        let response = self
            .network
            .send_server_request(
                "GET",
                &download.scheme,
                host,
                port,
                &server_key,
                &format!("file/{}", download.file_id),
                Vec::new(),
                None,
            )
            .await
            .map_err(|e| format!("attachment download failed: {e}"))?;
        if response.status_code != 200 {
            return Err(format!(
                "file server returned HTTP {}",
                response.status_code
            ));
        }
        let encrypted = response
            .body_bytes
            .ok_or("file server returned an empty attachment")?;
        let prefix = encrypted
            .first()
            .map(|byte| format!("{byte:02x}"))
            .unwrap_or_else(|| "empty".to_owned());
        debug_log(
            "attachment.download.response",
            &format!(
                "encrypted_bytes={} first_byte={} stream={}",
                encrypted.len(),
                prefix,
                download.wants_stream_decryption
            ),
        );
        let plaintext = session_tui_media::decrypt_attachment(
            &encrypted,
            &key,
            &digest,
            download.wants_stream_decryption,
        )?;
        if let Some(expected) = pointer.size {
            if plaintext.len() != expected as usize {
                // Some Session mobile clients report a size that differs from
                // the authenticated decrypted payload. The HMAC and digest
                // above are the integrity checks; don't discard a valid image
                // or audio attachment because this informational field differs.
                debug_log(
                    "attachment.size_mismatch",
                    &format!(
                        "pointer_bytes={expected} plaintext_bytes={}",
                        plaintext.len()
                    ),
                );
            }
        }
        let file_name = pointer
            .file_name
            .clone()
            .unwrap_or_else(|| "attachment".into());
        let content_type = pointer
            .content_type
            .clone()
            .unwrap_or_else(|| mime_type_for_name(&file_name).into());
        let metadata = AttachmentMeta {
            file_name,
            content_type,
            url: url.to_owned(),
            key,
            digest,
            size: pointer.size.unwrap_or(plaintext.len() as u32),
            deterministic: download.wants_stream_decryption,
            width: pointer.width,
            height: pointer.height,
        };
        let preview = session_tui_media::image_preview(&plaintext);
        Ok((metadata, encrypted, preview))
    }

    async fn send_receipt(
        &self,
        recipient_id: &str,
        receipt_type: i32,
        timestamps: Vec<u64>,
    ) -> Result<(), String> {
        if timestamps.is_empty() {
            return Ok(());
        }
        let content = Content {
            receipt_message: Some(libsession::proto::session_protos::ReceiptMessage {
                r#type: receipt_type,
                timestamp: timestamps,
            }),
            sig_timestamp: Some(now_ms()),
            ..Default::default()
        };
        self.send_content(recipient_id, content, now_ms()).await
    }

    async fn unsend_message(&self, recipient_id: &str, timestamp_ms: u64) -> Result<(), String> {
        let content = Content {
            unsend_request: Some(libsession::proto::session_protos::UnsendRequest {
                timestamp: timestamp_ms,
                author: self.identity.session_id.clone(),
            }),
            sig_timestamp: Some(now_ms()),
            ..Default::default()
        };
        self.send_content(recipient_id, content.clone(), now_ms()).await?;
        // Like Session, also tell this account's other devices.
        if !recipient_id.starts_with("03") && recipient_id != self.identity.session_id {
            if let Err(error) = self
                .send_content(&self.identity.session_id, content, now_ms())
                .await
            {
                debug_log("unsend.sync_copy", &format!("sent=false error={error}"));
            }
        }
        Ok(())
    }

    async fn send_content(
        &self,
        recipient_id: &str,
        content: Content,
        timestamp_ms: u64,
    ) -> Result<(), String> {
        debug_log(
            "send.begin",
            &format!(
                "recipient_prefix={} envelope_timestamp={} content_bytes={}",
                &recipient_id[..recipient_id.len().min(8)],
                timestamp_ms,
                content.encoded_len()
            ),
        );
        if recipient_id.starts_with("03") {
            let group = self
                .groups
                .lock()
                .map_err(|error| error.to_string())?
                .get(recipient_id)
                .cloned()
                .ok_or("group keys are not synced yet; run /rsync and retry")?;
            let mut group_pubkey = [0u8; 33];
            group_pubkey[0] = 0x03;
            group_pubkey[1..].copy_from_slice(&group.public_key);
            let wire = encode_for_group(
                &content.encode_to_vec(),
                &self.identity.ed_secret,
                timestamp_ms,
                &group_pubkey,
                &group.encryption_key,
                None,
            )
            .map_err(|error| format!("could not encode group message: {error}"))?;
            let encoded = STANDARD.encode(wire);
            let store_timestamp = now_ms();
            let signature = libsession::network::auth::sign_request_b64(
                "store",
                11,
                store_timestamp,
                &group.secret_key,
            )
            .map_err(|error| error.to_string())?;
            let mut params = serde_json::Map::new();
            params.insert("pubkey".to_owned(), Value::String(group.id.clone()));
            params.insert("namespace".to_owned(), Value::from(11));
            params.insert("timestamp".to_owned(), Value::from(store_timestamp));
            params.insert("signature".to_owned(), Value::String(signature));
            params.insert(
                "ttl".to_owned(),
                Value::from(rpc::DEFAULT_MESSAGE_TTL_MS),
            );
            params.insert("data".to_owned(), Value::String(encoded));
            let response = self
                .network
                .send_rpc("store", Value::Object(params), Some(&group.id))
                .await
                .map_err(|error| error.to_string())?;
            if response.status_code != 200 {
                let detail = response
                    .body
                    .as_deref()
                    .unwrap_or("no_response_body");
                let detail: String = detail.chars().take(240).collect();
                debug_log(
                    "group.send.response",
                    &format!("http_status={} detail={detail:?}", response.status_code),
                );
                return Err(format!(
                    "Session group store returned HTTP {}",
                    response.status_code
                ));
            }
            debug_log(
                "group.send.response",
                &format!("http_status={}", response.status_code),
            );
            return Ok(());
        }
        let recipient_bytes = hex::decode(recipient_id).map_err(|e| e.to_string())?;
        let recipient_key: [u8; 33] = recipient_bytes
            .try_into()
            .map_err(|_| "Session ID must contain 33 bytes".to_string())?;
        if recipient_key[0] != 0x05 {
            return Err("Recipient is not a standard Session ID".into());
        }
        let encoded = STANDARD.encode(
            encode_for_1o1(
                &content.encode_to_vec(),
                &self.identity.ed_secret,
                timestamp_ms,
                &recipient_key,
                None,
            )
            .map_err(|_| "Could not encode Session 1:1 message".to_string())?,
        );
        let recipient = recipient_id.to_owned();
        let response = self
            .network
            .send_store(&StoreParams {
                pubkey: &recipient,
                pubkey_ed25519: None,
                namespace: 0,
                timestamp_ms,
                ttl_ms: rpc::DEFAULT_MESSAGE_TTL_MS,
                data_base64: &encoded,
                signing_key: None,
            })
            .await
            .map_err(|e| e.to_string())?;
        debug_log(
            "send.response",
            &format!("http_status={}", response.status_code),
        );
        if response.status_code != 200 {
            return Err(format!(
                "Session store returned HTTP {}",
                response.status_code
            ));
        }
        Ok(())
    }

    async fn retrieve_messages(
        &self,
        last_hash: Option<&str>,
        group_cursors: HashMap<String, String>,
    ) -> Result<RetrieveResult, String> {
        debug_log(
            "retrieve.begin",
            &format!("cursor_present={}", last_hash.is_some()),
        );
        let pubkey_ed25519 = hex::encode(self.identity.ed_public);
        let mut items: Vec<Value> = Vec::new();
        let mut cursor = last_hash.map(str::to_owned);
        for _ in 0..MAX_RETRIEVE_PAGES {
            let response = self
                .network
                .send_retrieve(&RetrieveParams {
                    pubkey: &self.identity.session_id,
                    pubkey_ed25519: &pubkey_ed25519,
                    namespace: 0,
                    timestamp_ms: now_ms(),
                    last_hash: cursor.as_deref(),
                    max_size: Some(1_000_000),
                    signing_key: &self.identity.ed_secret,
                })
                .await
                .map_err(|e| e.to_string())?;
            debug_log(
                "retrieve.response",
                &format!(
                    "http_status={} body_bytes={}",
                    response.status_code,
                    response.body.as_ref().map_or(0, String::len)
                ),
            );
            if response.status_code != 200 {
                return Err(format!(
                    "Session retrieve returned HTTP {}",
                    response.status_code
                ));
            }
            let body = response
                .body
                .ok_or_else(|| "Empty retrieve response".to_string())?;
            let mut value: Value = serde_json::from_str(&body)
                .map_err(|e| format!("Invalid retrieve response: {e}"))?;
            let more = value.get("more").and_then(Value::as_bool).unwrap_or(false);
            let page = match value.get_mut("messages").map(Value::take) {
                Some(Value::Array(page)) => page,
                _ => return Err("Retrieve response has no messages array".to_string()),
            };
            if let Some(hash) = page
                .last()
                .and_then(|item| item.get("hash"))
                .and_then(Value::as_str)
            {
                cursor = Some(hash.to_owned());
            }
            let empty = page.is_empty();
            items.extend(page);
            if !more || empty {
                break;
            }
        }
        let messages = &items;
        let last_hash = cursor.filter(|hash| Some(hash.as_str()) != last_hash);
        let mut incoming = Vec::new();
        let mut undecryptable = 0;
        let mut bad_envelope = 0;
        let mut bad_content = 0;
        let mut delivery_receipts: HashMap<String, Vec<u64>> = HashMap::new();
        for item in messages {
            let Some(data) = item.get("data").and_then(Value::as_str) else {
                continue;
            };
            let wire = match STANDARD.decode(data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let envelope_bytes = match WebSocketMessage::decode(wire.as_slice()) {
                Ok(ws) if ws.r#type == Some(web_socket_message::Type::Request as i32) => {
                    match ws.request.and_then(|request| request.body) {
                        Some(body) => body,
                        None => {
                            bad_envelope += 1;
                            debug_log("retrieve.decode", "websocket_request_missing_body=true");
                            continue;
                        }
                    }
                }
                _ => wire,
            };
            let envelope = match Envelope::decode(envelope_bytes.as_slice()) {
                Ok(v) => v,
                Err(error) => {
                    bad_envelope += 1;
                    debug_log(
                        "retrieve.decode",
                        &format!("envelope_protobuf_error={error}"),
                    );
                    continue;
                }
            };
            if envelope.r#type != envelope::Type::SessionMessage as i32 {
                continue;
            }
            let Some(ciphertext) = envelope.content.as_deref() else {
                continue;
            };
            let (plaintext, sender_id) = match session_encrypt::decrypt_incoming_session_id(
                &self.identity.ed_secret,
                ciphertext,
            ) {
                Ok(v) => v,
                Err(_) => {
                    undecryptable += 1;
                    continue;
                }
            };
            let content_bytes = strip_session_padding(&plaintext);
            let content = match Content::decode(content_bytes) {
                Ok(v) => v,
                Err(_) => {
                    bad_content += 1;
                    continue;
                }
            };
            let hash = item
                .get("hash")
                .and_then(Value::as_str)
                .unwrap_or(data)
                .to_owned();
            if let Some(unsend) = content.unsend_request {
                let mut message = IncomingMessage::control(
                    hash,
                    sender_id.clone(),
                    sender_id,
                    unsend.timestamp,
                );
                message.unsend = Some((unsend.timestamp, unsend.author));
                incoming.push(message);
                continue;
            }
            if let Some(receipt) = content.receipt_message {
                let mut message = IncomingMessage::control(
                    hash,
                    sender_id.clone(),
                    sender_id,
                    envelope.timestamp,
                );
                message.receipt = Some((receipt.r#type, receipt.timestamp));
                incoming.push(message);
                continue;
            }
            let Some(data_message) = content.data_message else {
                continue;
            };
            let sync_target = data_message.sync_target.clone();
            let outgoing_sync = sender_id == self.identity.session_id
                && sync_target
                    .as_deref()
                    .is_some_and(libsession::util::types::session_id_is_valid);
            let contact_id = if outgoing_sync {
                sync_target.clone().expect("validated sync target")
            } else {
                sender_id.clone()
            };
            let sender_name = if outgoing_sync {
                None
            } else {
                data_message
                    .profile
                    .and_then(|profile| profile.display_name)
                    .map(|name| name.trim().to_owned())
                    .filter(|name| !name.is_empty())
            };
            let timestamp_ms = data_message.timestamp.unwrap_or(envelope.timestamp);
            let attachments: Vec<AttachmentMeta> = data_message
                .attachments
                .iter()
                .map(attachment_meta_from_pointer)
                .collect();
            let text = data_message.body.unwrap_or_default();
            if text.is_empty() && attachments.is_empty() {
                continue;
            }
            debug_log(
                "message.route",
                &format!(
                    "sender_prefix={} contact_prefix={} self_sync_copy={outgoing_sync} attachments={}",
                    &sender_id[..sender_id.len().min(8)],
                    &contact_id[..contact_id.len().min(8)],
                    attachments.len(),
                ),
            );
            if !outgoing_sync && sender_id != self.identity.session_id {
                delivery_receipts
                    .entry(sender_id.clone())
                    .or_default()
                    .push(timestamp_ms);
            }
            incoming.push(IncomingMessage {
                hash,
                sender_id,
                contact_id,
                outgoing: outgoing_sync,
                sender_name,
                body: Some(text),
                timestamp_ms,
                unsend: None,
                receipt: None,
                attachments,
            });
        }
        let groups = match self.discover_groups().await {
            Ok(groups) => groups,
            Err(error) => {
                debug_log("group.sync.failed", &format!("error={error}"));
                Vec::new()
            }
        };
        let runtime_groups: Vec<GroupRuntime> = self
            .groups
            .lock()
            .map(|groups| groups.values().cloned().collect())
            .unwrap_or_default();
        let mut new_group_cursors = HashMap::new();
        for group in &runtime_groups {
            let cursor = group_cursors.get(&group.id).map(String::as_str);
            match self.retrieve_group_messages(group, cursor).await {
                Ok((mut group_messages, last)) => {
                    incoming.append(&mut group_messages);
                    if let Some(last) = last
                        && Some(last.as_str()) != cursor
                    {
                        new_group_cursors.insert(group.id.clone(), last);
                    }
                }
                Err(error) => debug_log(
                    "group.retrieve.failed",
                    &format!("group_prefix={} error={error}", &group.id[..8]),
                ),
            }
        }
        for (sender, timestamps) in delivery_receipts {
            if self.send_receipt(&sender, 0, timestamps).await.is_ok() {
                debug_log("receipt.delivery.sent", "batched=true");
            } else {
                debug_log("receipt.delivery.failed", "send_failed=true");
            }
        }
        incoming.sort_by_key(|m| m.timestamp_ms);
        debug_log(
            "retrieve.parsed",
            &format!(
                "queued={} accepted={} decrypt_failed={} bad_envelope={} bad_content={}",
                messages.len(),
                incoming.len(),
                undecryptable,
                bad_envelope,
                bad_content
            ),
        );
        Ok(RetrieveResult {
            messages: incoming,
            queued: messages.len(),
            undecryptable,
            bad_envelope,
            bad_content,
            last_hash,
            groups,
            group_cursors: new_group_cursors,
        })
    }
}

fn prompt_identity() -> Result<Identity, Box<dyn std::error::Error>> {
    let saved_seed_path = session_data_dir()?.join("identity.dpapi");
    if let Some(seed) = load_protected_seed(&saved_seed_path)? {
        return identity_from_seed(seed, None);
    }
    let entered = rpassword::prompt_password(
        "Session seed (64 hex) or 13-word recovery phrase (blank creates account): ",
    )?;
    let (seed, recovery_phrase) = if entered.trim().is_empty() {
        print!("No seed entered. Create a NEW Session account? [y/N] ");
        io::stdout().flush()?;
        let mut answer = String::new();
        io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            return Err("cancelled; restart and enter your seed or recovery phrase".into());
        }
        let mut seed = random::random(16);
        seed.resize(32, 0);
        println!("\nNew Session identity created.");
        let phrase = encode_session_mnemonic(&seed[..16])?;
        (seed, Some(phrase))
    } else if entered.trim().split_whitespace().count() == 13 {
        (decode_session_mnemonic(entered.trim())?, None)
    } else {
        (hex::decode(entered.trim())?, None)
    };
    if seed.len() != 32 {
        return Err("Session seed must be exactly 32 bytes (64 hex characters)".into());
    }
    save_protected_seed(&saved_seed_path, &seed)?;
    identity_from_seed(seed, recovery_phrase)
}

fn identity_from_seed(
    seed: Vec<u8>,
    recovery_phrase: Option<String>,
) -> Result<Identity, Box<dyn std::error::Error>> {
    if seed.len() != 32 {
        return Err("Session seed must be exactly 32 bytes (64 hex characters)".into());
    }
    let (ed_public, ed_secret) = ed25519::ed25519_key_pair_from_seed(&seed)?;
    let curve_public = curve25519::to_curve25519_pubkey(&ed_public)?;
    let session_id = format!("05{}", hex::encode(curve_public));
    Ok(Identity {
        session_id,
        ed_public,
        ed_secret,
        recovery_phrase,
    })
}

#[cfg(windows)]
fn save_protected_seed(
    path: &std::path::Path,
    seed: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData},
    };
    let input = CRYPT_INTEGER_BLOB {
        cbData: seed.len() as u32,
        pbData: seed.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            ptr::null(),
            ptr::null::<c_void>(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("Windows DPAPI could not protect the Session seed".into());
    }
    let protected = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let result = std::fs::write(path, protected);
    unsafe {
        LocalFree(output.pbData.cast());
    }
    result?;
    Ok(())
}

#[cfg(windows)]
fn load_protected_seed(
    path: &std::path::Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    use std::{ffi::c_void, ptr};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
        },
    };
    if !path.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            ptr::null(),
            ptr::null::<c_void>(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        return Err("Windows could not unlock the saved Session seed for this user".into());
    }
    let seed =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe {
        LocalFree(output.pbData.cast());
    }
    if seed.len() != 32 {
        return Err("The saved Session seed file is invalid".into());
    }
    Ok(Some(seed))
}

#[cfg(not(windows))]
fn save_protected_seed(
    _path: &std::path::Path,
    _seed: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

#[cfg(not(windows))]
fn load_protected_seed(
    _path: &std::path::Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    Ok(None)
}

fn session_word_list() -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(serde_json::from_str(include_str!(
        "../../mnemonic_languages/english.json"
    ))?)
}

fn decode_session_mnemonic(phrase: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let words = session_word_list()?;
    let normalized = phrase.to_ascii_lowercase();
    let tokens: Vec<&str> = normalized.split_whitespace().collect();
    if tokens.len() != 13 {
        return Err("Session recovery phrase must contain 13 words".into());
    }
    if tokens.iter().any(|word| !word.is_ascii() || word.len() < 3) {
        return Err("Each Session recovery word must contain at least 3 English letters".into());
    }
    let indices: Vec<usize> = tokens[..12]
        .iter()
        .map(|token| {
            words
                .iter()
                .position(|word| word.starts_with(&token[..3]))
                .ok_or_else(|| format!("Unknown recovery word: {token}"))
        })
        .collect::<Result<_, _>>()?;
    let checksum_index = crc32_prefix_checksum(&tokens[..12]) % 12;
    if !words[indices[checksum_index]].starts_with(&tokens[12][..3]) {
        return Err("Recovery phrase checksum does not match; check the word order".into());
    }

    let n = words.len() as u64;
    let mut seed = Vec::with_capacity(32);
    for chunk in indices.chunks_exact(3) {
        let w1 = chunk[0] as u64;
        let w2 = chunk[1] as u64;
        let w3 = chunk[2] as u64;
        let value = w1 + n * ((n - w1 + w2) % n) + n * n * ((n - w2 + w3) % n);
        if value >= (1 << 32) || value % n != w1 {
            return Err("Invalid recovery phrase encoding".into());
        }
        seed.extend_from_slice(&(value as u32).to_le_bytes());
    }
    seed.resize(32, 0);
    Ok(seed)
}

fn encode_session_mnemonic(seed: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if seed.len() != 16 {
        return Err("Session recovery phrases encode exactly 16 bytes".into());
    }
    let words = session_word_list()?;
    let n = words.len() as u64;
    let mut indices = Vec::with_capacity(12);
    for chunk in seed.chunks_exact(4) {
        let value = u32::from_le_bytes(chunk.try_into()?) as u64;
        let w1 = value % n;
        let w2 = (value / n + w1) % n;
        let w3 = (value / n / n + w2) % n;
        indices.extend([w1 as usize, w2 as usize, w3 as usize]);
    }
    let checksum_index = crc32_prefix_checksum(
        &indices
            .iter()
            .map(|&i| words[i].as_str())
            .collect::<Vec<_>>(),
    ) % 12;
    let checksum_word = indices[checksum_index];
    indices.push(checksum_word);
    Ok(indices
        .into_iter()
        .map(|i| words[i].as_str())
        .collect::<Vec<_>>()
        .join(" "))
}

fn crc32_prefix_checksum(words: &[&str]) -> usize {
    let bytes: Vec<u8> = words
        .iter()
        .flat_map(|word| word.as_bytes().iter().take(3).copied())
        .collect();
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    (!crc) as usize
}

/// Local UTC offset, captured before any thread starts: the `time` crate
/// refuses to read it from a multi-threaded process on Unix.
static LOCAL_OFFSET: OnceLock<time::UtcOffset> = OnceLock::new();

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(
        io::stdout(),
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = LOCAL_OFFSET.set(
        time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
    );
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let debug = std::env::args().skip(1).any(|arg| arg == "--debug");
    init_debug_log(debug)?;
    let identity = prompt_identity()?;
    debug_log(
        "identity",
        &format!(
            "local_id_prefix={}",
            &identity.session_id[..identity.session_id.len().min(8)]
        ),
    );
    let client = Arc::new(SessionClient::new(identity)?);
    let store = LocalStore::open(&client.identity)?;
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        default_hook(info);
    }));
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(client.identity.session_id.clone());
    app.recovery_seed = client.identity.recovery_phrase.clone();
    if let Err(error) = store.load(&mut app) {
        app.status = format!("LOCAL HISTORY ERROR · {error}");
    }
    let result = run(&mut terminal, &mut app, &client, &store).await;
    restore_terminal();
    result?;
    Ok(())
}

type SyncTask = tokio::task::JoinHandle<Result<RetrieveResult, String>>;
type DownloadTask = tokio::task::JoinHandle<Result<DownloadedAttachment, (PendingDownload, String)>>;

/// Run a !Send network future on its own current-thread runtime.
fn spawn_network<T, F, Fut>(f: F) -> tokio::task::JoinHandle<Result<T, String>>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>>,
{
    tokio::task::spawn_blocking(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "could not start network runtime".to_string())?;
        runtime.block_on(f())
    })
}

/// Split command arguments on whitespace, honouring double quotes.
fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    let mut has_token = false;
    for c in input.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has_token = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

/// `path`, or `name (1).ext`, `name (2).ext`… if it already exists.
fn unique_path(path: std::path::PathBuf) -> std::path::PathBuf {
    if !path.exists() {
        return path;
    }
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("attachment")
        .to_owned();
    let extension = path.extension().and_then(|s| s.to_str()).map(str::to_owned);
    let parent = path.parent().map(std::path::Path::to_path_buf).unwrap_or_default();
    for n in 1.. {
        let name = match &extension {
            Some(extension) => format!("{stem} ({n}).{extension}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = parent.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

fn attachment_file_name(meta: &AttachmentMeta) -> String {
    let mut name = std::path::Path::new(&meta.file_name)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty() && *name != "." && *name != "..")
        .unwrap_or("attachment")
        .to_owned();
    if std::path::Path::new(&name).extension().is_none()
        && let Some(extension) = default_attachment_extension(&meta.content_type)
    {
        name.push('.');
        name.push_str(extension);
    }
    name
}

/// Queue every attachment that is not in the local cache yet.
fn enqueue_missing_downloads(
    app: &App,
    queue: &mut std::collections::VecDeque<PendingDownload>,
) {
    let Ok(root) = session_data_dir() else {
        return;
    };
    for conversation in &app.conversations {
        for message in &conversation.messages {
            for (index, meta) in message.attachments.iter().enumerate() {
                if meta.url.is_empty() {
                    continue;
                }
                let path = session_tui_media::attachment_blob_path(
                    &root,
                    &conversation.id,
                    message.timestamp_ms,
                    index,
                );
                if !path.exists() {
                    queue.push_back(PendingDownload {
                        peer: conversation.id.clone(),
                        timestamp_ms: message.timestamp_ms,
                        outgoing: message.outgoing,
                        index,
                        meta: meta.clone(),
                    });
                }
            }
        }
    }
}

fn start_download(client: &Arc<SessionClient>, job: PendingDownload) -> DownloadTask {
    let client = Arc::clone(client);
    tokio::task::spawn_blocking(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return Err((job, "could not start download runtime".into())),
        };
        let pointer = attachment_pointer_from_meta(&job.meta);
        match runtime.block_on(tokio::time::timeout(
            Duration::from_secs(120),
            client.download_attachment(&pointer),
        )) {
            Ok(Ok((_, encrypted, preview))) => Ok(DownloadedAttachment {
                job,
                encrypted,
                preview,
            }),
            Ok(Err(error)) => Err((job, error)),
            Err(_) => Err((job, "download timed out".into())),
        }
    })
}

fn finish_download(
    app: &mut App,
    store: &LocalStore,
    result: Result<DownloadedAttachment, (PendingDownload, String)>,
) {
    let downloaded = match result {
        Ok(downloaded) => downloaded,
        Err((job, error)) => {
            debug_log(
                "attachment.download.failed",
                &format!("index={} error={error}", job.index),
            );
            return;
        }
    };
    let job = &downloaded.job;
    if let Err(error) =
        store.save_attachment_blob(&job.peer, job.timestamp_ms, job.index, &downloaded.encrypted)
    {
        debug_log("attachment.cache.failed", &format!("error={error}"));
        return;
    }
    let Some(conversation) = app.conversations.iter_mut().find(|c| c.id == job.peer) else {
        return;
    };
    let Some(message) = conversation
        .messages
        .iter_mut()
        .find(|m| m.timestamp_ms == job.timestamp_ms && m.outgoing == job.outgoing)
    else {
        return;
    };
    if message.image_previews.len() < message.attachments.len() {
        message.image_previews.resize(message.attachments.len(), None);
    }
    if let Some(slot) = message.image_previews.get_mut(job.index)
        && downloaded.preview.is_some()
    {
        *slot = downloaded.preview;
        let _ = store.update_message(&job.peer, message);
    }
}

async fn run(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    client: &Arc<SessionClient>,
    store: &LocalStore,
) -> io::Result<()> {
    let mut last_sync = Instant::now() - Duration::from_secs(30);
    let mut sync_task: Option<SyncTask> = None;
    let mut read_receipt_task: Option<tokio::task::JoinHandle<Result<(), String>>> = None;
    let mut attachment_task: Option<(
        tokio::task::JoinHandle<Result<SentAttachments, String>>,
        String,
        u64,
    )> = None;
    let mut download_task: Option<DownloadTask> = None;
    let mut download_queue = std::collections::VecDeque::new();
    enqueue_missing_downloads(app, &mut download_queue);
    let mut pending_read_receipts: std::collections::VecDeque<(String, Vec<u64>)> =
        std::collections::VecDeque::new();
    loop {
        if read_receipt_task
            .as_ref()
            .is_some_and(|task| task.is_finished())
            && let Some(task) = read_receipt_task.take()
        {
            match task.await {
                Ok(Ok(())) => debug_log("receipt.read.sent", "sent=true"),
                _ => debug_log("receipt.read.failed", "send_failed=true"),
            }
        }
        if download_task.as_ref().is_some_and(|task| task.is_finished())
            && let Some(task) = download_task.take()
        {
            match task.await {
                Ok(result) => finish_download(app, store, result),
                Err(error) => debug_log("attachment.download.panic", &error.to_string()),
            }
        }
        if download_task.is_none()
            && let Some(job) = download_queue.pop_front()
        {
            download_task = Some(start_download(client, job));
        }
        if attachment_task
            .as_ref()
            .is_some_and(|(task, _, _)| task.is_finished())
            && let Some((task, peer, pending_timestamp)) = attachment_task.take()
        {
            let result = match task.await {
                Ok(result) => result,
                Err(error) => Err(format!("upload task failed: {error}")),
            };
            if let Some(index) = app.conversations.iter().position(|c| c.id == peer) {
                let convo = &mut app.conversations[index];
                let pending = convo
                    .messages
                    .iter()
                    .position(|m| m.timestamp_ms == pending_timestamp && m.outgoing);
                match result {
                    Ok(sent) => {
                        if let Some(pending_index) = pending {
                            convo.messages.remove(pending_index);
                        }
                        let mut message = Message::new(sent.caption, sent.timestamp_ms, true);
                        for (index, (meta, encrypted, preview)) in
                            sent.files.into_iter().enumerate()
                        {
                            let _ = store.save_attachment_blob(
                                &peer,
                                sent.timestamp_ms,
                                index,
                                &encrypted,
                            );
                            message.attachments.push(meta);
                            message.image_previews.push(preview);
                        }
                        let _ = store.save_message(&peer, &message);
                        convo.messages.push(message);
                        convo.selected_message = convo.messages.len() - 1;
                        convo.refresh_preview();
                        app.status = if sent.sync_copy_sent {
                            "ATTACHMENT SENT · SYNCED TO YOUR OTHER DEVICES".into()
                        } else {
                            "ATTACHMENT SENT · DEVICE SYNC COPY FAILED".into()
                        };
                        app.sort_conversations();
                    }
                    Err(error) => {
                        debug_log("attachment.task.failed", &format!("error={error}"));
                        if let Some(pending_index) = pending {
                            convo.messages[pending_index].body = format!("Upload failed · {error}");
                            convo.refresh_preview();
                        }
                        app.status = format!("ATTACHMENT FAILED · {error}");
                    }
                }
            }
        }
        if app.recovery_seed.is_none()
            && !app.show_help
            && let Some(receipt) = mark_current_conversation_read(app, store)
            && !receipt.0.starts_with("03")
        {
            pending_read_receipts.push_back(receipt);
        }
        if read_receipt_task.is_none()
            && let Some((peer, timestamps)) = pending_read_receipts.pop_front()
        {
            read_receipt_task = Some(start_read_receipt(Arc::clone(client), peer, timestamps));
        }
        if sync_task.as_ref().is_some_and(|task| task.is_finished())
            && let Some(task) = sync_task.take()
        {
            let result = match task.await {
                Ok(result) => result,
                Err(_) => Err("sync task failed".into()),
            };
            finish_sync(
                app,
                store,
                &client.identity.session_id,
                result,
                &mut download_queue,
            );
        }
        let waiting_for_receipt = app.conversations.iter().flat_map(|c| &c.messages).any(|m| {
            m.outgoing
                && m.receipt_status < 2
                && now_ms().saturating_sub(m.timestamp_ms) < 5 * 60 * 1000
        });
        let sync_interval = if waiting_for_receipt {
            Duration::from_secs(5)
        } else {
            Duration::from_secs(30)
        };
        if app.recovery_seed.is_none()
            && sync_task.is_none()
            && last_sync.elapsed() >= sync_interval
        {
            last_sync = Instant::now();
            start_sync(app, client, store, &mut sync_task);
        }
        terminal.draw(|frame| draw(frame, app))?;
        if !event::poll(Duration::from_millis(150))? {
            continue;
        }
        let key = match event::read()? {
            Event::Mouse(mouse) => {
                handle_mouse(app, mouse);
                continue;
            }
            Event::Paste(text) if app.image_viewer.is_none() && app.recovery_seed.is_none() => {
                // The composer is single-line: fold pasted line breaks.
                let text = text.replace("\r\n", "\n").replace(['\r', '\n'], " ");
                app.input.push_str(&text);
                app.focus = FocusArea::Composer;
                continue;
            }
            Event::Key(key) => key,
            _ => continue,
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if app.image_viewer.is_some() {
            if key.code == KeyCode::Esc {
                app.image_viewer = None;
            }
            continue;
        }
        if app.recovery_seed.is_some() {
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.recovery_seed = None;
            }
            continue;
        }
        match key.code {
            KeyCode::Tab => {
                app.focus = match app.focus {
                    FocusArea::Contacts => FocusArea::Messages,
                    FocusArea::Messages => FocusArea::Composer,
                    FocusArea::Composer => FocusArea::Contacts,
                };
            }
            KeyCode::BackTab => {
                app.focus = match app.focus {
                    FocusArea::Contacts => FocusArea::Composer,
                    FocusArea::Messages => FocusArea::Contacts,
                    FocusArea::Composer => FocusArea::Messages,
                };
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(());
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.input.clear();
            }
            KeyCode::Esc if app.show_help => app.show_help = false,
            KeyCode::Esc if app.input_mode == InputMode::ContactId => {
                app.input.clear();
                app.input_mode = InputMode::Message;
                app.status = "ADD CONTACT CANCELLED".into();
            }
            KeyCode::Char('n')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    && app.input.is_empty()
                    && app.input_mode == InputMode::Message =>
            {
                app.input_mode = InputMode::ContactId;
                app.focus = FocusArea::Composer;
                app.status = "ENTER CONTACT SESSION ID (05…)".into();
            }
            KeyCode::Left if app.input.is_empty() && !app.conversations.is_empty() => {
                app.selected = app.selected.saturating_sub(1);
            }
            KeyCode::Right if app.input.is_empty() && !app.conversations.is_empty() => {
                app.selected = (app.selected + 1).min(app.conversations.len() - 1);
            }
            KeyCode::Up if app.input.is_empty() && app.focus == FocusArea::Contacts => {
                app.selected = app.selected.saturating_sub(1);
            }
            KeyCode::Down if app.input.is_empty() && app.focus == FocusArea::Contacts => {
                if !app.conversations.is_empty() {
                    app.selected = (app.selected + 1).min(app.conversations.len() - 1);
                }
            }
            KeyCode::Up if app.input.is_empty() && app.focus == FocusArea::Messages => {
                if let Some(conversation) = app.conversations.get_mut(app.selected) {
                    conversation.selected_message = conversation.selected_message.saturating_sub(1);
                }
            }
            KeyCode::Down if app.input.is_empty() && app.focus == FocusArea::Messages => {
                if let Some(conversation) = app.conversations.get_mut(app.selected)
                    && !conversation.messages.is_empty()
                {
                    conversation.selected_message =
                        (conversation.selected_message + 1).min(conversation.messages.len() - 1);
                }
            }
            KeyCode::Delete if app.input.is_empty() => {
                let Some((timestamp, outgoing)) = app
                    .selected_message()
                    .map(|message| (message.timestamp_ms, message.outgoing))
                else {
                    app.status = "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
                    continue;
                };
                let peer = app.conversations[app.selected].id.clone();
                if outgoing {
                    app.status = "SENDING UNSEND REQUEST…".into();
                    terminal.draw(|frame| draw(frame, app))?;
                    if let Err(error) = client.unsend_message(&peer, timestamp).await {
                        app.status = format!("UNSEND FAILED · {error}");
                        continue;
                    }
                }
                if let Some(removed) = app.remove_selected_message()
                    && let Err(error) = store.delete_message(&peer, &removed)
                {
                    app.status = format!("LOCAL DELETE ERROR · {error}");
                    continue;
                }
                app.status = if outgoing {
                    "MESSAGE UNSENT".into()
                } else {
                    "MESSAGE DELETED LOCALLY".into()
                };
            }
            KeyCode::Enter
                if app.input_mode == InputMode::ContactId && !app.input.starts_with('/') =>
            {
                app.submit_contact_id();
                if let Some(contact) = app.conversations.get(app.selected)
                    && let Err(error) = store.save_contact(&contact.id)
                {
                    app.status = format!("LOCAL CONTACT ERROR · {error}");
                }
            }
            KeyCode::Enter => {
                let input = app.input.clone();
                let (command, rest) = input
                    .split_once(char::is_whitespace)
                    .map_or((input.as_str(), ""), |(c, r)| (c, r.trim()));
                match command {
                    "/attach" => {
                        app.input.clear();
                        let (paths, caption) = match rest.split_once(" -- ") {
                            Some((paths, caption)) => (split_args(paths), caption.trim().to_owned()),
                            None => (split_args(rest), String::new()),
                        };
                        if paths.is_empty() {
                            app.status = "USAGE · /attach PATH [PATH…] [-- CAPTION]".into();
                            continue;
                        }
                        if paths.len() > MAX_ATTACHMENTS {
                            app.status =
                                format!("TOO MANY FILES · SESSION ALLOWS {MAX_ATTACHMENTS} PER MESSAGE");
                            continue;
                        }
                        let Some(recipient) = app.conversations.get(app.selected).map(|c| c.id.clone())
                        else {
                            app.status = "ADD A CONTACT FIRST WITH CTRL+N".into();
                            continue;
                        };
                        if attachment_task.is_some() {
                            app.status = "AN ATTACHMENT IS ALREADY UPLOADING".into();
                            app.input = input;
                            continue;
                        }
                        if let Some(missing) =
                            paths.iter().find(|p| !std::path::Path::new(p).is_file())
                        {
                            app.status = format!("FILE NOT FOUND · {missing}");
                            app.input = input;
                            continue;
                        }
                        let label = if paths.len() == 1 {
                            std::path::Path::new(&paths[0])
                                .file_name()
                                .and_then(|n| n.to_str())
                                .unwrap_or("attachment")
                                .to_owned()
                        } else {
                            format!("{} files", paths.len())
                        };
                        let pending_timestamp = now_ms();
                        if let Some(conversation) = app.conversations.get_mut(app.selected) {
                            conversation.messages.push(Message::new(
                                format!("Uploading · {label}"),
                                pending_timestamp,
                                true,
                            ));
                            conversation.selected_message = conversation.messages.len() - 1;
                            conversation.refresh_preview();
                        }
                        app.status = format!("UPLOADING ATTACHMENT · {label}");
                        let task_client = Arc::clone(client);
                        let task_peer = recipient.clone();
                        let profile_name = app.profile_name.clone();
                        let paths: Vec<std::path::PathBuf> =
                            paths.into_iter().map(std::path::PathBuf::from).collect();
                        attachment_task = Some((
                            spawn_network(move || async move {
                                task_client
                                    .send_attachments(&task_peer, &paths, &caption, &profile_name)
                                    .await
                            }),
                            recipient,
                            pending_timestamp,
                        ));
                    }
                    "/save" => {
                        app.input.clear();
                        let mut args = split_args(rest);
                        let index = args
                            .first()
                            .and_then(|a| a.parse::<usize>().ok())
                            .filter(|n| *n >= 1);
                        if index.is_some() {
                            args.remove(0);
                        }
                        let target = args.join(" ");
                        let Some((peer, timestamp, attachments)) =
                            app.conversations.get(app.selected).and_then(|c| {
                                let m = c.messages.get(c.selected_message)?;
                                Some((c.id.clone(), m.timestamp_ms, m.attachments.clone()))
                            })
                        else {
                            app.status = "SELECT AN ATTACHMENT WITH ↑/↓ FIRST".into();
                            continue;
                        };
                        if attachments.is_empty() {
                            app.status = "SELECTED MESSAGE HAS NO ATTACHMENT".into();
                            continue;
                        }
                        let selected: Vec<usize> = match index {
                            Some(n) if n <= attachments.len() => vec![n - 1],
                            Some(_) => {
                                app.status = format!(
                                    "MESSAGE HAS {} ATTACHMENT(S) · USE /save 1-{}",
                                    attachments.len(),
                                    attachments.len()
                                );
                                continue;
                            }
                            None => (0..attachments.len()).collect(),
                        };
                        let cwd = std::env::current_dir().unwrap_or_default();
                        let target_path = (!target.is_empty()).then(|| std::path::PathBuf::from(&target));
                        let into_dir = selected.len() > 1
                            || target_path.as_ref().is_none_or(|p| p.is_dir());
                        if selected.len() > 1
                            && let Some(dir) = target_path.as_ref()
                            && !dir.is_dir()
                        {
                            app.status = format!("NOT A FOLDER · {}", dir.display());
                            continue;
                        }
                        app.status = "SAVING ATTACHMENT…".into();
                        terminal.draw(|frame| draw(frame, app))?;
                        let mut saved = Vec::new();
                        let mut failure = None;
                        for index in selected {
                            let metadata = &attachments[index];
                            let destination = if into_dir {
                                unique_path(
                                    target_path
                                        .clone()
                                        .unwrap_or_else(|| cwd.clone())
                                        .join(attachment_file_name(metadata)),
                                )
                            } else {
                                target_path.clone().expect("single file target")
                            };
                            let result = async {
                                let cache_path = session_tui_media::attachment_blob_path(
                                    &session_data_dir()?,
                                    &peer,
                                    timestamp,
                                    index,
                                );
                                let encrypted = match std::fs::read(&cache_path) {
                                    Ok(bytes) => bytes,
                                    Err(_) => {
                                        let pointer = attachment_pointer_from_meta(metadata);
                                        let (_, bytes, _) =
                                            client.download_attachment(&pointer).await?;
                                        store.save_attachment_blob(&peer, timestamp, index, &bytes)?;
                                        bytes
                                    }
                                };
                                let plaintext = session_tui_media::decrypt_attachment(
                                    &encrypted,
                                    &metadata.key,
                                    &metadata.digest,
                                    metadata.deterministic,
                                )?;
                                std::fs::write(&destination, plaintext).map_err(|e| e.to_string())?;
                                Ok::<(), String>(())
                            }
                            .await;
                            match result {
                                Ok(()) => saved.push(destination),
                                Err(error) => {
                                    failure = Some(format!("{} · {error}", metadata.file_name));
                                    break;
                                }
                            }
                        }
                        app.status = match (failure, saved.as_slice()) {
                            (Some(error), _) => format!("SAVE FAILED · {error}"),
                            (None, [one]) => format!("SAVED FILE · {}", one.display()),
                            (None, many) => format!(
                                "SAVED {} FILES · {}",
                                many.len(),
                                target_path.unwrap_or(cwd).display()
                            ),
                        };
                    }
                    "/name" if rest.is_empty() => {
                        app.input.clear();
                        app.status = if app.profile_name.is_empty() {
                            "PROFILE NAME NOT SET · USE /name YOUR NAME".into()
                        } else {
                            format!("PROFILE NAME · {}", app.profile_name)
                        };
                    }
                    "/name" => {
                        app.input.clear();
                        if rest.len() > 100 {
                            app.status = "NAME TOO LONG · MAXIMUM 100 UTF-8 BYTES".into();
                        } else {
                            app.profile_name = rest.to_owned();
                            app.status = match store.save_profile_name(&app.profile_name) {
                                Ok(()) => {
                                    "PROFILE NAME SAVED · IT WILL SYNC WITH YOUR NEXT MESSAGE".into()
                                }
                                Err(error) => format!("PROFILE SAVE FAILED · {error}"),
                            };
                        }
                    }
                    "/exit" if rest.is_empty() => return Ok(()),
                    "/rsync" if rest.is_empty() => {
                        app.input.clear();
                        last_sync = Instant::now();
                        start_sync(app, client, store, &mut sync_task);
                    }
                    "/view" => {
                        app.input.clear();
                        let index = match rest {
                            "" => None,
                            n => match n.parse::<usize>() {
                                Ok(n) if n >= 1 => Some(n - 1),
                                _ => {
                                    app.status = "USAGE · /view [N]".into();
                                    continue;
                                }
                            },
                        };
                        app.status = match open_selected_image(app, index) {
                            Ok(()) => "IMAGE PREVIEW · PRESS ESC TO CLOSE".into(),
                            Err(error) => format!("IMAGE PREVIEW FAILED · {error}"),
                        };
                    }
                    "/?" if rest.is_empty() => {
                        app.input.clear();
                        app.show_help = true;
                    }
                    _ if app.input_mode == InputMode::ContactId => {
                        app.status = "UNKNOWN COMMAND · ESC TO CANCEL ADDING A CONTACT".into();
                    }
                    _ => {
                        let body = app.input.trim().to_owned();
                        if body.is_empty() {
                            app.focus = FocusArea::Composer;
                            continue;
                        }
                        let Some(recipient) = app.conversations.get(app.selected).map(|c| c.id.clone())
                        else {
                            app.status = "ADD A CONTACT FIRST WITH CTRL+N".into();
                            continue;
                        };
                        app.status = "SENDING THROUGH SESSION ONION ROUTING…".into();
                        terminal.draw(|frame| draw(frame, app))?;
                        match client
                            .send_message(&recipient, &body, &app.profile_name)
                            .await
                        {
                            Ok((timestamp_ms, sync_copy_sent)) => {
                                app.input.clear();
                                let message = Message::new(body, timestamp_ms, true);
                                let save = store.save_message(&recipient, &message);
                                if let Some(convo) = app.conversations.get_mut(app.selected) {
                                    convo.messages.push(message);
                                    convo.selected_message = convo.messages.len() - 1;
                                    convo.refresh_preview();
                                }
                                app.sort_conversations();
                                app.status = match save {
                                    Err(error) => format!("SENT · LOCAL SAVE ERROR · {error}"),
                                    Ok(()) if sync_copy_sent => {
                                        "SENT · SYNCED TO YOUR OTHER DEVICES".into()
                                    }
                                    Ok(()) => "SENT · OTHER DEVICE SYNC COPY FAILED".into(),
                                };
                            }
                            Err(error) => app.status = format!("SEND FAILED · {error}"),
                        }
                    }
                }
            }
            KeyCode::Backspace => {
                app.input.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.focus = FocusArea::Composer;
                app.input.push(c)
            }
            _ => {}
        }
    }
}

fn start_sync(
    app: &mut App,
    client: &Arc<SessionClient>,
    store: &LocalStore,
    task: &mut Option<SyncTask>,
) {
    if task.is_some() {
        app.status = "SYNC ALREADY RUNNING".into();
        return;
    }
    let (cursor, group_cursors) = match (store.get_last_hash(), store.get_group_cursors()) {
        (Ok(hash), Ok(groups)) => (hash, groups),
        (Err(error), _) | (_, Err(error)) => {
            app.status = format!("SYNC CURSOR ERROR · {error}");
            return;
        }
    };
    app.status = "SYNCING IN BACKGROUND · TYPE /? FOR HELP".into();
    debug_log(
        "sync.spawn",
        &format!("cursor_present={}", cursor.is_some()),
    );
    let client = Arc::clone(client);
    // Network bootstrap keeps ThreadRng across an await, making the future
    // !Send, so it runs on a dedicated current-thread runtime.
    *task = Some(spawn_network(move || async move {
        match tokio::time::timeout(
            Duration::from_secs(90),
            client.retrieve_messages(cursor.as_deref(), group_cursors),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => {
                debug_log("sync.timeout", "deadline_seconds=90");
                Err("sync timed out after 90 seconds".into())
            }
        }
    }));
}

fn mark_current_conversation_read(app: &mut App, store: &LocalStore) -> Option<(String, Vec<u64>)> {
    let conversation = app.conversations.get_mut(app.selected)?;
    let peer = conversation.id.clone();
    let mut timestamps = Vec::new();
    for message in &mut conversation.messages {
        if !message.outgoing && !message.is_read {
            message.is_read = true;
            timestamps.push(message.timestamp_ms);
            if let Err(error) = store.mark_message_read(&peer, message.timestamp_ms) {
                app.status = format!("READ STATE SAVE FAILED · {error}");
            }
        }
    }
    (!timestamps.is_empty()).then_some((peer, timestamps))
}

fn start_read_receipt(
    client: Arc<SessionClient>,
    peer: String,
    timestamps: Vec<u64>,
) -> tokio::task::JoinHandle<Result<(), String>> {
    spawn_network(move || async move { client.send_receipt(&peer, 1, timestamps).await })
}

/// Apply an UnsendRequest the way Session does: only the author may unsend,
/// and only that author's message with the given timestamp is removed.
fn apply_unsend(
    app: &mut App,
    store: &LocalStore,
    local_id: &str,
    sender_id: &str,
    contact_id: &str,
    timestamp: u64,
    author: &str,
) -> bool {
    if author != sender_id {
        debug_log("unsend.rejected", "reason=author_mismatch");
        return false;
    }
    let author_is_me = author == local_id;
    let mut removed_any = false;
    for conversation in &mut app.conversations {
        // Our own unsend arriving from a linked device names no chat, so
        // search every chat; otherwise only the chat it arrived in.
        if !(conversation.id == contact_id || (author_is_me && contact_id == local_id)) {
            continue;
        }
        let peer = conversation.id.clone();
        let mut index = 0;
        while index < conversation.messages.len() {
            let message = &conversation.messages[index];
            let matches = message.timestamp_ms == timestamp
                && if author_is_me {
                    message.outgoing
                } else {
                    !message.outgoing
                        && message.sender.as_deref().is_none_or(|sender| sender == author)
                };
            if matches {
                let removed = conversation.messages.remove(index);
                let _ = store.delete_message(&peer, &removed);
                removed_any = true;
            } else {
                index += 1;
            }
        }
        conversation.clamp_selection();
        conversation.refresh_preview();
    }
    removed_any
}

fn finish_sync(
    app: &mut App,
    store: &LocalStore,
    local_id: &str,
    result: Result<RetrieveResult, String>,
    download_queue: &mut std::collections::VecDeque<PendingDownload>,
) {
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            debug_log("sync.failed", "request_failed=true");
            app.status = format!("SYNC FAILED · {error}");
            return;
        }
    };
    let groups_found = result.groups.len();
    for group in result.groups.iter() {
        let index = app.ensure_contact(&group.id);
        app.conversations[index].name = group.name.clone();
        let _ = store.save_contact_name(&group.id, &group.name);
    }
    debug_log(
        "sync.complete",
        &format!(
            "queued={} groups={} decrypt_failed={} bad_envelope={} bad_content={}",
            result.queued,
            groups_found,
            result.undecryptable,
            result.bad_envelope,
            result.bad_content
        ),
    );
    if let Some(last_hash) = result.last_hash.as_deref()
        && let Err(error) = store.set_last_hash(last_hash)
    {
        app.status = format!("SYNC CURSOR SAVE ERROR · {error}");
        return;
    }
    for (group, hash) in &result.group_cursors {
        let _ = store.set_group_cursor(group, hash);
    }
    let mut added = 0;
    for message in result.messages {
        let is_new = store.mark_seen(&message.hash).unwrap_or(false);
        if !is_new || !app.seen_hashes.insert(message.hash) {
            continue;
        }
        if let Some((receipt_type, timestamps)) = message.receipt {
            let status = match receipt_type {
                0 => 1,
                1 => 2,
                _ => {
                    debug_log("receipt.incoming", "kind=unknown ignored=true");
                    continue;
                }
            };
            let mut matched = 0usize;
            if let Some(index) = app
                .conversations
                .iter()
                .position(|c| c.id == message.sender_id)
            {
                for timestamp in &timestamps {
                    if let Some(outgoing) = app.conversations[index]
                        .messages
                        .iter_mut()
                        .find(|m| m.outgoing && m.timestamp_ms == *timestamp)
                    {
                        outgoing.receipt_status = outgoing.receipt_status.max(status);
                        let _ = store.update_receipt_status(&message.sender_id, *timestamp, status);
                        matched += 1;
                    }
                }
            }
            debug_log(
                "receipt.incoming",
                &format!(
                    "peer_prefix={} kind={} timestamps={} matched={matched}",
                    &message.sender_id[..message.sender_id.len().min(8)],
                    if status == 2 { "read" } else { "delivery" },
                    timestamps.len(),
                ),
            );
            continue;
        }
        if let Some((timestamp, author)) = message.unsend {
            if apply_unsend(
                app,
                store,
                local_id,
                &message.sender_id,
                &message.contact_id,
                timestamp,
                &author,
            ) {
                added += 1;
            }
            continue;
        }
        let is_group = message.contact_id.starts_with("03");
        if let Some(name) = message.sender_name.as_deref()
            && !message.outgoing
        {
            if app.display_names.get(&message.sender_id).map(String::as_str) != Some(name) {
                app.display_names
                    .insert(message.sender_id.clone(), name.to_owned());
                let _ = store.save_display_name(&message.sender_id, name);
            }
            // A group's title comes from its config, never from a member.
            if !is_group
                && let Some(conversation) =
                    app.conversations.iter_mut().find(|c| c.id == message.contact_id)
                && conversation.name != name
            {
                conversation.name = name.to_owned();
                let _ = store.save_contact_name(&message.contact_id, name);
            }
        }
        let body = message.body.unwrap_or_default();
        if body.is_empty() && message.attachments.is_empty() {
            continue;
        }
        if message.outgoing
            && let Some(self_convo) = app.conversations.iter_mut().find(|c| c.id == local_id)
            && let Some(old_index) = self_convo.messages.iter().position(|m| {
                !m.outgoing && m.timestamp_ms == message.timestamp_ms && m.body == body
            })
        {
            // An older build filed this sync copy under "Note to Self".
            let removed = self_convo.messages.remove(old_index);
            self_convo.clamp_selection();
            self_convo.refresh_preview();
            let _ = store.delete_message(local_id, &removed);
        }
        let index = app.ensure_contact(&message.contact_id);
        let convo = &mut app.conversations[index];
        let sender = (is_group && !message.outgoing).then(|| message.sender_id.clone());
        if convo.messages.iter().any(|m| {
            m.timestamp_ms == message.timestamp_ms
                && m.outgoing == message.outgoing
                && (m.sender.is_none() || m.sender == sender)
        }) {
            continue;
        }
        let mut local_message = Message::new(body, message.timestamp_ms, message.outgoing);
        // Incoming messages stay unread until the chat is on screen; the
        // main loop then marks them read and sends the read receipt.
        local_message.is_read = message.outgoing;
        local_message.sender = sender;
        local_message.image_previews = vec![None; message.attachments.len()];
        for (attachment_index, meta) in message.attachments.iter().enumerate() {
            download_queue.push_back(PendingDownload {
                peer: message.contact_id.clone(),
                timestamp_ms: message.timestamp_ms,
                outgoing: message.outgoing,
                index: attachment_index,
                meta: meta.clone(),
            });
        }
        local_message.attachments = message.attachments;
        let _ = store.save_message(&message.contact_id, &local_message);
        let position = convo
            .messages
            .iter()
            .position(|m| m.timestamp_ms > local_message.timestamp_ms)
            .unwrap_or(convo.messages.len());
        let at_end = position == convo.messages.len();
        let was_at_bottom = convo.selected_message + 1 >= convo.messages.len();
        convo.messages.insert(position, local_message);
        if at_end && was_at_bottom {
            convo.selected_message = convo.messages.len() - 1;
        } else if position <= convo.selected_message && !convo.messages.is_empty() {
            convo.selected_message += 1;
        }
        convo.clamp_selection();
        convo.refresh_preview();
        added += 1;
    }
    if let Some(index) = app
        .conversations
        .iter()
        .position(|c| c.id == local_id && c.messages.is_empty())
    {
        let _ = store.delete_empty_contact(local_id);
        let selected_id = app.conversations.get(app.selected).map(|c| c.id.clone());
        app.conversations.remove(index);
        app.selected = selected_id
            .and_then(|id| app.conversations.iter().position(|c| c.id == id))
            .unwrap_or(0);
    }
    if added > 0 {
        app.sort_conversations();
    }
    app.status = format!(
        "SYNC · {added} NEW · {groups_found} GROUPS · {} QUEUED · {} DECRYPT FAIL · {} BAD ENVELOPE · {} BAD CONTENT",
        result.queued, result.undecryptable, result.bad_envelope, result.bad_content
    );
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn strip_session_padding(plaintext: &[u8]) -> &[u8] {
    let mut end = plaintext.len();
    while end > 0 {
        match plaintext[end - 1] {
            0 => end -= 1,
            0x80 => return &plaintext[..end - 1],
            _ => return plaintext,
        }
    }
    plaintext
}

/// Session-style timestamp: time only for today, date + time otherwise.
fn format_time(timestamp_ms: u64) -> String {
    use time::{OffsetDateTime, UtcOffset};
    let offset = LOCAL_OFFSET.get().copied().unwrap_or(UtcOffset::UTC);
    let Ok(time) = OffsetDateTime::from_unix_timestamp((timestamp_ms / 1000) as i64) else {
        return "--:--".into();
    };
    let local = time.to_offset(offset);
    let today = OffsetDateTime::now_utc().to_offset(offset);
    if local.date() == today.date() {
        format!("{:02}:{:02}", local.hour(), local.minute())
    } else if local.year() == today.year() {
        format!(
            "{:02}-{:02} {:02}:{:02}",
            local.month() as u8,
            local.day(),
            local.hour(),
            local.minute()
        )
    } else {
        format!(
            "{}-{:02}-{:02} {:02}:{:02}",
            local.year(),
            local.month() as u8,
            local.day(),
            local.hour(),
            local.minute()
        )
    }
}

fn draw(frame: &mut ratatui::Frame<'_>, app: &mut App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(Style::default().bg(BG)), area);
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .split(area);

    let header = Paragraph::new(Line::from(vec![
        Span::styled(
            " ◈ ",
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "SESSION",
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("   PRIVATE MESSENGER", Style::default().fg(MUTED)),
        Span::styled(
            format!("   FOCUS · {}", focus_name(app.focus)),
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        ),
        Span::raw("                                  "),
        Span::styled("● ", Style::default().fg(Color::Yellow)),
        Span::styled(
            &app.status,
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Rgb(35, 55, 62)))
            .style(Style::default().bg(PANEL)),
    );
    frame.render_widget(header, root[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(30), Constraint::Min(30)])
        .split(root[1]);
    draw_conversations(frame, columns[0], app);
    draw_chat(frame, columns[1], app);

    let footer = Paragraph::new(Line::from(vec![
        Span::styled("  Tab", Style::default().fg(TEAL)),
        Span::styled(" focus  ", Style::default().fg(MUTED)),
        Span::styled("  ←→", Style::default().fg(TEAL)),
        Span::styled(" chats  ", Style::default().fg(MUTED)),
        Span::styled("↑↓", Style::default().fg(TEAL)),
        Span::styled(" messages  ", Style::default().fg(MUTED)),
        Span::styled("Enter", Style::default().fg(TEAL)),
        Span::styled(" send  ", Style::default().fg(MUTED)),
        Span::styled("/rsync", Style::default().fg(TEAL)),
        Span::styled(" sync  ", Style::default().fg(MUTED)),
        Span::styled("/?", Style::default().fg(TEAL)),
        Span::styled(" help  ", Style::default().fg(MUTED)),
        Span::styled("/exit", Style::default().fg(TEAL)),
        Span::styled(" quit  ", Style::default().fg(MUTED)),
        Span::styled("Mouse", Style::default().fg(TEAL)),
        Span::styled(
            " click chat/image · wheel select",
            Style::default().fg(MUTED),
        ),
    ]))
    .style(Style::default().bg(PANEL));
    frame.render_widget(footer, root[2]);

    if app.show_help {
        draw_help(frame, area);
    }
    if let Some(seed) = app.recovery_seed.as_deref() {
        draw_recovery_seed(frame, area, seed);
    }
    if let Some(viewer) = app.image_viewer.as_mut() {
        let popup = centered_rect(92, 84, area);
        frame.render_widget(Clear, popup);
        let block = Block::default()
            .title(format!(" {} · ESC CLOSE ", viewer.title))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TEAL))
            .style(Style::default().bg(BG));
        let inner = block.inner(popup);
        frame.render_widget(block, popup);
        let image = StatefulImage::new(None).resize(Resize::Fit(Some(FilterType::Lanczos3)));
        frame.render_stateful_widget(image, inner, &mut viewer.protocol);
    }
}

fn focus_name(focus: FocusArea) -> &'static str {
    match focus {
        FocusArea::Contacts => "CONTACTS",
        FocusArea::Messages => "MESSAGES",
        FocusArea::Composer => "COMPOSER",
    }
}

fn draw_recovery_seed(frame: &mut ratatui::Frame<'_>, area: Rect, seed: &str) {
    let popup = centered_rect(70, 34, area);
    frame.render_widget(Clear, popup);
    let panel = Paragraph::new(vec![
        Line::from(Span::styled(
            "New Session account created",
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        )),
        Line::from(" "),
        Line::from("Save this 13-word recovery phrase before continuing:"),
        Line::from(" "),
        Line::from(Span::styled(seed, Style::default().fg(Color::Yellow))),
        Line::from(" "),
        Line::from(Span::styled(
            "Anyone with this seed can access your account.",
            Style::default().fg(Color::Red),
        )),
        Line::from("Press Enter when saved"),
    ])
    .block(
        Block::default()
            .title(" Recovery phrase ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TEAL))
            .style(Style::default().bg(PANEL)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(panel, popup);
}

fn draw_conversations(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let active = app.focus == FocusArea::Contacts;
    let focus_border = if active {
        Style::default().fg(TEAL)
    } else {
        Style::default().fg(Color::Rgb(35, 55, 62))
    };
    let inner = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(5)])
        .split(area);
    app.contact_list_area = Some(inner[1]);
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            if active {
                "  CHATS · FOCUS"
            } else {
                "  CHATS"
            },
            if active {
                Style::default().fg(TEAL).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(MUTED).add_modifier(Modifier::BOLD)
            },
        ),
        Span::styled("            Ctrl+N +", Style::default().fg(TEAL)),
    ]))
    .block(
        Block::default()
            .borders(Borders::RIGHT)
            .border_style(focus_border)
            .style(Style::default().bg(PANEL)),
    );
    frame.render_widget(title, inner[0]);
    let items: Vec<ListItem<'_>> = app
        .conversations
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let selected = i == app.selected;
            let marker = if selected && active { "▌" } else { " " };
            let entry_color = if selected {
                if active { TEAL } else { MUTED }
            } else {
                MUTED
            };
            let unread_count = c.unread();
            let unread = if unread_count > 0 {
                format!("  ●{unread_count}")
            } else {
                String::new()
            };
            ListItem::new(Text::from(vec![
                Line::from(vec![
                    Span::styled(
                        marker,
                        Style::default().fg(if active { TEAL } else { MUTED }),
                    ),
                    Span::styled(
                        format!(
                            " {}{}",
                            if c.id.starts_with("03") { "# " } else { "" },
                            c.name
                        ),
                        Style::default()
                            .fg(entry_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(unread, Style::default().fg(BLUE)),
                ]),
                Line::from(Span::styled(
                    format!("   {}", c.preview.chars().take(23).collect::<String>()),
                    Style::default().fg(MUTED),
                )),
                Line::from(" "),
            ]))
        })
        .collect();
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::RIGHT)
            .border_style(focus_border)
            .style(Style::default().bg(BG)),
    );
    let mut state = ListState::default();
    state.select(Some(app.selected));
    frame.render_stateful_widget(list, inner[1], &mut state);
    app.contact_list_offset = state.offset();
}

fn draw_chat(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .split(area);
    let selected = app.conversations.get(app.selected);
    let title_name = selected
        .map(|c| c.name.as_str())
        .unwrap_or("No conversation selected");
    let title_id = selected
        .map(|c| c.id.as_str())
        .unwrap_or("Ctrl+N to add a contact");
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {}", title_name),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("   {}", title_id), Style::default().fg(MUTED)),
        Span::styled("              SESSION ID", Style::default().fg(TEAL)),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Rgb(35, 55, 62)))
            .style(Style::default().bg(PANEL)),
    );
    frame.render_widget(title, rows[0]);

    let message_active = app.focus == FocusArea::Messages;
    let mut lines = vec![Line::from(" ")];
    let mut message_ranges = Vec::new();
    let mut attachment_ranges = Vec::new();
    if let Some(c) = selected {
        for (message_index, message) in c.messages.iter().enumerate() {
            let message_start = lines.len();
            let selected_message = message_index == c.selected_message;
            let marker = if selected_message && message_active {
                "▸"
            } else {
                " "
            };
            let (tag, color) = if message.outgoing {
                ("YOU".to_owned(), TEAL)
            } else if let Some(sender) = message.sender.as_deref() {
                (app.sender_label(sender), BLUE)
            } else {
                (c.name.clone(), BLUE)
            };
            let mut metadata = vec![
                Span::styled(
                    format!(" {marker} {tag}  "),
                    Style::default()
                        .fg(if selected_message && !message_active {
                            MUTED
                        } else {
                            color
                        })
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format_time(message.timestamp_ms), Style::default().fg(MUTED)),
            ];
            if message.outgoing {
                let (ticks, tick_color) = match message.receipt_status {
                    2 => (" ✓✓", TEAL),
                    1 => (" ✓✓", MUTED),
                    _ => (" ✓", MUTED),
                };
                metadata.push(Span::styled(
                    ticks,
                    Style::default().fg(tick_color).add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::from(metadata));
            let total = message.attachments.len();
            for (attachment_index, attachment) in message.attachments.iter().enumerate() {
                let attachment_start = lines.len();
                let numbering = if total > 1 {
                    format!("{}/{total} ", attachment_index + 1)
                } else {
                    String::new()
                };
                let pending = message
                    .image_previews
                    .get(attachment_index)
                    .is_none_or(Option::is_none)
                    && attachment.content_type.starts_with("image/");
                lines.push(Line::from(vec![
                    Span::styled(format!("    {numbering}"), Style::default().fg(MUTED)),
                    Span::styled(attachment_label(attachment), Style::default().fg(TEXT)),
                    Span::styled(
                        if pending { "  (loading…)" } else { "" },
                        Style::default().fg(MUTED),
                    ),
                ]));
                if let Some(Some(preview)) = message.image_previews.get(attachment_index) {
                    for pixels in &preview.rows {
                        let mut spans = vec![Span::raw("    ")];
                        spans.extend(pixels.iter().map(|(top, bottom)| {
                            Span::styled(
                                "▀",
                                Style::default()
                                    .fg(Color::Rgb(top[0], top[1], top[2]))
                                    .bg(Color::Rgb(bottom[0], bottom[1], bottom[2])),
                            )
                        }));
                        lines.push(Line::from(spans));
                    }
                }
                attachment_ranges.push((
                    attachment_start,
                    lines.len(),
                    message_index,
                    attachment_index,
                ));
            }
            for text_line in message.body.lines() {
                lines.push(Line::from(Span::styled(
                    format!("    {text_line}"),
                    Style::default().fg(TEXT),
                )));
            }
            lines.push(Line::from(" "));
            message_ranges.push((message_start, lines.len(), message_index));
        }
    } else {
        lines.push(Line::from(Span::styled(
            "  Add a contact with Ctrl+N. Use /rsync to sync the inbox.",
            Style::default().fg(MUTED),
        )));
    }
    let transcript_block = Block::default()
        .title(if message_active {
            " Messages · FOCUS "
        } else {
            " Messages "
        })
        .borders(Borders::ALL)
        .border_style(if message_active {
            Style::default().fg(TEAL)
        } else {
            Style::default().fg(Color::Rgb(35, 55, 62))
        })
        .style(Style::default().bg(BG));
    let transcript_area = transcript_block.inner(rows[1]);
    app.message_viewport = Some(transcript_area);
    let visible_height = transcript_area.height as usize;
    let wrapped = |part: &[Line<'_>]| {
        let width = transcript_area.width.max(1) as usize;
        part.iter()
            .map(|line| line.width().div_ceil(width).max(1))
            .sum::<usize>()
    };
    let total_visual_lines = wrapped(&lines);
    let max_scroll = total_visual_lines.saturating_sub(visible_height);
    let scroll = if message_active {
        selected
            .map(|c| {
                let (selected_start, selected_end, _) =
                    message_ranges.get(c.selected_message).copied().unwrap_or((
                        lines.len().saturating_sub(1),
                        lines.len(),
                        c.selected_message,
                    ));
                let selected_visual_start = wrapped(&lines[..selected_start.min(lines.len())]);
                let selected_visual_height =
                    wrapped(&lines[selected_start.min(lines.len())..selected_end]);
                // Keep the newest messages bottom-aligned when the selected
                // message overlaps the bottom viewport.  In particular, a
                // wrapped final message may start above max_scroll while its
                // body still extends below the viewport; scrolling to its
                // start would clip the newest text at the bottom.
                if selected_visual_start < max_scroll
                    && selected_visual_start + selected_visual_height <= max_scroll
                {
                    selected_visual_start
                } else if selected_visual_start + selected_visual_height
                    > max_scroll + visible_height
                {
                    selected_visual_start + selected_visual_height - visible_height
                } else {
                    max_scroll
                }
            })
            .unwrap_or(max_scroll)
            .min(max_scroll)
    } else {
        max_scroll
    };
    app.message_hitboxes.clear();
    let visible_end = scroll.saturating_add(visible_height);
    let ranges = message_ranges
        .iter()
        .map(|&(start, end, message)| (start, end, message, None))
        .chain(
            attachment_ranges
                .iter()
                .map(|&(start, end, message, attachment)| (start, end, message, Some(attachment))),
        );
    for (start, end, message_index, attachment_index) in ranges {
        let start_row = wrapped(&lines[..start.min(lines.len())]);
        let end_row = wrapped(&lines[..end.min(lines.len())]);
        if end_row <= scroll || start_row >= visible_end {
            continue;
        }
        let y_start = transcript_area.y
            + start_row
                .max(scroll)
                .saturating_sub(scroll)
                .min(u16::MAX as usize) as u16;
        let y_end = transcript_area.y
            + end_row
                .min(visible_end)
                .saturating_sub(scroll)
                .saturating_sub(1)
                .min(u16::MAX as usize) as u16;
        app.message_hitboxes
            .push((y_start, y_end, message_index, attachment_index));
    }
    let transcript = Paragraph::new(lines)
        .scroll((scroll.min(u16::MAX as usize) as u16, 0))
        .wrap(Wrap { trim: true })
        .style(Style::default().bg(BG))
        .block(transcript_block);
    frame.render_widget(transcript, rows[1]);

    let prompt = Paragraph::new(Line::from(vec![
        Span::styled(
            "  › ",
            Style::default()
                .fg(if app.focus == FocusArea::Composer {
                    TEAL
                } else {
                    MUTED
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            if app.input.is_empty() {
                if app.input_mode == InputMode::ContactId {
                    "Paste a Session ID (05…)…"
                } else {
                    "Write a message…"
                }
            } else {
                &app.input
            },
            Style::default().fg(if app.input.is_empty() { MUTED } else { TEXT }),
        ),
    ]))
    .block(
        Block::default()
            .title(if app.focus == FocusArea::Composer {
                " COMPOSER · FOCUS · Tab to change "
            } else {
                " COMPOSER · Tab to focus "
            })
            .borders(Borders::TOP)
            .border_style(if app.focus == FocusArea::Composer {
                Style::default().fg(TEAL)
            } else {
                Style::default().fg(Color::Rgb(35, 55, 62))
            })
            .style(Style::default().bg(PANEL)),
    );
    frame.render_widget(prompt, rows[2]);
}

fn draw_help(frame: &mut ratatui::Frame<'_>, area: Rect) {
    let popup = centered_rect(72, 62, area);
    frame.render_widget(Clear, popup);
    let help = Paragraph::new(vec![
        Line::from(Span::styled(
            "Keyboard shortcuts",
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        )),
        Line::from(" "),
        Line::from("← / →       Select a conversation"),
        Line::from("Tab         Move focus: contacts → messages → composer"),
        Line::from("↑ / ↓       Move in focused list"),
        Line::from("Mouse       Click chat/message; scroll to move selection"),
        Line::from("✓ / ✓✓     Delivered / read receipt for your messages"),
        Line::from("Delete      Delete selected message; outgoing messages send unsend"),
        Line::from("Ctrl+N      Add a contact by Session ID"),
        Line::from("/attach P1 [P2…] [-- caption]  Send files as one message (max 32)"),
        Line::from("/save [N] [PATH]  Save attachment N (default: all) to PATH or ./"),
        Line::from("            Focus Messages, select it with ↑/↓, then run /save"),
        Line::from("/view [N]   Open image N of the selected message (or click it)"),
        Line::from("Ctrl+U      Clear the composer"),
        Line::from("/name NAME Set the display name sent with your messages"),
        Line::from("/rsync     Retrieve your inbox and sync groups from this account"),
        Line::from("Enter       Send an end-to-end encrypted message"),
        Line::from("Backspace   Edit the message draft"),
        Line::from("/? / Esc    Open / close this panel"),
        Line::from("/exit      Quit the TUI"),
        Line::from(" "),
        Line::from(Span::styled(
            "Text uses Session routing. Delete removes locally; outgoing also requests remote unsend.",
            Style::default().fg(Color::Yellow),
        )),
    ])
    .block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(TEAL))
            .style(Style::default().bg(PANEL)),
    )
    .wrap(Wrap { trim: true });
    frame.render_widget(help, popup);
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - height) / 2),
            Constraint::Percentage(height),
            Constraint::Percentage((100 - height) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - width) / 2),
            Constraint::Percentage(width),
            Constraint::Percentage((100 - width) / 2),
        ])
        .split(vertical[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str, content_type: &str) -> AttachmentMeta {
        AttachmentMeta {
            file_name: name.into(),
            content_type: content_type.into(),
            url: String::new(),
            key: Vec::new(),
            digest: Vec::new(),
            size: 0,
            deterministic: false,
            width: None,
            height: None,
        }
    }

    #[test]
    fn split_args_honours_quotes() {
        assert_eq!(
            split_args(r#"a.png "my photo.jpg"  c"#),
            vec!["a.png", "my photo.jpg", "c"]
        );
        assert_eq!(split_args(r#""""#), vec![""]);
        assert!(split_args("   ").is_empty());
    }

    #[test]
    fn preview_text_summarises_albums() {
        let photos = [meta("a.jpg", "image/jpeg"), meta("b.jpg", "image/jpeg")];
        assert_eq!(message_preview_text("", &photos), "[2 Photos]");
        let mixed = [meta("a.jpg", "image/jpeg"), meta("b.pdf", "application/pdf")];
        assert_eq!(message_preview_text("", &mixed), "[Photo] a.jpg +1");
        assert_eq!(message_preview_text("caption\nmore", &photos), "caption");
        assert_eq!(message_preview_text("", &[]), "");
    }

    #[test]
    fn legacy_stored_message_still_loads() {
        let legacy = r#"{"body":"hi","attachment":{"file_name":"a.png","content_type":"image/png","url":"u","key":[],"digest":[],"size":1,"deterministic":false,"width":null,"height":null},"image_preview":null}"#;
        let stored: StoredMessage = serde_json::from_str(legacy).unwrap();
        assert!(stored.attachment.is_some());
        assert!(stored.attachments.is_empty());
        assert!(stored.sender.is_none());
    }

    #[test]
    fn attachment_file_name_is_sanitised() {
        assert_eq!(attachment_file_name(&meta("../../etc/x", "text/plain")), "x.txt");
        assert_eq!(attachment_file_name(&meta("voice", "audio/aac")), "voice.aac");
        assert_eq!(attachment_file_name(&meta("", "image/png")), "attachment.png");
    }

    #[test]
    fn blob_path_index_zero_is_backwards_compatible() {
        let root = std::path::Path::new("/r");
        let a = session_tui_media::attachment_blob_path(root, "05ab", 7, 0);
        let b = session_tui_media::attachment_blob_path(root, "05ab", 7, 1);
        assert_ne!(a, b);
    }
}
