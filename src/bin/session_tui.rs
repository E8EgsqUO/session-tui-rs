mod session_tui_media;
mod session_tui_group;
mod session_tui_input;
mod session_tui_account;

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

type DataQuote = libsession::proto::session_protos::data_message::Quote;

use libsession::{
    config::{
        config_base::ConfigBase,
        groups::info::GroupInfo as SharedGroupInfo,
        user_groups::GroupInfo as UserGroupInfo,
    },
    crypto::{curve25519, ed25519, random, session_encrypt},
    network::{
        HttpTransport, Network, NetworkConfig,
        rpc::{self, RetrieveParams, StoreParams},
        service_node::ServiceNode,
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
    /// The message this one replies to.
    quote: Option<QuoteRef>,
    /// Emoji reactions with the Session IDs of who reacted.
    reactions: Vec<ReactionEntry>,
    /// Disappearing-message setting this message was sent with.
    expiration: Option<Expiration>,
    /// Unix ms when the message disappears (set once its timer starts).
    expires_at: Option<u64>,
    /// Link previews (url, title).
    links: Vec<(String, Option<String>)>,
    /// Control/notice line (call, screenshot, group change…) rather than chat text.
    system: bool,
    /// Outgoing delivery state; not persisted (only sent messages are stored).
    send_state: SendState,
    /// Hashes of our own copies of this message in this account's swarm
    /// (1:1 sync copies), deleted from the swarm when the message is unsent.
    swarm_hashes: Vec<String>,
    /// Hash of a received message in the swarm it was fetched from (ours
    /// for 1:1, the group's for groups): group "delete content" commands
    /// and swarm expiry updates name messages by it.
    server_hash: Option<String>,
    /// When the swarm will drop it (from `retrieve`): tells whether another
    /// device already shortened a disappear-after-read message.
    swarm_expiry: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, serde::Serialize, serde::Deserialize)]
enum SendState {
    #[default]
    Sent,
    Sending,
    Failed,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq)]
struct QuoteRef {
    id: u64,
    author: String,
    text: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct ReactionEntry {
    emoji: String,
    authors: Vec<String>,
}

/// Session `Content.expirationType` + `expirationTimer`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
struct Expiration {
    /// 1 = delete after read, 2 = delete after send.
    kind: i32,
    seconds: u32,
}

impl Expiration {
    fn from_content(kind: Option<i32>, seconds: Option<u32>) -> Option<Self> {
        match (kind, seconds) {
            (Some(kind @ (1 | 2)), Some(seconds)) if seconds > 0 => Some(Self { kind, seconds }),
            _ => None,
        }
    }

    fn describe(setting: Option<Self>) -> String {
        match setting {
            None => "off".into(),
            Some(e) => format!(
                "{} after {}",
                format_duration(e.seconds),
                if e.kind == 1 { "read" } else { "send" }
            ),
        }
    }

    /// Parse `/disappear` arguments: `off`, or `read|send DURATION`.
    fn parse(args: &str) -> Result<Option<Self>, String> {
        let mut parts = args.split_whitespace();
        let usage = || "USAGE · /disappear off | read 12h | send 1d".to_string();
        let kind = match parts.next().ok_or_else(usage)? {
            "off" => return Ok(None),
            "read" => 1,
            "send" => 2,
            _ => return Err(usage()),
        };
        let seconds = parse_duration(parts.next().ok_or_else(usage)?).ok_or_else(usage)?;
        Ok(Some(Self { kind, seconds }))
    }
}

fn parse_duration(text: &str) -> Option<u32> {
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit())?);
    let number: u32 = number.parse().ok()?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    number.checked_mul(scale).filter(|seconds| *seconds > 0)
}

fn format_duration(seconds: u32) -> String {
    for (unit, size) in [("w", 604_800), ("d", 86_400), ("h", 3600), ("m", 60)] {
        if seconds >= size && seconds % size == 0 {
            return format!("{}{unit}", seconds / size);
        }
    }
    format!("{seconds}s")
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
            quote: None,
            reactions: Vec::new(),
            expiration: None,
            expires_at: None,
            links: Vec::new(),
            system: false,
            send_state: SendState::Sent,
            swarm_hashes: Vec::new(),
            server_hash: None,
            swarm_expiry: None,
        }
    }

    fn system(text: String, timestamp_ms: u64) -> Self {
        let mut message = Self::new(text, timestamp_ms, false);
        message.system = true;
        message.is_read = true;
        message
    }

    /// Session ID of whoever wrote this message.
    fn author<'a>(&'a self, conversation_id: &'a str, local_id: &'a str) -> &'a str {
        if self.outgoing {
            local_id
        } else {
            self.sender.as_deref().unwrap_or(conversation_id)
        }
    }

    /// Start the disappearing timer (Session starts "after send" timers at
    /// send time and "after read" ones when the message is read; our own
    /// messages count as read when sent).
    fn start_expiry(&mut self, read_at: Option<u64>) {
        if self.expires_at.is_some() {
            return;
        }
        if let Some(expiration) = self.expiration {
            let start = if expiration.kind == 2 || self.outgoing {
                Some(self.timestamp_ms)
            } else {
                read_at
            };
            self.expires_at = start.map(|start| start + u64::from(expiration.seconds) * 1000);
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quote: Option<QuoteRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reactions: Vec<ReactionEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiration: Option<Expiration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    links: Vec<(String, Option<String>)>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    system: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    swarm_hashes: Vec<String>,
    #[serde(default, alias = "group_hash", skip_serializing_if = "Option::is_none")]
    server_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    swarm_expiry: Option<u64>,
    /// Not written for sent messages (old rows read as sent).
    #[serde(default, skip_serializing_if = "is_sent")]
    send_state: SendState,
}

fn is_sent(state: &SendState) -> bool {
    *state == SendState::Sent
}

/// Session's default quick reactions (the reaction bar in the apps).
const QUICK_REACTIONS: [&str; 6] = ["😂", "🥰", "😢", "😡", "😮", "😈"];

/// `:name:` shortcodes expanded in messages and `/react`.
const EMOJI_SHORTCODES: &[(&str, &str)] = &[
    ("+1", "👍"), ("thumbsup", "👍"), ("-1", "👎"), ("thumbsdown", "👎"),
    ("joy", "😂"), ("haha", "😂"), ("lol", "😂"), ("xd", "😆"), ("rofl", "🤣"), ("smile", "😄"), ("grin", "😁"),
    ("laughing", "😆"), ("sweat_smile", "😅"), ("wink", "😉"), ("blush", "😊"),
    ("love", "🥰"), ("heart_eyes", "😍"), ("kiss", "😘"), ("thinking", "🤔"),
    ("neutral", "😐"), ("cry", "😢"), ("sob", "😭"), ("angry", "😠"),
    ("rage", "😡"), ("scream", "😱"), ("open_mouth", "😮"), ("sunglasses", "😎"),
    ("sleepy", "😴"), ("party", "🥳"), ("hug", "🤗"), ("shrug", "🤷"),
    ("facepalm", "🤦"), ("devil", "😈"), ("skull", "💀"), ("poop", "💩"),
    ("ok", "👌"), ("clap", "👏"), ("pray", "🙏"), ("wave", "👋"),
    ("muscle", "💪"), ("eyes", "👀"), ("heart", "❤️"), ("broken_heart", "💔"),
    ("fire", "🔥"), ("star", "⭐"), ("sparkles", "✨"), ("tada", "🎉"),
    ("100", "💯"), ("check", "✅"), ("x", "❌"), ("rocket", "🚀"),
    ("coffee", "☕"), ("beer", "🍺"),
];

/// Replace known `:name:` shortcodes with emoji; unknown ones stay as typed.
fn expand_shortcodes(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(':') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let replaced = after.find(':').and_then(|end| {
            let name = &after[..end];
            EMOJI_SHORTCODES
                .iter()
                .find(|(code, _)| *code == name)
                .map(|(_, emoji)| (*emoji, end))
        });
        match replaced {
            Some((emoji, end)) => {
                out.push_str(emoji);
                rest = &after[end + 1..];
            }
            None => {
                out.push(':');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// Transcript rows scrolled per mouse-wheel notch.
const WHEEL_ROWS: usize = 3;

const STORED_MESSAGE_PREFIX: &str = "\0session-tui-message-v1:";

/// Session clients accept at most 32 attachments in one message.
const MAX_ATTACHMENTS: usize = 32;

/// Upper bound on `more` pages fetched per namespace in one sync.
const MAX_RETRIEVE_PAGES: usize = 20;

const DEFAULT_SIDEBAR_WIDTH: u16 = 30;
const MIN_SIDEBAR_WIDTH: u16 = 20;
/// Narrowest the chat window may get when the chat list is widened.
const MIN_CHAT_WIDTH: u16 = 30;

#[derive(Clone)]
struct Conversation {
    name: String,
    id: String,
    preview: String,
    messages: Vec<Message>,
    selected_message: usize,
    /// Disappearing-messages setting applied to messages we send here.
    disappearing: Option<Expiration>,
    /// Show "typing…" until this instant.
    typing_until: Option<Instant>,
    /// Group membership is read-only (no write permission).
    read_only: bool,
    /// Top row of the transcript when scrolled with the mouse wheel;
    /// `None` follows the selection / newest messages.
    scroll: Option<usize>,
    /// Arrow keys moved the selection: keep it in view. Cleared by the
    /// mouse wheel, after which the view sticks to the newest messages.
    follow_selection: bool,
}

impl Conversation {
    /// Name shown for the chat; our own Session ID is "Note to Self", as in
    /// the official apps.
    fn title<'a>(&'a self, local_id: &str) -> &'a str {
        if self.id == local_id {
            "Note to Self"
        } else {
            &self.name
        }
    }

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ChatAction {
    /// `/delete`: the chat and its messages.
    Delete,
    /// `/remove`: the contact, and its chat.
    Remove,
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
    /// Message the next text/attachment replies to.
    reply_to: Option<QuoteRef>,
    /// Composer cursor (byte offset into `input`).
    cursor: usize,
    /// Ring the terminal bell for new messages (`/bell on|off`).
    bell: bool,
    /// Contacts blocked in the account config.
    blocked: HashSet<String>,
    /// Contacts already approved in the account config.
    approved: HashSet<String>,
    /// The terminal window has focus (from focus events).
    window_focused: bool,
    /// Quick-reaction bar for the selected message is open.
    reaction_picker: bool,
    /// Delete choice is open; `true` when "delete for everyone" is allowed.
    delete_prompt: Option<bool>,
    /// `/delete` or `/remove` waiting for confirmation, for this chat ID.
    chat_prompt: Option<(ChatAction, String)>,
    /// Emoji shortcode list is open.
    show_emoji: bool,
    help_scroll: u16,
    /// (scroll, max scroll) of the transcript as last drawn.
    transcript_scroll: (usize, usize),
    transcript_conversation: usize,
    local_id: String,
    /// Width of the chat list column, changed by dragging its right border.
    sidebar_width: u16,
    /// Column of the chat list's right border and the rows it spans.
    divider: Option<Rect>,
    /// The divider is being dragged with the mouse.
    dragging_divider: bool,
    /// Last left click (time, column, row), to detect double-clicks.
    last_click: Option<(Instant, u16, u16)>,
    /// Newest timestamp given to a message we send (see
    /// [`next_outgoing_timestamp`]).
    last_outgoing_ms: u64,
    /// Row count of each message in the open chat, by layout key.
    layout_heights: (String, HashMap<u64, usize>),
    /// Text waiting to be put on the system clipboard.
    clipboard: Option<String>,
    /// Top header (shows our own ID) and the chat's title bar.
    header_area: Option<Rect>,
    chat_title_area: Option<Rect>,
}

impl App {
    fn new(local_id: String) -> Self {
        Self {
            conversations: Vec::new(),
            selected: 0,
            input: String::new(),
            input_mode: InputMode::Message,
            seen_hashes: HashSet::new(),
            status: format!("{}… · READY", &local_id[..10.min(local_id.len())]),
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
            reply_to: None,
            cursor: 0,
            bell: true,
            blocked: HashSet::new(),
            approved: HashSet::new(),
            window_focused: true,
            reaction_picker: false,
            delete_prompt: None,
            chat_prompt: None,
            show_emoji: false,
            help_scroll: 0,
            transcript_scroll: (0, 0),
            transcript_conversation: usize::MAX,
            local_id,
            sidebar_width: DEFAULT_SIDEBAR_WIDTH,
            divider: None,
            dragging_divider: false,
            last_click: None,
            clipboard: None,
            layout_heights: (String::new(), HashMap::new()),
            last_outgoing_ms: 0,
            header_area: None,
            chat_title_area: None,
        }
    }

    /// Order chats by latest activity (newest first) like Session, keeping
    /// the currently selected chat selected.
    fn sort_conversations(&mut self) {
        let selected_id = self.conversations.get(self.selected).map(|c| c.id.clone());
        self.conversations
            .sort_by_key(|c| std::cmp::Reverse(c.last_activity()));
        // Message requests go below the regular chats, as their own section.
        let requests: HashSet<String> = self
            .conversations
            .iter()
            .filter(|c| self.is_request(c))
            .map(|c| c.id.clone())
            .collect();
        self.conversations
            .sort_by_key(|c| requests.contains(&c.id));
        if let Some(id) = selected_id
            && let Some(index) = self.conversations.iter().position(|c| c.id == id)
        {
            self.selected = index;
        }
    }

    /// A 1:1 chat started by someone we haven't approved: a message request.
    /// We approve by replying or with `/accept`.
    fn is_request(&self, conversation: &Conversation) -> bool {
        conversation.id.starts_with("05")
            && conversation.id != self.local_id
            && !self.approved.contains(&conversation.id)
            && !conversation.messages.is_empty()
            && !conversation.messages.iter().any(|m| m.outgoing)
    }

    fn sender_label(&self, sender: &str) -> String {
        if sender == self.local_id {
            return "You".into();
        }
        if let Some(conversation) = self
            .conversations
            .iter()
            .find(|c| c.id == sender && c.name != short_id(sender))
        {
            return conversation.name.clone();
        }
        self.display_names
            .get(sender)
            .cloned()
            .unwrap_or_else(|| short_id(sender))
    }

    fn selected_message(&self) -> Option<&Message> {
        let conversation = self.conversations.get(self.selected)?;
        conversation.messages.get(conversation.selected_message)
    }

    fn selected_message_mut(&mut self) -> Option<&mut Message> {
        let conversation = self.conversations.get_mut(self.selected)?;
        conversation.messages.get_mut(conversation.selected_message)
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
            disappearing: None,
            typing_until: None,
            read_only: false,
            scroll: None,
            follow_selection: false,
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
            message_blob_owner(&conversation.id, message),
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
    let image = session_tui_media::decode_image(&plaintext).map_err(|e| format!("decode image: {e}"))?;

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
    let images = app.selected_message().map_or(0, |message| {
        message
            .attachments
            .iter()
            .filter(|a| a.content_type.starts_with("image/"))
            .count()
    });
    app.image_viewer = Some(ImageViewer {
        index: attachment_index,
        title: if images > 1 {
            format!(
                "{} ({}/{count}) · ←/→ PREV/NEXT",
                metadata.file_name,
                attachment_index + 1
            )
        } else {
            metadata.file_name
        },
        protocol,
    });
    Ok(())
}

/// Database key part for a message's author: the member in groups, empty
/// for 1:1 chats and our own messages.
fn sender_key(message: &Message) -> &str {
    message.sender.as_deref().unwrap_or("")
}

/// A message's expiry in a `get_expiries` reply: `{"expiries": {hash: ms}}`,
/// possibly per swarm node under `"swarm"`. Missing means already expired.
fn parse_expiry(body: &Value, hash: &str) -> Option<u64> {
    let direct = body.get("expiries").and_then(|e| e.get(hash)).and_then(Value::as_u64);
    direct.or_else(|| {
        body.get("swarm")?
            .as_object()?
            .values()
            .filter_map(|node| node.get("expiries")?.get(hash)?.as_u64())
            .min()
    })
}

/// Short description of what a Content carries, for the debug log.
fn content_kind(content: &Content) -> String {
    if let Some(receipt) = &content.receipt_message {
        return format!("receipt:{}", if receipt.r#type == 0 { "delivery" } else { "read" });
    }
    if content.typing_message.is_some() {
        return "typing".into();
    }
    if let Some(data) = &content.data_message {
        if data.sync_target.is_some() {
            return "sync_copy".into();
        }
        if data.reaction.is_some() {
            return "reaction".into();
        }
        if data.group_update_message.is_some() {
            return "group_update".into();
        }
        return "message".into();
    }
    if content.unsend_request.is_some() {
        return "unsend".into();
    }
    if content.data_extraction_notification.is_some() {
        return "screenshot_notice".into();
    }
    "other".into()
}

/// Our Session ID, so the attachment cache keeps accounts apart.
static BLOB_ACCOUNT: OnceLock<String> = OnceLock::new();

/// Name under which a message's attachments are cached: account, chat,
/// author (group member) and direction, i.e. everything that tells apart
/// two messages with the same timestamp in the database.
fn blob_owner(peer: &str, sender: Option<&str>, outgoing: bool) -> String {
    format!(
        "v2|{}|{peer}|{}|{}",
        BLOB_ACCOUNT.get().map_or("", String::as_str),
        sender.unwrap_or(""),
        if outgoing { "out" } else { "in" }
    )
}

fn message_blob_owner(peer: &str, message: &Message) -> String {
    blob_owner(peer, message.sender.as_deref(), message.outgoing)
}

/// Write an attachment's encrypted blob to the local cache.
fn write_attachment_blob(owner: &str, timestamp: u64, index: usize, bytes: &[u8]) -> Result<(), String> {
    let root = session_data_dir()?;
    let path = session_tui_media::attachment_blob_path(&root, owner, timestamp, index);
    let parent = path.parent().ok_or("invalid attachment cache path")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())
}

/// Folder for `/paste` images between reading the clipboard and uploading.
fn paste_dir() -> Result<std::path::PathBuf, String> {
    Ok(session_data_dir()?.join("paste"))
}

fn is_pasted_image(path: &std::path::Path) -> bool {
    paste_dir().is_ok_and(|dir| path.parent() == Some(dir.as_path()))
}

/// Delete pasted images left behind (e.g. the program was closed mid-upload).
fn clean_paste_dir() {
    if let Ok(dir) = paste_dir()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for entry in entries.flatten() {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

/// Save the image on the system clipboard as a PNG in [`paste_dir`].
fn save_clipboard_image() -> Result<std::path::PathBuf, String> {
    let mut clipboard =
        arboard::Clipboard::new().map_err(|_| "NO CLIPBOARD (REMOTE/SSH SESSION?)".to_owned())?;
    let image = clipboard
        .get_image()
        .map_err(|_| "NO IMAGE ON THE CLIPBOARD".to_owned())?;
    let buffer = image::RgbaImage::from_raw(
        image.width as u32,
        image.height as u32,
        image.bytes.into_owned(),
    )
    .ok_or("UNREADABLE CLIPBOARD IMAGE")?;
    let mut png = Vec::new();
    buffer
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .map_err(|e| e.to_string())?;
    let dir = paste_dir()?;
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("screenshot-{}.png", now_ms()));
    // Screenshots are private: only this user may read the folder and file
    // (Windows: %APPDATA% is already private to the user).
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| e.to_string())?;
        options.mode(0o600);
    }
    let mut file = options.open(&path).map_err(|e| e.to_string())?;
    file.write_all(&png).map_err(|e| e.to_string())?;
    Ok(path)
}

/// Put `text` on the clipboard: OSC 52 for terminals that support it
/// (Windows Terminal, most others, also over SSH), plus the desktop's own
/// clipboard tool where there is one (VTE terminals ignore OSC 52).
fn copy_to_clipboard(out: &mut impl Write, text: &str) {
    let _ = write!(out, "\x1b]52;c;{}\x07", STANDARD.encode(text));
    let _ = out.flush();
    #[cfg(unix)]
    {
        use std::process::{Command, Stdio};
        let tools: &[&[&str]] = if cfg!(target_os = "macos") {
            &[&["pbcopy"]]
        } else {
            &[
                &["wl-copy"],
                &["xclip", "-selection", "clipboard"],
                &["xsel", "--clipboard", "--input"],
            ]
        };
        for tool in tools {
            if tool[0] == "wl-copy" && std::env::var_os("WAYLAND_DISPLAY").is_none() {
                continue;
            }
            if tool[0] != "wl-copy"
                && tool[0] != "pbcopy"
                && std::env::var_os("DISPLAY").is_none()
            {
                continue;
            }
            let Ok(mut child) = Command::new(tool[0])
                .args(&tool[1..])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
            else {
                continue;
            };
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(text.as_bytes());
            }
            // xclip/xsel stay alive to serve the selection; reap in the background.
            std::thread::spawn(move || child.wait());
            break;
        }
    }
}

fn handle_mouse(app: &mut App, mouse: crossterm::event::MouseEvent) {
    if app.image_viewer.is_some() {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            app.image_viewer = None;
        }
        return;
    }
    let double_click = matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) && {
        let now = Instant::now();
        let double = app.last_click.is_some_and(|(at, column, row)| {
            now.duration_since(at) < Duration::from_millis(500)
                && column.abs_diff(mouse.column) <= 1
                && row == mouse.row
        });
        app.last_click = (!double).then_some((now, mouse.column, mouse.row));
        double
    };
    if let Some(seed) = app.recovery_seed.as_ref() {
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            app.clipboard = Some(seed.clone());
            app.status = "RECOVERY PHRASE COPIED".into();
        }
        return;
    }
    let hit = |rect: Option<Rect>| {
        rect.is_some_and(|r| {
            mouse.column >= r.x
                && mouse.column < r.right()
                && mouse.row >= r.y
                && mouse.row < r.bottom()
        })
    };
    if double_click && hit(app.header_area) {
        app.clipboard = Some(app.local_id.clone());
        app.status = "YOUR SESSION ID COPIED".into();
        return;
    }
    if double_click && hit(app.chat_title_area) {
        if let Some(conversation) = app.conversations.get(app.selected) {
            app.clipboard = Some(conversation.id.clone());
            app.status = "SESSION ID COPIED".into();
        }
        return;
    }
    if double_click && hit(app.message_viewport) {
        let text = app
            .message_hitboxes
            .iter()
            .find(|(start, end, _, attachment)| {
                attachment.is_none() && mouse.row >= *start && mouse.row <= *end
            })
            .and_then(|(_, _, index, _)| {
                app.conversations.get(app.selected)?.messages.get(*index)
            })
            .map(|message| message.body.clone())
            .filter(|body| !body.is_empty());
        if let Some(text) = text {
            app.clipboard = Some(text);
            app.status = "MESSAGE COPIED".into();
            return;
        }
    }
    if app.dragging_divider {
        match mouse.kind {
            MouseEventKind::Drag(MouseButton::Left) => {
                if let Some(divider) = app.divider {
                    // The border is the list's last column.
                    let left = divider.x + 1 - app.sidebar_width;
                    app.sidebar_width = mouse.column.saturating_sub(left) + 1;
                }
            }
            MouseEventKind::Up(_) => app.dragging_divider = false,
            _ => {}
        }
        return;
    }
    if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
        && app.divider.is_some_and(|d| {
            mouse.column.abs_diff(d.x) <= 1
                && mouse.row >= d.y
                && mouse.row < d.y.saturating_add(d.height)
        })
    {
        app.dragging_divider = true;
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
        let (current, max_scroll) = app.transcript_scroll;
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if let Some(conversation) = app.conversations.get_mut(app.selected) {
                    conversation.scroll = Some(current.saturating_sub(WHEEL_ROWS));
                    conversation.follow_selection = false;
                }
            }
            MouseEventKind::ScrollDown => {
                if let Some(conversation) = app.conversations.get_mut(app.selected) {
                    let next = current + WHEEL_ROWS;
                    // Reaching the bottom resumes following new messages.
                    conversation.scroll = (next < max_scroll).then_some(next);
                    conversation.follow_selection = false;
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

/// A 1:1 (`05…`) or group (`03…`) chat ID: prefix + 64 hex digits.
fn is_chat_id(id: &str) -> bool {
    id.len() == 66
        && (id.starts_with("05") || id.starts_with("03"))
        && id[2..].bytes().all(|b| b.is_ascii_hexdigit())
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

/// The storage server reports the stored message hash either at the top
/// level or per swarm node (`{"swarm": {"<node>": {"hash": …}}}`).
fn find_message_hash(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => map
            .get("hash")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| map.values().find_map(find_message_hash)),
        Value::Array(items) => items.iter().find_map(find_message_hash),
        _ => None,
    }
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
    /// The swarm's expiry for it (`expiration` in the retrieve response).
    swarm_expiry: Option<u64>,
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
    quote: Option<QuoteRef>,
    expiration: Option<Expiration>,
    links: Vec<(String, Option<String>)>,
    /// (target message timestamp, target author, emoji, removed)
    reaction: Option<(u64, String, String, bool)>,
    /// Typing indicator: Some(true) started, Some(false) stopped.
    typing: Option<bool>,
    /// A notice to show in the chat instead of a chat message.
    event: Option<ChatEvent>,
}

/// Non-chat events shown as notice lines.
enum ChatEvent {
    Notice(String),
    /// Disappearing-messages setting changed (1:1 chats).
    TimerChanged(Option<Expiration>),
    /// Group membership changes; names are resolved when displayed.
    Members { action: &'static str, ids: Vec<String> },
    /// Group invite received in a 1:1 chat.
    Invite(LocalGroup),
    /// An admin removed everything these members posted.
    /// Member IDs, message hashes and the admin signature over them.
    DeleteMemberContent {
        ids: Vec<String>,
        hashes: Vec<String>,
        signature: Option<Vec<u8>>,
    },
}

impl IncomingMessage {
    fn control(hash: String, sender_id: String, contact_id: String, timestamp_ms: u64) -> Self {
        Self {
            hash,
            swarm_expiry: None,
            sender_id,
            contact_id,
            outgoing: false,
            sender_name: None,
            body: None,
            timestamp_ms,
            unsend: None,
            receipt: None,
            attachments: Vec::new(),
            quote: None,
            expiration: None,
            links: Vec::new(),
            reaction: None,
            typing: None,
            event: None,
        }
    }
}

/// Turn decrypted `Content` into an [`IncomingMessage`], following how the
/// Session clients interpret each message type. `contact_id` is the chat the
/// message belongs to (the sender for 1:1, the group for groups); a 1:1
/// sync copy of our own message is re-routed via `syncTarget`.
fn parse_content(
    local_id: &str,
    hash: String,
    sender_id: String,
    contact_id: String,
    envelope_timestamp: u64,
    content: Content,
) -> Option<IncomingMessage> {
    use libsession::proto::session_protos::{
        call_message, data_extraction_notification, group_update_info_change_message,
        group_update_member_change_message, typing_message,
    };
    let is_group = contact_id.starts_with("03");
    let mut message =
        IncomingMessage::control(hash, sender_id.clone(), contact_id, envelope_timestamp);
    message.outgoing = sender_id == local_id;
    if let Some(unsend) = content.unsend_request {
        message.timestamp_ms = unsend.timestamp;
        message.unsend = Some((unsend.timestamp, unsend.author));
        return Some(message);
    }
    if let Some(receipt) = content.receipt_message {
        message.receipt = Some((receipt.r#type, receipt.timestamp));
        return Some(message);
    }
    if let Some(typing) = content.typing_message {
        message.timestamp_ms = typing.timestamp;
        message.typing = Some(typing.action == typing_message::Action::Started as i32);
        return Some(message);
    }
    if let Some(notification) = content.data_extraction_notification {
        message.timestamp_ms = notification.timestamp.unwrap_or(envelope_timestamp);
        message.event = Some(ChatEvent::Notice(
            if notification.r#type == data_extraction_notification::Type::Screenshot as i32 {
                "took a screenshot"
            } else {
                "saved a media file"
            }
            .into(),
        ));
        return Some(message);
    }
    if let Some(call) = content.call_message {
        // Only the first message of a call attempt creates a notice.
        if call.r#type == call_message::Type::PreOffer as i32 && !message.outgoing {
            message.event = Some(ChatEvent::Notice(
                "called you (missed: calls are not supported in this client)".into(),
            ));
            return Some(message);
        }
        return None;
    }
    let expiration = Expiration::from_content(content.expiration_type, content.expiration_timer);
    let data_message = content.data_message?;
    message.timestamp_ms = data_message.timestamp.unwrap_or(envelope_timestamp);
    message.expiration = expiration;
    if !message.outgoing
        && let Some(name) = data_message
            .profile
            .as_ref()
            .and_then(|profile| profile.display_name.as_deref())
            .map(str::trim)
            .filter(|name| !name.is_empty())
    {
        message.sender_name = Some(name.to_owned());
    }

    if let Some(update) = data_message.group_update_message {
        message.event = if let Some(invite) = update.invite_message {
            Some(ChatEvent::Invite(LocalGroup {
                id: invite.group_session_id,
                name: invite.name,
                auth_data: invite.member_auth_data,
                responded: false,
            }))
        } else if let Some(change) = update.info_change_message {
            use group_update_info_change_message::Type;
            Some(match Type::try_from(change.r#type) {
                Ok(Type::Name) => ChatEvent::Notice(format!(
                    "renamed the group to \"{}\"",
                    change.updated_name.unwrap_or_default()
                )),
                Ok(Type::Avatar) => ChatEvent::Notice("changed the group picture".into()),
                _ => ChatEvent::Notice(format!(
                    "set disappearing messages to {}",
                    Expiration::describe(change.updated_expiration.filter(|s| *s > 0).map(
                        |seconds| Expiration { kind: 2, seconds }
                    ))
                )),
            })
        } else if let Some(change) = update.member_change_message {
            use group_update_member_change_message::Type;
            let action = match Type::try_from(change.r#type) {
                Ok(Type::Added) => "added",
                Ok(Type::Removed) => "removed",
                _ => "promoted to admin",
            };
            Some(ChatEvent::Members {
                action,
                ids: change.member_session_ids,
            })
        } else if update.member_left_message.is_some()
            || update.member_left_notification_message.is_some()
        {
            Some(ChatEvent::Notice("left the group".into()))
        } else if let Some(response) = update.invite_response {
            response
                .is_approved
                .then(|| ChatEvent::Notice("joined the group".into()))
        } else if update.promote_message.is_some() {
            Some(ChatEvent::Notice(
                "promoted you to admin (manage the group from another Session client)".into(),
            ))
        } else {
            update
                .delete_member_content
                .map(|delete| ChatEvent::DeleteMemberContent {
                    ids: delete.member_session_ids,
                    hashes: delete.message_hashes,
                    signature: delete.admin_signature,
                })
        };
        return message.event.is_some().then_some(message);
    }

    if data_message.flags.unwrap_or(0) & 2 != 0 {
        // EXPIRATION_TIMER_UPDATE
        message.event = Some(ChatEvent::TimerChanged(expiration));
        if message.outgoing
            && let Some(target) = data_message.sync_target.filter(|target| is_chat_id(target))
        {
            message.contact_id = target;
        }
        return Some(message);
    }

    // Our own messages mirrored from another device name the real chat
    // (a contact `05…` or a group `03…`). Only our own messages may be
    // re-routed; anything else stays in the sender's chat.
    if !is_group
        && message.outgoing
        && let Some(target) = data_message.sync_target.clone().filter(|target| is_chat_id(target))
    {
        message.contact_id = target;
        message.sender_name = None;
    }

    if let Some(reaction) = data_message.reaction {
        message.reaction = Some((
            reaction.id,
            reaction.author,
            reaction.emoji.unwrap_or_default(),
            reaction.action == 1,
        ));
        return Some(message);
    }

    let mut body = data_message.body.unwrap_or_default();
    if let Some(invitation) = data_message.open_group_invitation {
        body = format!("[Community invite] {} · {}", invitation.name, invitation.url);
    }
    message.attachments = data_message
        .attachments
        .iter()
        .map(attachment_meta_from_pointer)
        .collect();
    message.quote = data_message.quote.map(|quote| QuoteRef {
        id: quote.id,
        author: quote.author,
        text: quote.text.unwrap_or_else(|| {
            quote
                .attachments
                .first()
                .map(|a| format!("[{}]", a.file_name.clone().unwrap_or_else(|| "attachment".into())))
                .unwrap_or_default()
        }),
    });
    message.links = data_message
        .preview
        .into_iter()
        .map(|preview| (preview.url, preview.title))
        .collect();
    if body.is_empty() && message.attachments.is_empty() {
        return None;
    }
    message.body = Some(body);
    Some(message)
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
    /// All per-node cursors after this sync (saved with it).
    node_cursors: Vec<(String, String)>,
    /// Joined groups we have now sent the invite acceptance to.
    invite_responses: Vec<String>,
    account: Option<AccountSyncResult>,
}

/// One attachment waiting to be downloaded into the local cache.
#[derive(Clone)]
struct PendingDownload {
    peer: String,
    /// Group member who sent it (`Message::sender`).
    sender: Option<String>,
    timestamp_ms: u64,
    outgoing: bool,
    index: usize,
    meta: AttachmentMeta,
}

impl PendingDownload {
    /// This job's message and attachment (same message key as the database,
    /// and the attachment itself unchanged).
    fn is_for(&self, message: &Message) -> bool {
        message.timestamp_ms == self.timestamp_ms
            && message.outgoing == self.outgoing
            && message.sender == self.sender
            && message
                .attachments
                .get(self.index)
                .is_some_and(|meta| meta.digest == self.meta.digest)
    }
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
    can_write: bool,
}

#[derive(Clone)]
struct GroupRuntime {
    id: String,
    public_key: [u8; 32],
    auth: GroupAuth,
    /// Group encryption keys, newest generation first.
    keys: Vec<[u8; 32]>,
}

/// How this account authenticates to a group's swarm.
#[derive(Clone)]
enum GroupAuth {
    /// We hold the group's Ed25519 key (admin).
    Admin { seed: Vec<u8>, secret_key: Vec<u8> },
    /// Ordinary member: subaccount auth data issued by an admin.
    Member { auth_data: Vec<u8> },
}

impl GroupAuth {
    fn admin_seed(&self) -> Option<&[u8]> {
        match self {
            GroupAuth::Admin { seed, .. } => Some(seed),
            GroupAuth::Member { .. } => None,
        }
    }

    fn can_write(&self) -> bool {
        match self {
            GroupAuth::Admin { .. } => true,
            GroupAuth::Member { auth_data } => session_tui_group::subaccount_can_write(auth_data),
        }
    }
}

enum SwarmAuth<'a> {
    /// This account's own swarm (05…), signed with our Ed25519 key.
    User,
    Group(&'a GroupAuth),
}

/// A group joined from an invite in this client (not yet in UserGroups).
#[derive(Clone)]
struct LocalGroup {
    id: String,
    name: String,
    auth_data: Vec<u8>,
    /// We already told the group we accepted the invite.
    responded: bool,
}

struct SessionClient {
    identity: Identity,
    network: Network<HttpTransport>,
    groups: Mutex<HashMap<String, GroupRuntime>>,
    /// Swarm member we keep polling per account/group, while it answers.
    poll_nodes: Mutex<HashMap<String, ServiceNode>>,
    /// Message cursors per (swarm key, namespace, node), as the official
    /// clients keep them: a node is only asked for what is new since we
    /// last fetched from that same node, so a node that doesn't know
    /// another node's newest hash can't make us download everything again.
    /// Only cursors whose messages were committed to the database.
    node_cursors: Mutex<HashMap<String, String>>,
    /// Cursors reached by the sync in progress. They become `node_cursors`
    /// only once `finish_sync` has committed that sync's messages, so a
    /// failed write, rollback or timeout never moves the next start point.
    pending_cursors: Mutex<HashMap<String, String>>,
}

fn node_cursor_key(pubkey: &str, namespace: i32, node: &ServiceNode) -> String {
    format!("{pubkey}/{namespace}/{}", hex::encode(node.ed25519_pubkey.0))
}

/// Result of mirroring an outgoing message to this account's own swarm.
/// Result of one account-config sync.
struct AccountSyncResult {
    state: session_tui_account::AccountState,
    user_groups: Vec<UserGroupInfo>,
    /// New dumps for profile/contacts/read state/groups (None: keep old).
    dumps: [Option<Vec<u8>>; 4],
    /// Pending changes that are now stored on the swarm.
    applied: Vec<session_tui_account::AccountChange>,
}

/// Account config messages live for 30 days and are re-pushed on change.
const CONFIG_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;

struct SyncCopy {
    sent: bool,
    /// Hash of the copy in our swarm (needed to delete it on unsend).
    hash: Option<String>,
}

struct SentAttachments {
    timestamp_ms: u64,
    caption: String,
    /// (metadata, encrypted blob, preview) per attachment, in send order.
    files: Vec<(AttachmentMeta, Vec<u8>, Option<ImagePreview>)>,
    sync_copy: SyncCopy,
}

struct ImageViewer {
    title: String,
    protocol: StatefulProtocol,
    /// Attachment index inside the selected message.
    index: usize,
}

#[derive(Default)]
struct SyncBatch {
    /// First failed write; the batch then rolls back.
    error: Option<String>,
    /// Attachment files of deleted messages, removed only after COMMIT.
    deleted_files: Vec<std::path::PathBuf>,
}

struct LocalStore {
    /// Open sync batch (see [`LocalStore::begin_batch`]).
    batch: std::cell::RefCell<Option<SyncBatch>>,
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
                    sender TEXT NOT NULL DEFAULT '',
                    UNIQUE(peer_id, timestamp_ms, outgoing, sender)
                 );
                 CREATE TABLE IF NOT EXISTS seen_hashes (hash TEXT PRIMARY KEY);
                 CREATE TABLE IF NOT EXISTS sync_state (id INTEGER PRIMARY KEY CHECK(id = 1), last_hash TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS node_cursors (key TEXT PRIMARY KEY, hash TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    kind TEXT NOT NULL,
                    peer TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL,
                    payload BLOB NOT NULL DEFAULT x'',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_ms INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT NOT NULL DEFAULT ''
                 );
                 CREATE TABLE IF NOT EXISTS pending_receipts (
                    peer TEXT NOT NULL,
                    timestamp_ms INTEGER NOT NULL,
                    status INTEGER NOT NULL,
                    received_ms INTEGER NOT NULL,
                    PRIMARY KEY(peer, timestamp_ms)
                 );
                 CREATE UNIQUE INDEX IF NOT EXISTS outbox_once ON outbox(kind, peer, timestamp_ms)
                    WHERE kind != 'read_receipt';
                 CREATE TABLE IF NOT EXISTS profiles (session_id TEXT PRIMARY KEY, display_name TEXT NOT NULL);
                 CREATE TABLE IF NOT EXISTS config_dumps (slot INTEGER PRIMARY KEY, dump BLOB NOT NULL);
                 CREATE TABLE IF NOT EXISTS group_invites (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    auth_data BLOB NOT NULL,
                    inviter TEXT NOT NULL,
                    joined INTEGER NOT NULL DEFAULT 0,
                    responded INTEGER NOT NULL DEFAULT 0
                 );",
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
        let store = Self {
            connection,
            key,
            batch: std::cell::RefCell::new(None),
        };
        store.add_sender_to_message_key()?;
        Ok(store)
    }

    /// Older databases keyed messages on (chat, timestamp, outgoing), so two
    /// group members posting in the same millisecond collided and one was
    /// silently dropped. Rebuild the table with the author in the key (read
    /// from each encrypted row) once.
    fn add_sender_to_message_key(&self) -> Result<(), String> {
        let table_sql: String = self
            .connection
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'messages'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        if table_sql.contains("sender") {
            return Ok(());
        }
        debug_log("history.migrate", "step=message_sender_key");
        let migrate = || -> Result<(), String> {
            self.connection
                .execute_batch(
                    "BEGIN IMMEDIATE;
                     CREATE TABLE messages_v2 (
                        peer_id TEXT NOT NULL,
                        timestamp_ms INTEGER NOT NULL,
                        outgoing INTEGER NOT NULL,
                        body BLOB NOT NULL,
                        receipt_status INTEGER NOT NULL DEFAULT 0,
                        is_read INTEGER NOT NULL DEFAULT 1,
                        sender TEXT NOT NULL DEFAULT '',
                        UNIQUE(peer_id, timestamp_ms, outgoing, sender)
                     );",
                )
                .map_err(|e| e.to_string())?;
            let mut select = self
                .connection
                .prepare("SELECT peer_id, timestamp_ms, outgoing, body, receipt_status, is_read FROM messages")
                .map_err(|e| e.to_string())?;
            let mut rows = select.query([]).map_err(|e| e.to_string())?;
            while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                let body: Vec<u8> = row.get(3).map_err(|e| e.to_string())?;
                let sender = self
                    .decrypt_body(&body)
                    .ok()
                    .and_then(|plain| {
                        let json = plain.strip_prefix(STORED_MESSAGE_PREFIX)?.to_owned();
                        serde_json::from_str::<StoredMessage>(&json).ok()?.sender
                    })
                    .unwrap_or_default();
                self.connection
                    .execute(
                        "INSERT OR IGNORE INTO messages_v2(peer_id, timestamp_ms, outgoing, body, receipt_status, is_read, sender)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            row.get::<_, String>(0).map_err(|e| e.to_string())?,
                            row.get::<_, i64>(1).map_err(|e| e.to_string())?,
                            row.get::<_, bool>(2).map_err(|e| e.to_string())?,
                            body,
                            row.get::<_, u8>(4).map_err(|e| e.to_string())?,
                            row.get::<_, bool>(5).map_err(|e| e.to_string())?,
                            sender
                        ],
                    )
                    .map_err(|e| e.to_string())?;
            }
            drop(rows);
            drop(select);
            self.connection
                .execute_batch(
                    "DROP TABLE messages;
                     ALTER TABLE messages_v2 RENAME TO messages;
                     COMMIT;",
                )
                .map_err(|e| e.to_string())
        };
        migrate().inspect_err(|_| {
            let _ = self.connection.execute_batch("ROLLBACK");
        })
    }

    fn encrypt_body(&self, body: &str) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let nonce = random::random(24);
        let encrypted = cipher
            .encrypt(XNonce::from_slice(&nonce), body.as_bytes())
            .map_err(|_| "could not encrypt local message".to_string())?;
        Ok([nonce, encrypted].concat())
    }

    /// Run a write. Inside a sync batch, any failure is remembered so the
    /// whole batch rolls back, even where the caller ignores the result.
    fn exec<P: rusqlite::Params>(&self, sql: &str, params: P) -> rusqlite::Result<usize> {
        let result = self.connection.execute(sql, params);
        if let Err(error) = &result
            && let Some(batch) = self.batch.borrow_mut().as_mut()
        {
            batch.error.get_or_insert_with(|| error.to_string());
        }
        result
    }

    /// Start a sync batch: one transaction for everything a sync writes.
    fn begin_batch(&self) -> Result<(), String> {
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(|e| e.to_string())?;
        *self.batch.borrow_mut() = Some(SyncBatch::default());
        Ok(())
    }

    /// File to delete once the batch commits (kept if it rolls back).
    fn delete_file_after_commit(&self, path: std::path::PathBuf) {
        match self.batch.borrow_mut().as_mut() {
            Some(batch) => batch.deleted_files.push(path),
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Commit the batch if every write succeeded, else roll it back.
    fn end_batch(&self) -> Result<(), String> {
        let batch = self.batch.borrow_mut().take().unwrap_or_default();
        let result = match batch.error {
            Some(error) => Err(error),
            None => self.connection.execute_batch("COMMIT").map_err(|e| e.to_string()),
        };
        match result {
            Ok(()) => {
                for path in batch.deleted_files {
                    let _ = std::fs::remove_file(path);
                }
                Ok(())
            }
            Err(error) => {
                let _ = self.connection.execute_batch("ROLLBACK");
                Err(error)
            }
        }
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
        let mut resave = Vec::new();
        for row in rows {
            let (peer, timestamp_ms, outgoing, encrypted, receipt_status, is_read) =
                row.map_err(|e| e.to_string())?;
            let stored = self.decrypt_body(&encrypted)?;
            let mut message = Message::new(String::new(), timestamp_ms, outgoing);
            message.receipt_status = receipt_status;
            message.is_read = is_read;
            // Rewrite rows still using the old, bulky thumbnail format.
            let mut needs_resave = false;
            if let Some(json) = stored.strip_prefix(STORED_MESSAGE_PREFIX) {
                needs_resave |= json.contains("{\"rows\":");
                let payload: StoredMessage =
                    serde_json::from_str(json).map_err(|e| e.to_string())?;
                message.body = payload.body;
                message.sender = payload.sender;
                message.quote = payload.quote;
                message.reactions = payload.reactions;
                message.expiration = payload.expiration;
                message.expires_at = payload.expires_at;
                message.links = payload.links;
                message.system = payload.system;
                message.swarm_hashes = payload.swarm_hashes;
                message.server_hash = payload.server_hash;
                message.swarm_expiry = payload.swarm_expiry;
                message.send_state = payload.send_state;
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
            // Previews stored by older versions were larger; shrink them.
            let mut shrunk = false;
            for preview in message.image_previews.iter_mut().flatten() {
                let before = preview.rows.len();
                *preview = session_tui_media::shrink_preview(std::mem::take(preview));
                shrunk |= preview.rows.len() != before;
            }
            needs_resave |= shrunk;
            // Older builds cached attachments under the chat alone (and, for
            // a while, chat + author). Move a file over only if it is this
            // message's (its digest and MAC check out), so an old collision
            // between messages with the same timestamp can't hand one
            // message's file to another.
            if let Some(root) = root.as_deref() {
                let mut old_owners = vec![peer.clone()];
                if let Some(sender) = message.sender.as_deref() {
                    old_owners.push(format!("{peer}:{sender}"));
                }
                for (index, meta) in message.attachments.iter().enumerate() {
                    let new_path = session_tui_media::attachment_blob_path(
                        root,
                        &message_blob_owner(&peer, &message),
                        timestamp_ms,
                        index,
                    );
                    if new_path.exists() {
                        continue;
                    }
                    for old_owner in &old_owners {
                    let old_path =
                        session_tui_media::attachment_blob_path(root, old_owner, timestamp_ms, index);
                    if !old_path.exists() {
                        continue;
                    }
                    let belongs = std::fs::read(&old_path).is_ok_and(|blob| {
                        session_tui_media::decrypt_attachment(
                            &blob,
                            &meta.key,
                            &meta.digest,
                            meta.deterministic,
                        )
                        .is_ok()
                    });
                    if belongs {
                        let _ = std::fs::rename(&old_path, &new_path);
                        break;
                    }
                    }
                }
            }
            // Rebuild missing previews from cached image blobs.
            for (index, meta) in message.attachments.iter().enumerate() {
                if message.image_previews[index].is_some()
                    || !meta.content_type.starts_with("image/")
                {
                    continue;
                }
                let Some(root) = root.as_deref() else { break };
                let path = session_tui_media::attachment_blob_path(
                    root,
                    &message_blob_owner(&peer, &message),
                    timestamp_ms,
                    index,
                );
                let Ok(blob) = std::fs::read(path) else { continue };
                // Saved, so this decrypt + decode happens once, not every start.
                // An image that can't be decoded gets an empty preview.
                message.image_previews[index] = Some(
                    session_tui_media::decrypt_attachment(
                        &blob,
                        &meta.key,
                        &meta.digest,
                        meta.deterministic,
                    )
                    .ok()
                    .and_then(|plaintext| session_tui_media::image_preview(&plaintext))
                    .unwrap_or_default(),
                );
                needs_resave = true;
            }
            if needs_resave {
                resave.push((peer.clone(), message.clone()));
            }
            let index = app.ensure_contact(&peer);
            let convo = &mut app.conversations[index];
            convo.preview = message.preview_text();
            convo.messages.push(message);
            convo.selected_message = convo.messages.len() - 1;
        }
        drop(statement);

        // One transaction: a first start after an upgrade may rewrite many rows.
        let _ = self.connection.execute_batch("BEGIN");
        for (peer, message) in &resave {
            let _ = self.update_message(peer, message);
        }
        let _ = self.connection.execute_batch("COMMIT");
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
        let mut statement = self
            .connection
            .prepare("SELECT key, value FROM settings WHERE key LIKE 'disappearing:%'")
            .map_err(|e| e.to_string())?;
        let settings = statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .map_err(|e| e.to_string())?;
        for setting in settings {
            let (key, value) = setting.map_err(|e| e.to_string())?;
            if let (Some(peer), Ok(expiration)) = (
                key.strip_prefix("disappearing:"),
                serde_json::from_str::<Expiration>(&value),
            ) && let Some(conversation) = app.conversations.iter_mut().find(|c| c.id == peer)
            {
                conversation.disappearing = Some(expiration);
            }
        }
        drop(statement);
        app.bell = self.get_setting("bell").as_deref() != Some("off");
        if let Some(width) = self
            .get_setting("sidebar_width")
            .and_then(|w| w.parse().ok())
        {
            app.sidebar_width = width;
        }
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

    /// Saved account config state: profile, contacts, read state, groups.
    fn account_dumps(&self) -> [Option<Vec<u8>>; 4] {
        std::array::from_fn(|slot| {
            self.connection
                .query_row(
                    "SELECT dump FROM config_dumps WHERE slot = ?1",
                    [slot as i64],
                    |row| row.get(0),
                )
                .optional()
                .ok()
                .flatten()
        })
    }

    fn save_account_dump(&self, slot: usize, dump: &[u8]) -> Result<(), String> {
        self.exec(
            "INSERT INTO config_dumps(slot, dump) VALUES (?1, ?2) ON CONFLICT(slot) DO UPDATE SET dump=excluded.dump",
            params![slot as i64, dump],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn pending_account_changes(&self) -> Vec<session_tui_account::AccountChange> {
        self.get_setting("account_changes")
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    fn set_pending_account_changes(
        &self,
        changes: &[session_tui_account::AccountChange],
    ) -> Result<(), String> {
        self.set_setting(
            "account_changes",
            &serde_json::to_string(changes).map_err(|e| e.to_string())?,
        )
    }

    /// Queue a change for the account config; it is pushed on the next sync.
    fn queue_account_change(&self, change: session_tui_account::AccountChange) {
        let mut pending = self.pending_account_changes();
        session_tui_account::AccountChange::queue(&mut pending, change);
        if let Err(error) = self.set_pending_account_changes(&pending) {
            debug_log("account.queue_failed", &error);
        }
    }

    fn get_setting(&self, key: &str) -> Option<String> {
        self.connection
            .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| row.get(0))
            .optional()
            .ok()
            .flatten()
    }

    fn set_setting(&self, key: &str, value: &str) -> Result<(), String> {
        self.exec(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_profile_name(&self, name: &str) -> Result<(), String> {
        self.exec(
            "INSERT INTO settings(key, value) VALUES ('profile_name', ?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_contact_name(&self, id: &str, name: &str) -> Result<(), String> {
        self.exec(
            "INSERT INTO contacts(session_id, display_name) VALUES (?1, ?2) ON CONFLICT(session_id) DO UPDATE SET display_name=excluded.display_name",
            params![id, name],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_contact(&self, id: &str) -> Result<(), String> {
        self.exec(
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
            quote: message.quote.clone(),
            reactions: message.reactions.clone(),
            expiration: message.expiration,
            expires_at: message.expires_at,
            links: message.links.clone(),
            system: message.system,
            swarm_hashes: message.swarm_hashes.clone(),
            server_hash: message.server_hash.clone(),
            swarm_expiry: message.swarm_expiry,
            send_state: message.send_state,
        })
        .map_err(|e| e.to_string())?;
        self.encrypt_body(&format!("{STORED_MESSAGE_PREFIX}{payload}"))
    }

    /// Store a message we just created; fails if that key already exists.
    fn insert_new_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        let body = self.encrypted_payload(message)?;
        self.exec(
            "INSERT INTO messages(peer_id, timestamp_ms, outgoing, body, receipt_status, is_read, sender) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![peer, message.timestamp_ms as i64, message.outgoing, body, message.receipt_status, message.is_read, sender_key(message)],
        ).map_err(|e| e.to_string())?;
        self.save_contact(peer)
    }

    fn save_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        let body = self.encrypted_payload(message)?;
        self.exec(
            "INSERT OR IGNORE INTO messages(peer_id, timestamp_ms, outgoing, body, receipt_status, is_read, sender) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![peer, message.timestamp_ms as i64, message.outgoing, body, message.receipt_status, message.is_read, sender_key(message)],
        ).map_err(|e| e.to_string())?;
        self.save_contact(peer)
    }

    /// Rewrite the stored payload (e.g. after an attachment preview arrives).
    fn update_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        let body = self.encrypted_payload(message)?;
        self.exec(
            "UPDATE messages SET body = ?4 WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = ?3 AND sender = ?5",
            params![peer, message.timestamp_ms as i64, message.outgoing, body, sender_key(message)],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_display_name(&self, id: &str, name: &str) -> Result<(), String> {
        self.exec(
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
        write_attachment_blob(peer, timestamp, index, bytes)
    }

    fn save_invite(&self, group: &LocalGroup, inviter: &str) -> Result<(), String> {
        self.exec(
            "INSERT INTO group_invites(group_id, name, auth_data, inviter) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id) DO UPDATE SET name=excluded.name, auth_data=excluded.auth_data, inviter=excluded.inviter",
            params![group.id, group.name, group.auth_data, inviter],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Invites (`joined = false`) or joined groups (`joined = true`), with
    /// the inviter's Session ID.
    fn local_groups(&self, joined: bool) -> Result<Vec<(LocalGroup, String)>, String> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT group_id, name, auth_data, responded, inviter FROM group_invites WHERE joined = ?1 ORDER BY rowid",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([joined], |row| {
                Ok((
                    LocalGroup {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        auth_data: row.get(2)?,
                        responded: row.get(3)?,
                    },
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<_, _>>().map_err(|e| e.to_string())
    }

    fn set_group_joined(&self, group_id: &str) -> Result<(), String> {
        self.exec("UPDATE group_invites SET joined = 1 WHERE group_id = ?1", [group_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn set_group_responded(&self, group_id: &str) -> Result<(), String> {
        self.exec("UPDATE group_invites SET responded = 1 WHERE group_id = ?1", [group_id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn set_disappearing(&self, peer: &str, setting: Option<Expiration>) -> Result<(), String> {
        let key = format!("disappearing:{peer}");
        match setting {
            None => self.exec("DELETE FROM settings WHERE key = ?1", [key])
                .map(|_| ()),
            Some(setting) => self.exec(
                    "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    params![key, serde_json::to_string(&setting).unwrap_or_default()],
                )
                .map(|_| ()),
        }
        .map_err(|e| e.to_string())
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
        self.exec(
            "INSERT INTO settings(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![format!("group_cursor:{group}"), hash],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn update_receipt_status(&self, peer: &str, timestamp: u64, status: u8) -> Result<(), String> {
        self.exec(
            "UPDATE messages SET receipt_status = MAX(receipt_status, ?3) WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = 1 AND sender = ''",
            params![peer, timestamp as i64, status],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_message_read(&self, peer: &str, message: &Message) -> Result<(), String> {
        self.exec(
            "UPDATE messages SET is_read = 1 WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = 0 AND sender = ?3",
            params![peer, message.timestamp_ms as i64, sender_key(message)],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn mark_seen(&self, hash: &str) -> Result<bool, String> {
        let inserted = self.exec(
                "INSERT OR IGNORE INTO seen_hashes(hash) VALUES (?1)",
                [hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(inserted > 0)
    }

    /// Queue network work that must survive a restart (see [`OutboxKind`]).
    fn outbox_add(&self, kind: OutboxKind, peer: &str, timestamp_ms: u64, payload: &[u8]) -> Result<(), String> {
        // Each step of a message is queued once (unique index); queuing it
        // again is a no-op.
        self.exec(
            "INSERT OR IGNORE INTO outbox(kind, peer, timestamp_ms, payload) VALUES (?1, ?2, ?3, ?4)",
            params![kind.as_str(), peer, timestamp_ms as i64, payload],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Entries due at `now_ms`, oldest first.
    fn outbox_due(&self, now_ms: u64) -> Vec<OutboxEntry> {
        let Ok(mut statement) = self.connection.prepare(
            "SELECT id, kind, peer, timestamp_ms, payload, attempts FROM outbox
             WHERE next_attempt_ms <= ?1 ORDER BY id LIMIT 32",
        ) else {
            return Vec::new();
        };
        statement
            .query_map([now_ms as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, u32>(5)?,
                ))
            })
            .map(|rows| {
                rows.flatten()
                    .filter_map(|(id, kind, peer, timestamp_ms, payload, attempts)| {
                        Some(OutboxEntry {
                            id,
                            kind: OutboxKind::parse(&kind)?,
                            peer,
                            timestamp_ms: timestamp_ms as u64,
                            payload,
                            attempts,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn outbox_done(&self, id: i64) -> Result<(), String> {
        self.exec("DELETE FROM outbox WHERE id = ?1", [id])
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn outbox_failed(&self, id: i64, attempts: u32, next_attempt_ms: u64, error: &str) -> Result<(), String> {
        self.exec(
            "UPDATE outbox SET attempts = ?2, next_attempt_ms = ?3, last_error = ?4 WHERE id = ?1",
            params![id, attempts, next_attempt_ms.min(i64::MAX as u64) as i64, error],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// `/retry`: send this message's queued work now, with a fresh budget.
    /// Returns false when nothing was queued for it.
    fn outbox_retry_now(&self, peer: &str, timestamp_ms: u64) -> Result<bool, String> {
        let changed = self
            .exec(
                "UPDATE outbox SET attempts = 0, next_attempt_ms = 0
                 WHERE peer = ?1 AND timestamp_ms = ?2 AND kind IN ('text', 'sync_copy')",
                params![peer, timestamp_ms as i64],
            )
            .map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    /// Keep a receipt whose message hasn't arrived yet (highest status wins).
    fn save_pending_receipt(&self, peer: &str, timestamp_ms: u64, status: u8) -> Result<(), String> {
        self.exec(
            "INSERT INTO pending_receipts(peer, timestamp_ms, status, received_ms) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer, timestamp_ms) DO UPDATE SET status = MAX(status, excluded.status)",
            params![peer, timestamp_ms as i64, status, now_ms() as i64],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// The waiting receipt status for this message, removed once applied.
    fn take_pending_receipt(&self, peer: &str, timestamp_ms: u64) -> Option<u8> {
        let status: u8 = self
            .connection
            .query_row(
                "SELECT status FROM pending_receipts WHERE peer = ?1 AND timestamp_ms = ?2",
                params![peer, timestamp_ms as i64],
                |row| row.get(0),
            )
            .ok()?;
        let _ = self.exec(
            "DELETE FROM pending_receipts WHERE peer = ?1 AND timestamp_ms = ?2",
            params![peer, timestamp_ms as i64],
        );
        Some(status)
    }

    /// Receipts whose message never arrived are kept for 14 days.
    fn prune_pending_receipts(&self) {
        let _ = self.exec(
            "DELETE FROM pending_receipts WHERE received_ms < ?1",
            [now_ms().saturating_sub(14 * 24 * 3_600_000) as i64],
        );
    }

    /// Per-node message cursors, see `SessionClient::node_cursors`.
    fn node_cursors(&self) -> HashMap<String, String> {
        let Ok(mut statement) = self.connection.prepare("SELECT key, hash FROM node_cursors") else {
            return HashMap::new();
        };
        statement
            .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    fn set_node_cursor(&self, key: &str, hash: &str) -> Result<(), String> {
        self.exec(
            "INSERT INTO node_cursors(key, hash) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET hash = excluded.hash",
            params![key, hash],
        )
        .map_err(|e| e.to_string())?;
        Ok(())
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
        self.exec(
                "INSERT INTO sync_state(id, last_hash) VALUES (1, ?1) ON CONFLICT(id) DO UPDATE SET last_hash = excluded.last_hash",
                [hash],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn delete_empty_contact(&self, peer: &str) -> Result<(), String> {
        self.exec(
            "DELETE FROM contacts WHERE session_id = ?1 AND NOT EXISTS (SELECT 1 FROM messages WHERE peer_id = ?1)",
            [peer],
        ).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Delete one stored message and its cached attachment files.
    fn delete_message(&self, peer: &str, message: &Message) -> Result<(), String> {
        // A deleted message is never sent, synced or expired later.
        let kinds = if message.outgoing {
            "('text', 'sync_copy')"
        } else {
            "('expire_read', 'fetch_expiry')"
        };
        self.exec(
            &format!("DELETE FROM outbox WHERE peer = ?1 AND timestamp_ms = ?2 AND kind IN {kinds}"),
            params![peer, message.timestamp_ms as i64],
        )
        .map_err(|e| e.to_string())?;
        self.exec(
                "DELETE FROM messages WHERE peer_id = ?1 AND timestamp_ms = ?2 AND outgoing = ?3 AND sender = ?4",
                params![peer, message.timestamp_ms as i64, message.outgoing, sender_key(message)],
            )
            .map_err(|e| e.to_string())?;
        if let Ok(root) = session_data_dir() {
            for index in 0..message.attachments.len() {
                self.delete_file_after_commit(session_tui_media::attachment_blob_path(
                    &root,
                    &message_blob_owner(peer, message),
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
            poll_nodes: Mutex::new(HashMap::new()),
            node_cursors: Mutex::new(HashMap::new()),
            pending_cursors: Mutex::new(HashMap::new()),
        })
    }

    /// pubkey/namespace/timestamp/signature (+ subaccount fields for
    /// members) for an authenticated request to a group swarm.
    fn group_auth_params(
        &self,
        auth: &GroupAuth,
        group_id: &str,
        method: &str,
        namespace: i32,
        timestamp_ms: u64,
    ) -> Result<serde_json::Map<String, Value>, String> {
        let mut params = serde_json::Map::new();
        params.insert("pubkey".to_owned(), Value::String(group_id.to_owned()));
        params.insert("namespace".to_owned(), Value::from(namespace));
        params.insert("timestamp".to_owned(), Value::from(timestamp_ms));
        match auth {
            GroupAuth::Admin { secret_key, .. } => {
                let signature = libsession::network::auth::sign_request_b64(
                    method,
                    namespace,
                    timestamp_ms,
                    secret_key,
                )
                .map_err(|error| error.to_string())?;
                params.insert("signature".to_owned(), Value::String(signature));
            }
            GroupAuth::Member { auth_data } => {
                let message =
                    libsession::network::auth::canonical_sign_string(method, namespace, timestamp_ms);
                let signed = session_tui_group::subaccount_sign(
                    &self.identity.ed_secret,
                    auth_data,
                    message.as_bytes(),
                )?;
                params.insert("subaccount".to_owned(), Value::String(signed.subaccount));
                params.insert(
                    "subaccount_sig".to_owned(),
                    Value::String(signed.subaccount_sig),
                );
                params.insert("signature".to_owned(), Value::String(signed.signature));
            }
        }
        Ok(params)
    }

    /// The swarm member to poll for `pubkey`: the same one as last time
    /// while it is still in the swarm, else a random member.
    async fn poll_node(&self, pubkey: &str) -> Result<ServiceNode, String> {
        let swarm = self
            .network
            .swarm_nodes(pubkey)
            .await
            .map_err(|e| e.to_string())?;
        let mut chosen = self.poll_nodes.lock().map_err(|_| "poll node lock")?;
        if let Some(node) = chosen.get(pubkey)
            && swarm.iter().any(|n| n.ed25519_pubkey == node.ed25519_pubkey)
        {
            return Ok(node.clone());
        }
        let node = swarm[rand::random::<u32>() as usize % swarm.len()].clone();
        chosen.insert(pubkey.to_owned(), node.clone());
        Ok(node)
    }

    /// The polled node failed or said "wrong swarm" (421): pick again next time.
    async fn drop_poll_node(&self, pubkey: &str) {
        if let Ok(mut chosen) = self.poll_nodes.lock() {
            chosen.remove(pubkey);
        }
        self.network.forget_swarm(pubkey).await;
    }

    fn cursor_for(&self, key: &str) -> Option<String> {
        self.node_cursors.lock().ok()?.get(key).cloned()
    }

    /// Record a candidate cursor for the sync in progress (see
    /// `pending_cursors`); `cursor_for` keeps returning the committed one.
    fn set_cursor(&self, key: String, hash: String) {
        if let Ok(mut cursors) = self.pending_cursors.lock() {
            cursors.insert(key, hash);
        }
    }

    /// The candidate cursors of this sync, handed to `finish_sync` with its
    /// messages.
    fn take_pending_cursors(&self) -> Vec<(String, String)> {
        self.pending_cursors
            .lock()
            .map(|mut c| c.drain().collect())
            .unwrap_or_default()
    }

    async fn retrieve_namespace_raw(
        &self,
        pubkey: &str,
        namespace: i32,
        auth: &SwarmAuth<'_>,
    ) -> Result<Vec<(String, Vec<u8>)>, String> {
        self.retrieve_namespace_since(pubkey, namespace, auth, None, false)
            .await
            .map(|(messages, _)| messages)
    }

    /// Retrieve every message after `cursor`, following the swarm's `more`
    /// flag. Returns the messages and the hash of the newest one seen.
    async fn retrieve_namespace_since(
        &self,
        pubkey: &str,
        namespace: i32,
        auth: &SwarmAuth<'_>,
        cursor: Option<&str>,
        per_node: bool,
    ) -> Result<(Vec<(String, Vec<u8>)>, Option<String>), String> {
        // `per_node`: poll one sticky node with its own cursor; `cursor` is
        // only the fallback for a node we have never polled.
        let (node, key) = if per_node {
            let node = self.poll_node(pubkey).await?;
            let key = node_cursor_key(pubkey, namespace, &node);
            (Some(node), Some(key))
        } else {
            (None, None)
        };
        let mut all = Vec::new();
        let mut last_hash = key
            .as_deref()
            .and_then(|key| self.cursor_for(key))
            .or_else(|| cursor.map(str::to_owned));
        for _ in 0..MAX_RETRIEVE_PAGES {
            let page = self
                .retrieve_namespace_page(pubkey, namespace, auth, last_hash.as_deref(), node.as_ref())
                .await;
            let (page, more) = match page {
                Ok(page) => page,
                Err(error) => {
                    if per_node {
                        self.drop_poll_node(pubkey).await;
                    }
                    return Err(error);
                }
            };
            let empty = page.is_empty();
            if let Some((hash, _)) = page.last() {
                last_hash = Some(hash.clone());
            }
            all.extend(page);
            if !more || empty {
                break;
            }
        }
        if let (Some(key), Some(hash)) = (key, last_hash.clone()) {
            self.set_cursor(key, hash);
        }
        Ok((all, last_hash))
    }

    async fn retrieve_namespace_page(
        &self,
        pubkey: &str,
        namespace: i32,
        auth: &SwarmAuth<'_>,
        last_hash: Option<&str>,
        node: Option<&ServiceNode>,
    ) -> Result<(Vec<(String, Vec<u8>)>, bool), String> {
        let pubkey_ed25519 = hex::encode(self.identity.ed_public);
        let response = if let SwarmAuth::Group(group_auth) = auth {
            // Group namespace requests carry pubkey, namespace, timestamp and
            // signature (plus subaccount fields for members), but not the
            // user-request-only pubkey_ed25519 field.
            let mut params =
                self.group_auth_params(group_auth, pubkey, "retrieve", namespace, now_ms())?;
            params.insert("max_size".to_owned(), Value::from(1_000_000u32));
            if let Some(last_hash) = last_hash {
                params.insert("last_hash".to_owned(), Value::String(last_hash.to_owned()));
            }
            match node {
                Some(node) => self.network.send_rpc_to(node, "retrieve", Value::Object(params)).await,
                None => self.network.send_rpc("retrieve", Value::Object(params), Some(pubkey)).await,
            }
            .map_err(|error| error.to_string())?
        } else {
            let params = RetrieveParams {
                pubkey,
                pubkey_ed25519: &pubkey_ed25519,
                namespace,
                timestamp_ms: now_ms(),
                last_hash,
                max_size: Some(1_000_000),
                signing_key: &self.identity.ed_secret,
            };
            match node {
                Some(node) => self.network.send_retrieve_to(node, &params).await,
                None => self.network.send_retrieve(&params).await,
            }
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

    async fn discover_groups(
        &self,
        local_groups: &[LocalGroup],
        user_groups: Vec<UserGroupInfo>,
    ) -> Result<Vec<DiscoveredGroup>, String> {
        debug_log(
            "group.user_config.parsed",
            &format!("groups={}", user_groups.len()),
        );
        // Groups joined through an invite in this client are not in the
        // account's UserGroups config, so they are added from local storage.
        let mut candidates: Vec<(String, String, Vec<u8>, Vec<u8>)> = Vec::new();
        for group in user_groups {
            if group.removed_status != 0 {
                debug_log(
                    "group.config.skipped",
                    &format!("reason=removed status={}", group.removed_status),
                );
                continue;
            }
            if group.id.len() != 66 || !group.id.starts_with("03") {
                continue;
            }
            candidates.push((group.id, group.base.name, group.secretkey, group.auth_data));
        }
        for local in local_groups {
            if !candidates.iter().any(|(id, ..)| id == &local.id) {
                candidates.push((
                    local.id.clone(),
                    local.name.clone(),
                    Vec::new(),
                    local.auth_data.clone(),
                ));
            }
        }
        let mut runtime_groups = HashMap::new();
        let mut discovered_groups = Vec::new();
        for (id, config_name, admin_seed, auth_data) in candidates {
            let Ok(public_key) = <[u8; 32]>::try_from(
                hex::decode(&id[2..]).unwrap_or_default().as_slice(),
            ) else {
                continue;
            };
            let mut discovered = DiscoveredGroup {
                id: id.clone(),
                name: if config_name.is_empty() {
                    format!("Group {}", &id[2..10])
                } else {
                    config_name.clone()
                },
                can_write: false,
            };
            let auth = if admin_seed.len() == 32 {
                let (derived_pk, secret_key) =
                    ed25519::ed25519_key_pair_from_seed(&admin_seed).map_err(|e| e.to_string())?;
                if derived_pk != public_key {
                    debug_log("group.config.invalid", "admin_seed_does_not_match_group_id=true");
                    discovered_groups.push(discovered);
                    continue;
                }
                GroupAuth::Admin {
                    seed: admin_seed.clone(),
                    secret_key: secret_key.to_vec(),
                }
            } else if session_tui_group::verify_subaccount(
                &public_key,
                &self.identity.ed_secret,
                &auth_data,
                false,
            ) {
                GroupAuth::Member { auth_data }
            } else {
                debug_log(
                    "group.config.no_access",
                    &format!(
                        "group_prefix={} seed_bytes={} auth_bytes={}",
                        &id[..8],
                        admin_seed.len(),
                        auth_data.len()
                    ),
                );
                discovered_groups.push(discovered);
                continue;
            };
            discovered.can_write = auth.can_write();
            let swarm_auth = SwarmAuth::Group(&auth);
            let key_messages = match self.retrieve_namespace_raw(&id, 12, &swarm_auth).await {
                Ok(messages) => messages,
                Err(error) => {
                    debug_log(
                        "group.keys.retrieve_failed",
                        &format!("group_prefix={} error={error}", &id[..8]),
                    );
                    discovered_groups.push(discovered);
                    continue;
                }
            };
            let key_message_count = key_messages.len();
            let mut keys: Vec<session_tui_group::GroupKey> = Vec::new();
            for (_, message) in &key_messages {
                for key in session_tui_group::decrypt_key_message(
                    message,
                    &public_key,
                    &self.identity.ed_secret,
                    auth.admin_seed(),
                ) {
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
            // Newest generation first: it is used for sending, the rest only
            // to decrypt older messages.
            keys.sort_by_key(|key| std::cmp::Reverse(key.generation));
            if keys.is_empty() {
                debug_log(
                    "group.keys.unavailable",
                    &format!(
                        "group_prefix={} member={} key_messages={key_message_count}",
                        &id[..8],
                        matches!(auth, GroupAuth::Member { .. })
                    ),
                );
                discovered_groups.push(discovered);
                continue;
            }

            let info_messages = match self.retrieve_namespace_raw(&id, 13, &swarm_auth).await {
                Ok(messages) => messages,
                Err(error) => {
                    debug_log(
                        "group.info.retrieve_failed",
                        &format!("group_prefix={} error={error}", &id[..8]),
                    );
                    Vec::new()
                }
            };
            let admin_secret = match &auth {
                GroupAuth::Admin { secret_key, .. } => Some(secret_key.as_slice()),
                GroupAuth::Member { .. } => None,
            };
            let mut info = ConfigBase::<SharedGroupInfo>::new_group(&public_key, admin_secret, None)?;
            for key in keys.iter().rev() {
                info.add_key(key.key, true);
            }
            let info_merge: Vec<(&str, &[u8])> = info_messages
                .iter()
                .map(|(hash, bytes)| (hash.as_str(), bytes.as_slice()))
                .collect();
            let _ = info.merge(&info_merge);
            if let Some(name) = info.config_type.name.clone().filter(|name| !name.is_empty()) {
                discovered.name = name;
            }
            debug_log(
                "group.config.runtime_ready",
                &format!(
                    "group_prefix={} member={} keys={}",
                    &id[..8],
                    matches!(auth, GroupAuth::Member { .. }),
                    keys.len()
                ),
            );
            discovered_groups.push(discovered);
            runtime_groups.insert(
                id.clone(),
                GroupRuntime {
                    id,
                    public_key,
                    auth,
                    keys: keys.into_iter().map(|key| key.key).collect(),
                },
            );
        }
        *self.groups.lock().map_err(|error| error.to_string())? = runtime_groups;
        Ok(discovered_groups)
    }

    /// Older Session clients wrapped config data in an envelope holding a
    /// `SharedConfigMessage` (kind 1 profile, 2 contacts, 3 read state,
    /// 4 groups); current ones store it raw.
    fn unwrap_shared_config(&self, wire: &[u8], kind: i32) -> Result<Vec<u8>, String> {
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
        if shared.kind != kind {
            return Err(format!(
                "shared config kind mismatch: expected {kind}, got {}",
                shared.kind
            ));
        }
        Ok(shared.data)
    }

    /// Fetch one user config namespace and merge it (raw, or legacy
    /// envelope-wrapped). Returns whether it is safe to push to it: we
    /// fetched it and either it is empty or we understood its contents.
    async fn merge_config_namespace<T: libsession::config::config_base::ConfigType>(
        &self,
        config: &mut ConfigBase<T>,
        namespace: i32,
        kind: i32,
    ) -> bool {
        let messages = match self
            .retrieve_namespace_raw(&self.identity.session_id, namespace, &SwarmAuth::User)
            .await
        {
            Ok(messages) => messages,
            Err(error) => {
                debug_log(
                    "account.fetch_failed",
                    &format!("namespace={namespace} error={error}"),
                );
                return false;
            }
        };
        let raw: Vec<(&str, &[u8])> = messages
            .iter()
            .map(|(hash, bytes)| (hash.as_str(), bytes.as_slice()))
            .collect();
        let mut good = config.merge(&raw).map(|hashes| hashes.len()).unwrap_or(0);
        if good < messages.len() {
            let unwrapped: Vec<(String, Vec<u8>)> = messages
                .iter()
                .filter_map(|(hash, wire)| {
                    let mut data = self.unwrap_shared_config(wire, kind).ok()?;
                    if let Ok(inner) = self.unwrap_shared_config(&data, kind) {
                        data = inner;
                    }
                    Some((hash.clone(), data))
                })
                .collect();
            if !unwrapped.is_empty() {
                let refs: Vec<(&str, &[u8])> = unwrapped
                    .iter()
                    .map(|(hash, bytes)| (hash.as_str(), bytes.as_slice()))
                    .collect();
                good += config.merge(&refs).map(|hashes| hashes.len()).unwrap_or(0);
            }
        }
        debug_log(
            "account.merged",
            &format!("namespace={namespace} messages={} understood={good}", messages.len()),
        );
        messages.is_empty() || good > 0
    }

    /// Push a dirty config to our swarm and confirm it. Returns false if the
    /// push failed (the caller then keeps the old dump and pending changes).
    async fn push_config_namespace<T: libsession::config::config_base::ConfigType>(
        &self,
        config: &mut ConfigBase<T>,
        namespace: i32,
    ) -> bool {
        if !config.needs_push() {
            return true;
        }
        let pushed = config.push();
        let pubkey_ed25519 = hex::encode(self.identity.ed_public);
        let mut last_hash = None;
        for message in &pushed.messages {
            let timestamp_ms = now_ms();
            let encoded = STANDARD.encode(message);
            let response = self
                .network
                .send_store(&StoreParams {
                    pubkey: &self.identity.session_id,
                    pubkey_ed25519: Some(&pubkey_ed25519),
                    namespace,
                    timestamp_ms,
                    ttl_ms: CONFIG_TTL_MS,
                    data_base64: &encoded,
                    signing_key: Some(&self.identity.ed_secret),
                })
                .await;
            match response {
                Ok(response) if response.status_code == 200 => {
                    last_hash = response
                        .body
                        .as_deref()
                        .and_then(|body| serde_json::from_str::<Value>(body).ok())
                        .as_ref()
                        .and_then(find_message_hash);
                }
                Ok(response) => {
                    debug_log(
                        "account.push_failed",
                        &format!("namespace={namespace} http_status={}", response.status_code),
                    );
                    return false;
                }
                Err(error) => {
                    debug_log(
                        "account.push_failed",
                        &format!("namespace={namespace} error={error}"),
                    );
                    return false;
                }
            }
        }
        let Some(hash) = last_hash else {
            debug_log("account.push_failed", &format!("namespace={namespace} reason=no_hash"));
            return false;
        };
        config.confirm_pushed(pushed.seqno, &hash);
        debug_log(
            "account.pushed",
            &format!("namespace={namespace} seqno={}", pushed.seqno),
        );
        if let Err(error) = self.delete_own_messages(&pushed.obsolete_hashes).await {
            debug_log("account.obsolete_delete_failed", &error);
        }
        true
    }

    /// Merge the account's shared config from the swarm, apply our pending
    /// local changes and push them.
    async fn sync_account(
        &self,
        dumps: [Option<Vec<u8>>; 4],
        changes: Vec<session_tui_account::AccountChange>,
    ) -> Result<AccountSyncResult, String> {
        use session_tui_account::AccountChange;
        let mut configs = session_tui_account::AccountConfigs::new(&self.identity.ed_secret, &dumps)?;
        let safe = [
            self.merge_config_namespace(&mut configs.profile, 2, 1).await,
            self.merge_config_namespace(&mut configs.contacts, 3, 2).await,
            self.merge_config_namespace(&mut configs.convos, 4, 3).await,
            self.merge_config_namespace(&mut configs.groups, 5, 4).await,
        ];
        let slot = |change: &AccountChange| match change {
            AccountChange::ProfileName(_) => 0,
            AccountChange::ApproveContact { .. }
            | AccountChange::SetBlocked { .. }
            | AccountChange::ContactExpiry { .. }
            | AccountChange::HideContact { .. }
            | AccountChange::RemoveContact { .. } => 1,
            AccountChange::ReadUpTo { .. } => 2,
            AccountChange::JoinGroup { .. } => 3,
        };
        let mut attempted = Vec::new();
        for change in changes {
            if safe[slot(&change)] {
                configs.apply(&change);
                attempted.push(change);
            }
        }
        let pushed = [
            safe[0] && self.push_config_namespace(&mut configs.profile, 2).await,
            safe[1] && self.push_config_namespace(&mut configs.contacts, 3).await,
            safe[2] && self.push_config_namespace(&mut configs.convos, 4).await,
            safe[3] && self.push_config_namespace(&mut configs.groups, 5).await,
        ];
        let applied = attempted
            .into_iter()
            .filter(|change| pushed[slot(change)])
            .collect();
        let state = configs.state();
        let user_groups = configs.groups.get().iter_groups().cloned().collect();
        let all_dumps = configs.dumps();
        // Keep the previous dump where we could not push: the change is
        // re-applied (and re-pushed) next time.
        let dumps = std::array::from_fn(|i| pushed[i].then(|| all_dumps[i].clone()));
        Ok(AccountSyncResult {
            state,
            user_groups,
            dumps,
            applied,
        })
    }

    async fn retrieve_group_messages(
        &self,
        group: &GroupRuntime,
        cursor: Option<&str>,
    ) -> Result<(Vec<IncomingMessage>, Option<String>), String> {
        let (raw_messages, last_hash) = self
            .retrieve_namespace_since(&group.id, 11, &SwarmAuth::Group(&group.auth), cursor, true)
            .await?;
        let key_refs: Vec<&[u8]> = group.keys.iter().map(|key| key.as_slice()).collect();
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
            if let Some(message) = parse_content(
                &self.identity.session_id,
                hash,
                sender_id,
                group.id.clone(),
                decoded.envelope.timestamp,
                content,
            ) {
                incoming.push(message);
            }
        }
        Ok((incoming, last_hash))
    }

    /// Send a DataMessage (text, reply, reaction, timer update…) with the
    /// chat's disappearing setting, plus the linked-device sync copy.
    /// Returns whether the sync copy was stored.
    async fn send_data_message(
        &self,
        recipient_id: &str,
        data_message: DataMessage,
        expiration: Option<Expiration>,
    ) -> Result<SyncCopy, String> {
        let timestamp_ms = data_message.timestamp.ok_or("message has no timestamp")?;
        let content = Content {
            data_message: Some(data_message.clone()),
            sig_timestamp: Some(timestamp_ms),
            expiration_type: expiration.map(|e| e.kind),
            expiration_timer: expiration.map(|e| e.seconds),
            ..Default::default()
        };
        self.send_content(recipient_id, content, timestamp_ms).await?;
        Ok(self
            .send_sync_copy(recipient_id, data_message, timestamp_ms, expiration)
            .await)
    }

    /// Shorten how long our swarm keeps a received message, to `expiry_ms`
    /// (a disappear-after-read message we have read), as the official
    /// clients do; other devices and new installs then see the deadline.
    async fn expire_shorten(&self, hash: &str, expiry_ms: u64) -> Result<(), String> {
        // "expire" || "shorten" || expiry || messages[0] || … || messages[N]
        let signed = format!("expire{}{expiry_ms}{hash}", "shorten");
        let signature = ed25519::sign(&self.identity.ed_secret, signed.as_bytes())
            .map_err(|e| e.to_string())?;
        let params = serde_json::json!({
            "pubkey": self.identity.session_id,
            "pubkey_ed25519": hex::encode(self.identity.ed_public),
            "signature": STANDARD.encode(signature),
            "messages": [hash],
            "expiry": expiry_ms,
            "shorten": true,
        });
        let response = self
            .network
            .send_rpc("expire", params, Some(&self.identity.session_id))
            .await
            .map_err(|e| e.to_string())?;
        if response.status_code != 200 {
            return Err(format!("expire returned HTTP {}", response.status_code));
        }
        Ok(())
    }

    /// When our swarm will drop a message (`None`: it is already gone).
    async fn swarm_expiry_of(&self, hash: &str) -> Result<Option<u64>, String> {
        let timestamp = now_ms();
        // "get_expiries" || timestamp || messages[0] || … || messages[N]
        let signed = format!("get_expiries{timestamp}{hash}");
        let signature = ed25519::sign(&self.identity.ed_secret, signed.as_bytes())
            .map_err(|e| e.to_string())?;
        let params = serde_json::json!({
            "pubkey": self.identity.session_id,
            "pubkey_ed25519": hex::encode_upper(self.identity.ed_public),
            "signature": STANDARD.encode(signature),
            "messages": [hash],
            "timestamp": timestamp,
        });
        let response = self
            .network
            .send_rpc("get_expiries", params, Some(&self.identity.session_id))
            .await
            .map_err(|e| e.to_string())?;
        if response.status_code != 200 {
            return Err(format!("get_expiries returned HTTP {}", response.status_code));
        }
        let body: Value = serde_json::from_str(response.body.as_deref().unwrap_or(""))
            .map_err(|e| format!("get_expiries: {e}"))?;
        Ok(parse_expiry(&body, hash))
    }

    /// Send a DataMessage to its chat only (the sync copy is a separate
    /// outbox step).
    async fn send_to_chat(
        &self,
        recipient_id: &str,
        data_message: DataMessage,
        expiration: Option<Expiration>,
    ) -> Result<(), String> {
        let timestamp_ms = data_message.timestamp.ok_or("message has no timestamp")?;
        let content = Content {
            data_message: Some(data_message),
            sig_timestamp: Some(timestamp_ms),
            expiration_type: expiration.map(|e| e.kind),
            expiration_timer: expiration.map(|e| e.seconds),
            ..Default::default()
        };
        self.send_content(recipient_id, content, timestamp_ms).await.map(|_| ())
    }

    /// Typing indicator for a 1:1 chat (Session does not send them to groups).
    async fn send_typing(&self, recipient_id: &str, started: bool) -> Result<(), String> {
        use libsession::proto::session_protos::{TypingMessage, typing_message::Action};
        let timestamp_ms = now_ms();
        let content = Content {
            typing_message: Some(TypingMessage {
                timestamp: timestamp_ms,
                action: if started { Action::Started } else { Action::Stopped } as i32,
            }),
            sig_timestamp: Some(timestamp_ms),
            ..Default::default()
        };
        self.send_content(recipient_id, content, timestamp_ms)
            .await
            .map(|_| ())
    }

    /// Tell a group we accepted its invite (shows as "joined" for others).
    async fn send_invite_response(&self, group_id: &str) -> Result<(), String> {
        use libsession::proto::session_protos::{
            GroupUpdateInviteResponseMessage, GroupUpdateMessage,
        };
        let timestamp_ms = now_ms();
        let data_message = DataMessage {
            timestamp: Some(timestamp_ms),
            group_update_message: Some(GroupUpdateMessage {
                invite_response: Some(GroupUpdateInviteResponseMessage { is_approved: true }),
                ..Default::default()
            }),
            ..Default::default()
        };
        self.send_data_message(group_id, data_message, None)
            .await
            .map(|_| ())
    }

    /// Encrypt and upload one file to the Session file server.
    async fn upload_attachment(
        &self,
        path: &std::path::Path,
    ) -> Result<(AttachmentPointer, AttachmentMeta, Vec<u8>, Option<ImagePreview>), String> {
        debug_log("attachment.begin", "reading local file");
        // Refuse oversized files before reading and encrypting them (the
        // encrypted size is checked again below; it is slightly larger).
        let limit = libsession::network::backends::file_server::default_config().max_file_size;
        if std::fs::metadata(path).is_ok_and(|m| m.len() > limit) {
            return Err(format!(
                "{} exceeds Session's {} MB file limit",
                path.display(),
                limit / 1_000_000
            ));
        }
        // Read at most limit + 1 bytes: the file may grow after the check
        // above, or be a device/pipe without a real size.
        let plaintext = File::open(path)
            .and_then(|file| {
                let mut bytes = Vec::new();
                file.take(limit + 1).read_to_end(&mut bytes)?;
                Ok(bytes)
            })
            .map_err(|e| {
                debug_log("attachment.read_failed", &format!("error={e}"));
                format!("read {}: {e}", path.display())
            })?;
        if plaintext.len() as u64 > limit {
            return Err(format!(
                "{} exceeds Session's {} MB file limit",
                path.display(),
                limit / 1_000_000
            ));
        }
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
        quote: Option<DataQuote>,
        expiration: Option<Expiration>,
        timestamp_ms: u64,
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
        let caption = caption.trim().to_owned();
        let data_message = DataMessage {
            body: (!caption.is_empty()).then(|| caption.clone()),
            timestamp: Some(timestamp_ms),
            attachments: pointers,
            profile: profile_for(profile_name, timestamp_ms),
            quote,
            ..Default::default()
        };
        let sync_copy = self
            .send_data_message(recipient_id, data_message, expiration)
            .await?;
        debug_log(
            "attachment.sent",
            &format!("files={} sync_copy_sent={}", files.len(), sync_copy.sent),
        );
        Ok(SentAttachments {
            timestamp_ms,
            caption,
            files,
            sync_copy,
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
        expiration: Option<Expiration>,
    ) -> SyncCopy {
        if recipient_id.starts_with("03") || recipient_id == self.identity.session_id {
            return SyncCopy {
                sent: true,
                hash: None,
            };
        }
        let sync_content = Content {
            data_message: Some(DataMessage {
                sync_target: Some(recipient_id.to_owned()),
                ..data_message
            }),
            sig_timestamp: Some(timestamp_ms),
            expiration_type: expiration.map(|e| e.kind),
            expiration_timer: expiration.map(|e| e.seconds),
            ..Default::default()
        };
        match self
            .send_content(&self.identity.session_id, sync_content, timestamp_ms)
            .await
        {
            Ok(hash) => SyncCopy { sent: true, hash },
            Err(error) => {
                debug_log("send.sync_copy", &format!("sent=false error={error}"));
                SyncCopy {
                    sent: false,
                    hash: None,
                }
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
        self.send_content(recipient_id, content, now_ms())
            .await
            .map(|_| ())
    }

    /// "Delete for everyone": tell the chat and this account's other
    /// devices, then remove our own swarm copies (`own_hashes`).
    async fn unsend_message(
        &self,
        recipient_id: &str,
        timestamp_ms: u64,
        own_hashes: Vec<String>,
    ) -> Result<(), String> {
        let sent_at = now_ms();
        let content = Content {
            unsend_request: Some(libsession::proto::session_protos::UnsendRequest {
                timestamp: timestamp_ms,
                author: self.identity.session_id.clone(),
            }),
            ..Default::default()
        };
        self.send_content(recipient_id, content.clone(), sent_at).await?;
        if !recipient_id.starts_with("03") && recipient_id != self.identity.session_id {
            self.send_content(&self.identity.session_id, content, sent_at)
                .await
                .map_err(|error| format!("other devices not notified: {error}"))?;
        }
        if let Err(error) = self.delete_own_messages(&own_hashes).await {
            debug_log("unsend.swarm_delete", &format!("error={error}"));
        }
        Ok(())
    }

    /// Store `content` in the recipient's (or group's) swarm. Returns the
    /// swarm message hash for 1:1 stores when the node reports it.
    async fn send_content(
        &self,
        recipient_id: &str,
        mut content: Content,
        timestamp_ms: u64,
    ) -> Result<Option<String>, String> {
        // Session clients drop messages whose signed timestamp differs from
        // the envelope timestamp, so always use the same value for both.
        content.sig_timestamp = Some(timestamp_ms);
        debug_log(
            "send.begin",
            &format!(
                "recipient_prefix={} kind={} envelope_timestamp={} content_bytes={}",
                &recipient_id[..recipient_id.len().min(8)],
                content_kind(&content),
                timestamp_ms,
                content.encoded_len()
            ),
        );
        // Disappear-after-send messages only live on the swarm for their timer.
        let ttl_ms = match (content.expiration_type, content.expiration_timer) {
            (Some(2), Some(seconds)) if seconds > 0 => {
                (u64::from(seconds) * 1000).min(rpc::DEFAULT_MESSAGE_TTL_MS)
            }
            // Typing indicators are only useful for a few seconds.
            _ if content.typing_message.is_some() => 20_000,
            _ => rpc::DEFAULT_MESSAGE_TTL_MS,
        };
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
                group.keys.first().ok_or("no group encryption key")?,
                None,
            )
            .map_err(|error| format!("could not encode group message: {error}"))?;
            if !group.auth.can_write() {
                return Err("your membership in this group is read-only".into());
            }
            let encoded = STANDARD.encode(wire);
            let mut params =
                self.group_auth_params(&group.auth, &group.id, "store", 11, now_ms())?;
            params.insert(
                "ttl".to_owned(),
                Value::from(ttl_ms),
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
            return Ok(None);
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
                ttl_ms,
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
        Ok(response
            .body
            .as_deref()
            .and_then(|body| serde_json::from_str::<Value>(body).ok())
            .as_ref()
            .and_then(find_message_hash))
    }

    /// Delete our own messages from this account's swarm by hash, so that
    /// linked or newly restored devices cannot fetch them again.
    async fn delete_own_messages(&self, hashes: &[String]) -> Result<(), String> {
        if hashes.is_empty() {
            return Ok(());
        }
        let mut to_sign = b"delete".to_vec();
        for hash in hashes {
            to_sign.extend_from_slice(hash.as_bytes());
        }
        let signature = ed25519::sign(&self.identity.ed_secret, &to_sign)
            .map_err(|error| error.to_string())?;
        let params = serde_json::json!({
            "pubkey": self.identity.session_id,
            "pubkey_ed25519": hex::encode(self.identity.ed_public),
            "messages": hashes,
            "signature": STANDARD.encode(signature),
        });
        let response = self
            .network
            .send_rpc("delete", params, Some(&self.identity.session_id))
            .await
            .map_err(|error| error.to_string())?;
        debug_log(
            "swarm.delete",
            &format!("hashes={} http_status={}", hashes.len(), response.status_code),
        );
        if response.status_code != 200 {
            return Err(format!("swarm delete returned HTTP {}", response.status_code));
        }
        Ok(())
    }

    async fn retrieve_messages(
        &self,
        last_hash: Option<&str>,
        group_cursors: HashMap<String, String>,
        local_groups: Vec<LocalGroup>,
        account_dumps: [Option<Vec<u8>>; 4],
        account_changes: Vec<session_tui_account::AccountChange>,
    ) -> Result<RetrieveResult, String> {
        debug_log(
            "retrieve.begin",
            &format!("cursor_present={}", last_hash.is_some()),
        );
        // Candidates left by a sync that failed or timed out are dropped.
        let _ = self.take_pending_cursors();
        let pubkey_ed25519 = hex::encode(self.identity.ed_public);
        let mut items: Vec<Value> = Vec::new();
        // One sticky node with its own cursor (see `node_cursors`); the
        // global cursor is only the starting point for a new node.
        let node = self.poll_node(&self.identity.session_id).await?;
        let node_key = node_cursor_key(&self.identity.session_id, 0, &node);
        let mut cursor = self
            .cursor_for(&node_key)
            .or_else(|| last_hash.map(str::to_owned));
        debug_log(
            "retrieve.node",
            &format!(
                "node_prefix={} node_cursor={}",
                &hex::encode(node.ed25519_pubkey.0)[..8],
                self.cursor_for(&node_key).is_some()
            ),
        );
        for _ in 0..MAX_RETRIEVE_PAGES {
            let response = match self
                .network
                .send_retrieve_to(
                    &node,
                    &RetrieveParams {
                        pubkey: &self.identity.session_id,
                        pubkey_ed25519: &pubkey_ed25519,
                        namespace: 0,
                        timestamp_ms: now_ms(),
                        last_hash: cursor.as_deref(),
                        max_size: Some(1_000_000),
                        signing_key: &self.identity.ed_secret,
                    },
                )
                .await
            {
                Ok(response) if response.status_code == 200 => response,
                Ok(response) => {
                    self.drop_poll_node(&self.identity.session_id).await;
                    return Err(format!("Session retrieve returned HTTP {}", response.status_code));
                }
                Err(error) => {
                    self.drop_poll_node(&self.identity.session_id).await;
                    return Err(error.to_string());
                }
            };
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
        if let Some(hash) = cursor.clone() {
            self.set_cursor(node_key, hash);
        }
        let messages = &items;
        let last_hash = cursor.filter(|hash| Some(hash.as_str()) != last_hash);
        let mut incoming = Vec::new();
        let mut undecryptable = 0;
        let mut bad_envelope = 0;
        let mut bad_content = 0;
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
            let Some(mut message) = parse_content(
                &self.identity.session_id,
                hash,
                sender_id.clone(),
                sender_id.clone(),
                envelope.timestamp,
                content,
            ) else {
                continue;
            };
            message.swarm_expiry = item.get("expiration").and_then(Value::as_u64);
            debug_log(
                "message.route",
                &format!(
                    "sender_prefix={} contact_prefix={} outgoing={} attachments={}",
                    &sender_id[..sender_id.len().min(8)],
                    &message.contact_id[..message.contact_id.len().min(8)],
                    message.outgoing,
                    message.attachments.len(),
                ),
            );
            // No delivery receipts: current Session clients don't send them,
            // phones show them as empty "new message" notifications, and a
            // swarm node that doesn't know our cursor returns the whole
            // history, which re-acknowledged every old message.
            incoming.push(message);
        }
        let account = match self.sync_account(account_dumps, account_changes).await {
            Ok(account) => Some(account),
            Err(error) => {
                debug_log("account.sync_failed", &error);
                None
            }
        };
        let user_groups = account
            .as_ref()
            .map(|account| account.user_groups.clone())
            .unwrap_or_default();
        let groups = match self.discover_groups(&local_groups, user_groups).await {
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
        let mut invite_responses = Vec::new();
        for local in local_groups.iter().filter(|local| !local.responded) {
            let ready = self
                .groups
                .lock()
                .map(|groups| groups.contains_key(&local.id))
                .unwrap_or(false);
            if ready && self.send_invite_response(&local.id).await.is_ok() {
                invite_responses.push(local.id.clone());
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
            node_cursors: self.take_pending_cursors(),
            invite_responses,
            account,
        })
    }
}

fn prompt_identity() -> Result<Identity, Box<dyn std::error::Error>> {
    let saved_seed_path = session_data_dir()?.join(SAVED_SEED_FILE);
    if std::env::args().skip(1).any(|arg| arg == "--forget-seed") {
        match std::fs::remove_file(&saved_seed_path) {
            Ok(()) => println!("Removed the saved seed."),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                println!("No saved seed.")
            }
            Err(error) => return Err(error.into()),
        }
    }
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

/// File name of the saved seed: DPAPI-protected on Windows, passphrase
/// encrypted elsewhere.
const SAVED_SEED_FILE: &str = if cfg!(windows) {
    "identity.dpapi"
} else {
    "identity.seed"
};

#[cfg_attr(windows, allow(dead_code))]
const SEED_FILE_MAGIC: &[u8; 8] = b"STUISED1";

#[cfg_attr(windows, allow(dead_code))]
/// Argon2id (64 MiB, 3 passes) key for the saved-seed file.
fn seed_file_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32)).map_err(|e| e.to_string())?;
    let mut key = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| e.to_string())?;
    Ok(key)
}

#[cfg_attr(windows, allow(dead_code))]
/// `magic || salt(16) || nonce(24) || XChaCha20-Poly1305(seed)`
fn encrypt_seed_file(seed: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    let salt = random::random(16);
    let nonce = random::random(24);
    let key = seed_file_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| e.to_string())?;
    let encrypted = cipher
        .encrypt(XNonce::from_slice(&nonce), seed)
        .map_err(|_| "could not encrypt the seed".to_string())?;
    Ok([SEED_FILE_MAGIC.as_slice(), &salt, &nonce, &encrypted].concat())
}

#[cfg_attr(windows, allow(dead_code))]
fn decrypt_seed_file(data: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if data.len() < 8 + 16 + 24 + 16 || &data[..8] != SEED_FILE_MAGIC {
        return Err("the saved seed file is not recognised".into());
    }
    let (salt, rest) = data[8..].split_at(16);
    let (nonce, encrypted) = rest.split_at(24);
    let key = seed_file_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|e| e.to_string())?;
    cipher
        .decrypt(XNonce::from_slice(nonce), encrypted)
        .map_err(|_| "wrong passphrase".to_string())
}

/// Linux/macOS: offer to keep the seed on disk, encrypted with a passphrase
/// (there is no per-user secret store we can rely on everywhere, and an
/// unencrypted seed file would hand over the account to anyone reading it).
#[cfg(not(windows))]
fn save_protected_seed(
    path: &std::path::Path,
    seed: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    println!(
        "\nSave the seed on this computer so you don't have to enter it again?\n\
         It is encrypted with a passphrase you choose; leave blank to not save it."
    );
    let passphrase = loop {
        let first = rpassword::prompt_password("New passphrase (blank = don't save): ")?;
        if first.is_empty() {
            return Ok(());
        }
        if first.chars().count() < 6 {
            println!("Use at least 6 characters.");
            continue;
        }
        if rpassword::prompt_password("Repeat passphrase: ")? == first {
            break first;
        }
        println!("Passphrases differ, try again.");
    };
    let data = encrypt_seed_file(seed, &passphrase)?;
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&data)?;
    println!("Seed saved to {} (use --forget-seed to remove it).", path.display());
    Ok(())
}

#[cfg(not(windows))]
fn load_protected_seed(
    path: &std::path::Path,
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let Ok(data) = std::fs::read(path) else {
        return Ok(None);
    };
    for _ in 0..3 {
        let passphrase = rpassword::prompt_password(
            "Passphrase for the saved seed (blank = enter seed instead): ",
        )?;
        if passphrase.is_empty() {
            return Ok(None);
        }
        match decrypt_seed_file(&data, &passphrase) {
            Ok(seed) if seed.len() == 32 => return Ok(Some(seed)),
            Ok(_) => return Err("The saved Session seed file is invalid".into()),
            Err(error) => println!("{error}"),
        }
    }
    Err("too many wrong passphrases".into())
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
        crossterm::event::DisableFocusChange,
        DisableMouseCapture,
        LeaveAlternateScreen,
        crossterm::cursor::Show
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = LOCAL_OFFSET.set(
        time::UtcOffset::current_local_offset().unwrap_or(time::UtcOffset::UTC),
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async_main());
    // Dropping the runtime would wait for network work still running on
    // blocking threads (a sync can take up to 90 s). Local state is already
    // saved, so don't wait for it.
    runtime.shutdown_timeout(Duration::from_millis(300));
    result
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
    let _ = BLOB_ACCOUNT.set(client.identity.session_id.clone());
    let store = LocalStore::open(&client.identity)?;
    store.prune_pending_receipts();
    if let Ok(mut cursors) = client.node_cursors.lock() {
        *cursors = store.node_cursors();
    }
    clean_paste_dir();
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
        EnableBracketedPaste,
        crossterm::event::EnableFocusChange
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new(client.identity.session_id.clone());
    app.recovery_seed = client.identity.recovery_phrase.clone();
    if let Err(error) = store.load(&mut app) {
        app.status = format!("LOCAL HISTORY ERROR · {error}");
    }
    app.last_outgoing_ms = app
        .conversations
        .iter()
        .flat_map(|c| &c.messages)
        .filter(|m| m.outgoing)
        .map(|m| m.timestamp_ms)
        .max()
        .unwrap_or(0);
    // Account state from the last sync, before the network is reached.
    if let Ok(configs) =
        session_tui_account::AccountConfigs::new(&client.identity.ed_secret, &store.account_dumps())
    {
        apply_account_state(&mut app, &store, &configs.state());
    }
    let result = run(&mut terminal, &mut app, &client, &store).await;
    restore_terminal();
    result?;
    Ok(())
}

type SyncTask = tokio::task::JoinHandle<Result<RetrieveResult, String>>;
type DownloadTask = tokio::task::JoinHandle<Result<DownloadedAttachment, (PendingDownload, String)>>;

type NetworkJob =
    Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()>>> + Send>;

/// The network thread: one long-lived current-thread runtime that runs all
/// network work, so HTTPS connections stay pooled between syncs instead of
/// being re-established (TLS handshakes) every few seconds.
fn network_jobs() -> &'static tokio::sync::mpsc::UnboundedSender<NetworkJob> {
    static JOBS: OnceLock<tokio::sync::mpsc::UnboundedSender<NetworkJob>> = OnceLock::new();
    JOBS.get_or_init(|| {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<NetworkJob>();
        std::thread::Builder::new()
            .name("network".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("network runtime");
                let local = tokio::task::LocalSet::new();
                local.block_on(&runtime, async move {
                    while let Some(job) = receiver.recv().await {
                        tokio::task::spawn_local(job());
                    }
                });
            })
            .expect("network thread");
        sender
    })
}

/// Run a !Send network future on the network thread.
fn spawn_network<T, F, Fut>(f: F) -> tokio::task::JoinHandle<Result<T, String>>
where
    T: Send + 'static,
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<T, String>> + 'static,
{
    let (done, result) = tokio::sync::oneshot::channel();
    let job: NetworkJob = Box::new(move || {
        Box::pin(async move {
            let _ = done.send(f().await);
        })
    });
    let queued = network_jobs().send(job).is_ok();
    tokio::spawn(async move {
        if !queued {
            return Err("network thread stopped".to_owned());
        }
        result
            .await
            .unwrap_or_else(|_| Err("network task failed".to_owned()))
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
/// Write `bytes` to `path` via a temporary file in the same folder, renamed
/// into place only when complete: a full disk or a crash never leaves a
/// half-written file under the final name.
fn write_file_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid file name")?;
    let temporary = path.with_file_name(format!(".{name}.{}.part", now_ms()));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&temporary, path)
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}

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
        if app.is_request(conversation) {
            continue;
        }
        for message in &conversation.messages {
            for (index, meta) in message.attachments.iter().enumerate() {
                if meta.url.is_empty() {
                    continue;
                }
                let path = session_tui_media::attachment_blob_path(
                    &root,
                    &message_blob_owner(&conversation.id, message),
                    message.timestamp_ms,
                    index,
                );
                if !path.exists() {
                    queue.push_back(PendingDownload {
                        peer: conversation.id.clone(),
                        sender: message.sender.clone(),
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
    // The message may have been deleted, unsent or expired meanwhile: then
    // the file must not be written (nothing would ever clean it up).
    let Some(conversation) = app.conversations.iter_mut().find(|c| c.id == job.peer) else {
        return;
    };
    let Some(message) = conversation.messages.iter_mut().find(|m| job.is_for(m)) else {
        debug_log("attachment.download.orphan", "message_gone=true discarded=true");
        return;
    };
    if let Err(error) = store.save_attachment_blob(
        &blob_owner(&job.peer, job.sender.as_deref(), job.outgoing),
        job.timestamp_ms,
        job.index,
        &downloaded.encrypted,
    ) {
        debug_log("attachment.cache.failed", &format!("error={error}"));
        return;
    }
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
    let mut attachment_task: Option<(
        tokio::task::JoinHandle<Result<SentAttachments, String>>,
        String,
        u64,
    )> = None;
    let mut download_task: Option<DownloadTask> = None;
    let mut save_task: Option<tokio::task::JoinHandle<Result<String, String>>> = None;
    let mut download_queue = std::collections::VecDeque::new();
    enqueue_missing_downloads(app, &mut download_queue);
    // Outgoing text/reaction/timer sends: (task, chat, message timestamp).
    // Outbox work in flight (see `OutboxKind`), at most OUTBOX_PARALLEL.
    let mut outbox_tasks: Vec<(tokio::task::JoinHandle<Result<Option<String>, String>>, OutboxEntry)> =
        Vec::new();
    let mut last_outbox_check: Option<Instant> = None;
    let mut exit_warned = false;
    let mut background_tasks: Vec<(tokio::task::JoinHandle<Result<(), String>>, &'static str)> =
        Vec::new();
    let mut last_typing: Option<(String, Instant)> = None;
    let mut last_expiry_sweep = Instant::now();
    let mut last_title_unread: Option<usize> = None;
    let mut redraw = true;
    let mut last_draw = Instant::now();
    loop {
        // Outbox: finished work.
        let mut index = 0;
        while index < outbox_tasks.len() {
            if !outbox_tasks[index].0.is_finished() {
                index += 1;
                continue;
            }
            let (task, entry) = outbox_tasks.swap_remove(index);
            let result = task
                .await
                .unwrap_or_else(|error| Err(format!("send task failed: {error}")));
            finish_outbox(app, store, &entry, result);
        }
        // Outbox: start what is due (looked up at most once a second, or
        // right away after something was queued).
        if last_outbox_check.is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
            && outbox_tasks.len() < OUTBOX_PARALLEL
        {
            last_outbox_check = Some(Instant::now());
            for entry in store.outbox_due(now_ms()) {
                if outbox_tasks.len() >= OUTBOX_PARALLEL {
                    break;
                }
                if outbox_tasks.iter().any(|(_, running)| running.id == entry.id) {
                    continue;
                }
                match start_outbox(client, app, &entry) {
                    Some(task) => outbox_tasks.push((task, entry)),
                    // Its message was deleted: nothing left to send.
                    None => {
                        let _ = store.outbox_done(entry.id);
                    }
                }
            }
        }
        // Fire-and-forget network work (unsend, typing, reactions…).
        let mut index = 0;
        while index < background_tasks.len() {
            if !background_tasks[index].0.is_finished() {
                index += 1;
                continue;
            }
            let (task, what) = background_tasks.swap_remove(index);
            if let Ok(Err(error)) | Err(error) = task.await.map_err(|e| e.to_string()) {
                debug_log("background.failed", &format!("task={what} error={error}"));
                if what != "typing" {
                    app.status = format!("{} FAILED · {error}", what.to_uppercase());
                }
            }
        }
        if last_expiry_sweep.elapsed() >= Duration::from_secs(1) {
            last_expiry_sweep = Instant::now();
            remove_expired_messages(app, store);
        }
        if save_task.as_ref().is_some_and(|task| task.is_finished())
            && let Some(task) = save_task.take()
        {
            app.status = match task.await {
                Ok(Ok(status)) => status,
                Ok(Err(error)) => format!("SAVE FAILED · {error}"),
                Err(error) => format!("SAVE FAILED · {error}"),
            };
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
            // Files from strangers are fetched (and images decoded) only
            // once the request is accepted; /accept queues them again.
            let conversation = app.conversations.iter().find(|c| c.id == job.peer);
            let from_request = conversation.is_some_and(|c| app.is_request(c));
            let still_there =
                conversation.is_some_and(|c| c.messages.iter().any(|m| job.is_for(m)));
            if !from_request && still_there {
                download_task = Some(start_download(client, job));
            }
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
                        message.swarm_hashes.extend(sent.sync_copy.hash);
                        for (index, (meta, encrypted, preview)) in
                            sent.files.into_iter().enumerate()
                        {
                            let _ = store.save_attachment_blob(
                                &blob_owner(&peer, None, true),
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
                        app.status = if sent.sync_copy.sent {
                            "ATTACHMENT SENT · SYNCED TO YOUR OTHER DEVICES".into()
                        } else {
                            // Retried from the outbox (rebuilt from the
                            // stored message and its attachment pointers).
                            if peer.starts_with("05") && peer != app.local_id {
                                let _ = store.outbox_add(OutboxKind::SyncCopy, &peer, sent.timestamp_ms, &[]);
                                last_outbox_check = None;
                            }
                            "ATTACHMENT SENT · DEVICE SYNC COPY WILL BE RETRIED".into()
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
        let unread: usize = app.conversations.iter().map(Conversation::unread).sum();
        if last_title_unread != Some(unread) {
            last_title_unread = Some(unread);
            let title = if unread > 0 {
                format!("({unread}) Session")
            } else {
                "Session".to_owned()
            };
            let _ = execute!(terminal.backend_mut(), crossterm::terminal::SetTitle(title));
        }
        if app.recovery_seed.is_none()
            && !app.show_help
            && app.window_focused
            && mark_current_conversation_read(app, store)
        {
            last_outbox_check = None;
        }
        if sync_task.as_ref().is_some_and(|task| task.is_finished())
            && let Some(task) = sync_task.take()
        {
            let result = match task.await {
                Ok(result) => result,
                Err(_) => Err("sync task failed".into()),
            };
            let new_messages = finish_sync(
                app,
                store,
                &client.identity.session_id,
                result,
                &mut download_queue,
                Some(&client.node_cursors),
            );
            if new_messages > 0 && app.bell {
                // BEL: Windows Terminal beeps and/or flashes the taskbar,
                // depending on its "bell notification style" setting.
                let _ = terminal.backend_mut().write_all(b"\x07");
                let _ = terminal.backend_mut().flush();
            }
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
        // Coalesce bursts of input (e.g. mouse-wheel spins): redraw once the
        // queue is empty, but at least every 50 ms.
        // Idle, only redraw once a second (results of background work, the
        // typing indicator, expiry); input redraws right away. Each draw
        // lays out the whole open chat, so this is most of the idle CPU.
        if (redraw || last_draw.elapsed() >= Duration::from_secs(1))
            && (!event::poll(Duration::ZERO)? || last_draw.elapsed() >= Duration::from_millis(50))
        {
            terminal.draw(|frame| draw(frame, app))?;
            last_draw = Instant::now();
            redraw = false;
        }
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        redraw = true;
        let key = match event::read()? {
            Event::FocusGained => {
                app.window_focused = true;
                continue;
            }
            Event::FocusLost => {
                app.window_focused = false;
                continue;
            }
            Event::Mouse(mouse) => {
                let was_dragging = app.dragging_divider;
                handle_mouse(app, mouse);
                if let Some(text) = app.clipboard.take() {
                    copy_to_clipboard(terminal.backend_mut(), &text);
                }
                if was_dragging && !app.dragging_divider {
                    let _ = store.set_setting("sidebar_width", &app.sidebar_width.to_string());
                }
                continue;
            }
            Event::Paste(text) if app.image_viewer.is_none() && app.recovery_seed.is_none() => {
                // Keep pasted line breaks: Enter is the only thing that sends.
                let text = text.replace("\r\n", "\n").replace('\r', "\n");
                let text = if app.input_mode == InputMode::ContactId {
                    text.trim().to_owned()
                } else {
                    text
                };
                session_tui_input::insert(&mut app.input, &mut app.cursor, &text);
                app.focus = FocusArea::Composer;
                continue;
            }
            Event::Key(key) => key,
            _ => continue,
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if let Some(viewer) = app.image_viewer.as_ref() {
            let step: isize = match key.code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    app.image_viewer = None;
                    continue;
                }
                KeyCode::Right | KeyCode::Char('n') | KeyCode::Char(' ') => 1,
                KeyCode::Left | KeyCode::Char('p') | KeyCode::Backspace => -1,
                _ => continue,
            };
            let current = viewer.index;
            let images: Vec<usize> = app.selected_message().map_or(Vec::new(), |message| {
                message
                    .attachments
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.content_type.starts_with("image/"))
                    .map(|(index, _)| index)
                    .collect()
            });
            if images.len() > 1 {
                let position = images.iter().position(|i| *i == current).unwrap_or(0) as isize;
                let next = images[(position + step).rem_euclid(images.len() as isize) as usize];
                if let Err(error) = open_selected_image(app, Some(next)) {
                    app.status = format!("IMAGE PREVIEW FAILED · {error}");
                }
            }
            continue;
        }
        if let Some(seed) = app.recovery_seed.as_ref() {
            if matches!(key.code, KeyCode::Char('c' | 'C')) {
                copy_to_clipboard(terminal.backend_mut(), seed);
                app.status = "RECOVERY PHRASE COPIED".into();
            }
            if matches!(key.code, KeyCode::Enter | KeyCode::Esc) {
                app.recovery_seed = None;
            }
            continue;
        }
        if let Some((action, id)) = app.chat_prompt.take() {
            app.status = if matches!(key.code, KeyCode::Char('y' | 'Y')) {
                delete_chat(app, store, action, &id)
            } else {
                "CANCELLED".into()
            };
            continue;
        }
        if let Some(can_unsend) = app.delete_prompt.take() {
            match key.code {
                KeyCode::Char('1') => {
                    app.status = delete_selected(app, client, store, &mut background_tasks, false);
                }
                KeyCode::Char('2') if can_unsend => {
                    app.status = delete_selected(app, client, store, &mut background_tasks, true);
                }
                _ => app.status = "DELETE CANCELLED".into(),
            }
            continue;
        }
        if app.reaction_picker {
            app.reaction_picker = false;
            if let KeyCode::Char(c @ '1'..='6') = key.code {
                let emoji = QUICK_REACTIONS[c as usize - '1' as usize];
                react_to_selected(app, client, store, emoji, &mut background_tasks);
            }
            continue;
        }
        if app.show_emoji {
            app.show_emoji = false;
            continue;
        }
        if app.show_help {
            match key.code {
                KeyCode::Up => app.help_scroll = app.help_scroll.saturating_sub(1),
                KeyCode::Down => app.help_scroll = app.help_scroll.saturating_add(1).min(60),
                KeyCode::PageUp => app.help_scroll = app.help_scroll.saturating_sub(10),
                KeyCode::PageDown => app.help_scroll = app.help_scroll.saturating_add(10).min(60),
                _ => app.show_help = false,
            }
            continue;
        }
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let editing = !app.input.is_empty();
        match key.code {
            // Line break: Shift+Enter / Alt+Enter / Ctrl+J (terminals differ
            // in which of these they can report).
            KeyCode::Enter
                if app.input_mode == InputMode::Message
                    && key
                        .modifiers
                        .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT) =>
            {
                session_tui_input::insert(&mut app.input, &mut app.cursor, "\n");
                app.focus = FocusArea::Composer;
            }
            KeyCode::Char('j') if ctrl && app.input_mode == InputMode::Message => {
                session_tui_input::insert(&mut app.input, &mut app.cursor, "\n");
                app.focus = FocusArea::Composer;
            }
            KeyCode::Char('w') if ctrl => {
                session_tui_input::delete_word(&mut app.input, &mut app.cursor);
            }
            KeyCode::Char('a') if ctrl && editing => {
                session_tui_input::home(&app.input, &mut app.cursor);
            }
            KeyCode::Char('e') if ctrl && editing => {
                session_tui_input::end(&app.input, &mut app.cursor);
            }
            KeyCode::Left if editing => session_tui_input::left(&app.input, &mut app.cursor),
            KeyCode::Right if editing => session_tui_input::right(&app.input, &mut app.cursor),
            KeyCode::Home if editing => session_tui_input::home(&app.input, &mut app.cursor),
            KeyCode::End if editing => session_tui_input::end(&app.input, &mut app.cursor),
            KeyCode::Up if editing && app.focus == FocusArea::Composer => {
                session_tui_input::vertical(&app.input, &mut app.cursor, true);
            }
            KeyCode::Down if editing && app.focus == FocusArea::Composer => {
                session_tui_input::vertical(&app.input, &mut app.cursor, false);
            }
            KeyCode::Delete if editing => {
                session_tui_input::delete(&mut app.input, &mut app.cursor);
            }
            KeyCode::Char('e')
                if app.focus == FocusArea::Messages
                    && app.input.is_empty()
                    && key.modifiers.is_empty() =>
            {
                if app.selected_message().is_some_and(|m| !m.system) {
                    app.reaction_picker = true;
                } else {
                    app.status = "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
                }
            }
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
                app.cursor = 0;
            }
            KeyCode::Esc if app.show_help => app.show_help = false,
            KeyCode::Esc if app.reply_to.is_some() => {
                app.reply_to = None;
                app.status = "REPLY CANCELLED".into();
            }
            KeyCode::Char('r')
                if app.focus == FocusArea::Messages
                    && app.input.is_empty()
                    && key.modifiers.is_empty() =>
            {
                let local_id = client.identity.session_id.clone();
                if let Some(conversation) = app.conversations.get(app.selected)
                    && let Some(message) = conversation.messages.get(conversation.selected_message)
                    && !message.system
                    && message.send_state == SendState::Sent
                {
                    app.reply_to = Some(QuoteRef {
                        id: message.timestamp_ms,
                        author: message.author(&conversation.id, &local_id).to_owned(),
                        text: message.preview_text(),
                    });
                    app.focus = FocusArea::Composer;
                    app.status = "REPLYING · ESC TO CANCEL".into();
                }
            }
            KeyCode::Char('+') if app.focus == FocusArea::Messages && app.input.is_empty() => {
                react_to_selected(app, client, store, "👍", &mut background_tasks);
            }
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
                    conversation.scroll = None;
                    conversation.follow_selection = true;
                    conversation.selected_message = conversation.selected_message.saturating_sub(1);
                }
            }
            KeyCode::Down if app.input.is_empty() && app.focus == FocusArea::Messages => {
                if let Some(conversation) = app.conversations.get_mut(app.selected)
                    && !conversation.messages.is_empty()
                {
                    conversation.scroll = None;
                    conversation.follow_selection = true;
                    conversation.selected_message =
                        (conversation.selected_message + 1).min(conversation.messages.len() - 1);
                }
            }
            KeyCode::Delete if app.input.is_empty() => {
                let Some((outgoing, local_only)) = app.selected_message().map(|message| {
                    (
                        message.outgoing,
                        (message.outgoing && message.send_state != SendState::Sent)
                            || message.system,
                    )
                }) else {
                    app.status = "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
                    continue;
                };
                if local_only {
                    // Never left this device: nothing to unsend.
                    app.status = delete_selected(app, client, store, &mut background_tasks, false);
                } else {
                    app.delete_prompt = Some(outgoing);
                }
            }
            KeyCode::Enter
                if app.input_mode == InputMode::ContactId && !app.input.starts_with('/') =>
            {
                app.submit_contact_id();
                if app.input_mode == InputMode::Message
                    && let Some(contact) = app.conversations.get(app.selected)
                {
                    if let Err(error) = store.save_contact(&contact.id) {
                        app.status = format!("LOCAL CONTACT ERROR · {error}");
                    }
                    store.queue_account_change(session_tui_account::AccountChange::ApproveContact {
                        id: contact.id.clone(),
                        name: None,
                    });
                }
            }
            KeyCode::Enter => {
                let mut input = app.input.clone();
                // `/paste [-- caption]`: the clipboard image becomes a
                // temporary file sent through `/attach`, which deletes it.
                if input.trim() == "/paste" || input.trim_start().starts_with("/paste ") {
                    let caption = input
                        .split_once(" -- ")
                        .map(|(_, caption)| format!(" -- {caption}"))
                        .unwrap_or_default();
                    match save_clipboard_image() {
                        Ok(path) => input = format!("/attach \"{}\"{caption}", path.display()),
                        Err(error) => {
                            app.input.clear();
                            app.cursor = 0;
                            app.status = format!("PASTE FAILED · {error}");
                            continue;
                        }
                    }
                }
                let (command, rest) = input
                    .split_once(char::is_whitespace)
                    .map_or((input.as_str(), ""), |(c, r)| (c, r.trim()));
                // `/1`–`/9`: switch to that chat, numbered top to bottom
                // as in the chat list.
                if rest.is_empty()
                    && let Some(number) = command
                        .strip_prefix('/')
                        .filter(|n| n.len() == 1)
                        .and_then(|n| n.parse::<usize>().ok())
                        .filter(|n| *n >= 1)
                {
                    app.input.clear();
                    app.cursor = 0;
                    let count = app.conversations.len();
                    if number <= count {
                        app.selected = number - 1;
                        app.status = format!(
                            "CHAT {number} · {}",
                            app.conversations[number - 1].title(&app.local_id)
                        );
                    } else {
                        app.status = match count {
                            0 => "NO CHATS YET · CTRL+N TO ADD ONE".into(),
                            1 => "ONLY 1 CHAT · USE /1".into(),
                            n => format!("ONLY {n} CHATS · USE /1–/{}", n.min(9)),
                        };
                    }
                    continue;
                }
                match command {
                    "/attach" => {
                        app.input.clear();
                        let (paths, caption) = match rest.split_once(" -- ") {
                            Some((paths, caption)) => {
                                (split_args(paths), expand_shortcodes(caption.trim()))
                            }
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
                            app.cursor = input.len();
                            app.input = input;
                            continue;
                        }
                        if let Some(missing) =
                            paths.iter().find(|p| !std::path::Path::new(p).is_file())
                        {
                            app.status = format!("FILE NOT FOUND · {missing}");
                            app.cursor = input.len();
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
                        let pending_timestamp = next_outgoing_timestamp(&mut app.last_outgoing_ms);
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
                        let quote = app.reply_to.take().map(data_quote);
                        let expiration = app
                            .conversations
                            .get(app.selected)
                            .and_then(|c| c.disappearing);
                        let paths: Vec<std::path::PathBuf> =
                            paths.into_iter().map(std::path::PathBuf::from).collect();
                        let pasted: Vec<std::path::PathBuf> =
                            paths.iter().filter(|p| is_pasted_image(p)).cloned().collect();
                        attachment_task = Some((
                            spawn_network(move || async move {
                                let result = task_client
                                    .send_attachments(
                                        &task_peer,
                                        &paths,
                                        &caption,
                                        &profile_name,
                                        quote,
                                        expiration,
                                        pending_timestamp,
                                    )
                                    .await;
                                // Pasted screenshots are temporary: gone once
                                // sent (or failed); the sent copy is cached
                                // encrypted like any attachment.
                                for path in &pasted {
                                    let _ = std::fs::remove_file(path);
                                }
                                result
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
                                Some((
                                    message_blob_owner(&c.id, m),
                                    m.timestamp_ms,
                                    m.attachments.clone(),
                                ))
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
                        // Never overwrite an existing file silently.
                        if !into_dir
                            && let Some(file) = target_path.as_ref()
                            && file.exists()
                        {
                            app.status = format!(
                                "FILE EXISTS · {} · CHOOSE ANOTHER NAME OR A FOLDER",
                                file.display()
                            );
                            continue;
                        }
                        if save_task.is_some() {
                            app.status = "A SAVE IS ALREADY RUNNING".into();
                            continue;
                        }
                        app.status = "SAVING ATTACHMENT…".into();
                        // Download (if not cached), decrypt and write on the
                        // network thread, so the interface never waits.
                        let task_client = Arc::clone(client);
                        save_task = Some(spawn_network(move || async move {
                            let mut saved = Vec::new();
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
                                                task_client.download_attachment(&pointer).await?;
                                            write_attachment_blob(&peer, timestamp, index, &bytes)?;
                                            bytes
                                        }
                                    };
                                    // CPU and disk work on a blocking thread,
                                    // not the shared network thread.
                                    let (key, digest, deterministic, target) = (
                                        metadata.key.clone(),
                                        metadata.digest.clone(),
                                        metadata.deterministic,
                                        destination.clone(),
                                    );
                                    tokio::task::spawn_blocking(move || {
                                        let plaintext = session_tui_media::decrypt_attachment(
                                            &encrypted,
                                            &key,
                                            &digest,
                                            deterministic,
                                        )?;
                                        write_file_atomically(&target, &plaintext)
                                    })
                                    .await
                                    .map_err(|e| e.to_string())??;
                                    Ok::<(), String>(())
                                }
                                .await;
                                if let Err(error) = result {
                                    return Err(format!("{} · {error}", metadata.file_name));
                                }
                                saved.push(destination);
                            }
                            Ok(match saved.as_slice() {
                                [one] => format!("SAVED FILE · {}", one.display()),
                                many => format!(
                                    "SAVED {} FILES · {}",
                                    many.len(),
                                    target_path.unwrap_or(cwd).display()
                                ),
                            })
                        }));
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
                            store.queue_account_change(
                                session_tui_account::AccountChange::ProfileName(rest.to_owned()),
                            );
                            app.status = match store.save_profile_name(&app.profile_name) {
                                Ok(()) => "PROFILE NAME SAVED · SYNCING TO YOUR OTHER DEVICES".into(),
                                Err(error) => format!("PROFILE SAVE FAILED · {error}"),
                            };
                        }
                    }
                    "/exit" if rest.is_empty() => {
                        // Unsent texts are in the outbox and go out on the
                        // next start. An upload in progress is not resumed,
                        // so say so once.
                        if attachment_task.is_some() && !exit_warned {
                            app.input.clear();
                            exit_warned = true;
                            app.status =
                                "AN ATTACHMENT IS STILL UPLOADING AND WON'T RESUME · /exit AGAIN TO QUIT".into();
                            continue;
                        }
                        return Ok(());
                    }
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
                    "/block" | "/unblock" => {
                        app.input.clear();
                        let blocked = command == "/block";
                        let Some(id) = app
                            .conversations
                            .get(app.selected)
                            .map(|c| c.id.clone())
                            .filter(|id| id.starts_with("05") && *id != app.local_id)
                        else {
                            app.status = "OPEN A 1:1 CHAT FIRST".into();
                            continue;
                        };
                        if blocked {
                            app.blocked.insert(id.clone());
                        } else {
                            app.blocked.remove(&id);
                        }
                        store.queue_account_change(session_tui_account::AccountChange::SetBlocked {
                            id,
                            blocked,
                        });
                        app.status = if blocked {
                            "CONTACT BLOCKED · THEIR MESSAGES ARE IGNORED ON ALL YOUR DEVICES".into()
                        } else {
                            "CONTACT UNBLOCKED".into()
                        };
                    }
                    "/delete" | "/remove" => {
                        app.input.clear();
                        let action = if command == "/delete" {
                            ChatAction::Delete
                        } else {
                            ChatAction::Remove
                        };
                        let Some(id) = app.conversations.get(app.selected).map(|c| c.id.clone())
                        else {
                            app.status = "NO CHAT SELECTED".into();
                            continue;
                        };
                        if action == ChatAction::Remove
                            && (!id.starts_with("05") || id == app.local_id)
                        {
                            app.status = "/remove IS FOR 1:1 CONTACTS · USE /delete".into();
                            continue;
                        }
                        app.chat_prompt = Some((action, id));
                    }
                    "/bell" => {
                        app.input.clear();
                        match rest {
                            "on" | "off" => {
                                app.bell = rest == "on";
                                let _ = store.set_setting("bell", rest);
                            }
                            "" => {}
                            _ => {
                                app.status = "USAGE · /bell on|off".into();
                                continue;
                            }
                        }
                        app.status = format!(
                            "NEW-MESSAGE BELL {}",
                            if app.bell { "ON" } else { "OFF" }
                        );
                    }
                    "/emoji" if rest.is_empty() => {
                        app.input.clear();
                        app.show_emoji = true;
                    }
                    "/?" if rest.is_empty() => {
                        app.input.clear();
                        app.help_scroll = 0;
                        app.show_help = true;
                    }
                    _ if app.input_mode == InputMode::ContactId => {
                        app.status = "UNKNOWN COMMAND · ESC TO CANCEL ADDING A CONTACT".into();
                    }
                    "/retry" => {
                        app.input.clear();
                        // A failed message, or a sent one whose sync copy
                        // for other devices ran out of attempts: retry what
                        // is queued for it (a sent message is not resent).
                        let selected = app.conversations.get(app.selected).and_then(|c| {
                            let message = c.messages.get(c.selected_message)?;
                            (message.outgoing && !message.system).then(|| (c.id.clone(), message.clone()))
                        });
                        let Some((peer, mut message)) = selected else {
                            app.status = "SELECT ONE OF YOUR MESSAGES TO RETRY".into();
                            continue;
                        };
                        let queued = store.outbox_retry_now(&peer, message.timestamp_ms).unwrap_or(false);
                        if message.send_state == SendState::Failed {
                            message.send_state = SendState::Sending;
                            let saved = store.begin_batch().and_then(|()| {
                                let _ = store.update_message(&peer, &message);
                                if !queued {
                                    // Failed in an older build: queue it now.
                                    let _ = store.outbox_add(OutboxKind::Text, &peer, message.timestamp_ms, &[]);
                                }
                                store.end_batch()
                            });
                            app.status = match saved {
                                Ok(()) => {
                                    if let Some(m) = app.selected_message_mut() {
                                        m.send_state = SendState::Sending;
                                    }
                                    "RETRYING…".into()
                                }
                                Err(error) => format!("RETRY NOT SAVED · {error}"),
                            };
                        } else if queued {
                            app.status = "RETRYING THE OTHER-DEVICE SYNC COPY…".into();
                        } else {
                            app.status = "NOTHING TO RETRY FOR THIS MESSAGE".into();
                        }
                        last_outbox_check = None;
                    }
                    "/react" => {
                        app.input.clear();
                        if rest.is_empty() {
                            app.status = "USAGE · /react EMOJI (again to remove)".into();
                        } else {
                            let emoji = expand_shortcodes(rest);
                            react_to_selected(app, client, store, &emoji, &mut background_tasks);
                        }
                    }
                    "/disappear" => {
                        app.input.clear();
                        let Some(conversation) = app.conversations.get(app.selected) else {
                            continue;
                        };
                        if rest.is_empty() {
                            app.status = format!(
                                "DISAPPEARING MESSAGES · {}",
                                Expiration::describe(conversation.disappearing)
                            );
                            continue;
                        }
                        if conversation.id.starts_with("03") {
                            app.status =
                                "GROUP TIMERS ARE SET BY ADMINS IN THE GROUP SETTINGS".into();
                            continue;
                        }
                        let setting = match Expiration::parse(rest) {
                            Ok(setting) => setting,
                            Err(usage) => {
                                app.status = usage;
                                continue;
                            }
                        };
                        let peer = conversation.id.clone();
                        let timestamp = now_ms();
                        let conversation = &mut app.conversations[app.selected];
                        conversation.disappearing = setting;
                        let notice = Message::system(
                            format!(
                                "You set disappearing messages to {}",
                                Expiration::describe(setting)
                            ),
                            timestamp,
                        );
                        let _ = store.save_message(&peer, &notice);
                        conversation.messages.push(notice);
                        conversation.selected_message = conversation.messages.len() - 1;
                        let _ = store.set_disappearing(&peer, setting);
                        store.queue_account_change(session_tui_account::AccountChange::ContactExpiry {
                            id: peer.clone(),
                            expiry: setting.map(|e| (e.kind, e.seconds)),
                        });
                        let task_client = Arc::clone(client);
                        let data_message = DataMessage {
                            timestamp: Some(timestamp),
                            flags: Some(2),
                            ..Default::default()
                        };
                        background_tasks.push((
                            spawn_network(move || async move {
                                task_client
                                    .send_data_message(&peer, data_message, setting)
                                    .await
                                    .map(|_| ())
                            }),
                            "timer update",
                        ));
                        app.status = format!(
                            "DISAPPEARING MESSAGES · {}",
                            Expiration::describe(setting)
                        );
                    }
                    "/accept" | "/decline"
                        if app
                            .conversations
                            .get(app.selected)
                            .is_some_and(|c| app.is_request(c)) =>
                    {
                        app.input.clear();
                        let conversation = &app.conversations[app.selected];
                        let peer = conversation.id.clone();
                        if command == "/accept" {
                            app.approved.insert(peer.clone());
                            store.queue_account_change(
                                session_tui_account::AccountChange::ApproveContact {
                                    id: peer,
                                    name: (conversation.name != short_id(&conversation.id))
                                        .then(|| conversation.name.clone()),
                                },
                            );
                            app.sort_conversations();
                            enqueue_missing_downloads(app, &mut download_queue);
                            app.status = "REQUEST ACCEPTED".into();
                        } else {
                            let removed = app.conversations.remove(app.selected);
                            for message in &removed.messages {
                                let _ = store.delete_message(&peer, message);
                            }
                            let _ = store.delete_empty_contact(&peer);
                            app.selected = app
                                .selected
                                .min(app.conversations.len().saturating_sub(1));
                            app.status =
                                "REQUEST DECLINED · /block STOPS THEM WRITING AGAIN".into();
                        }
                    }
                    "/accept" => {
                        app.input.clear();
                        let invites = store.local_groups(false).unwrap_or_default();
                        let current = app.conversations.get(app.selected).map(|c| c.id.clone());
                        let chosen = invites
                            .iter()
                            .rev()
                            .find(|(_, inviter)| Some(inviter) == current.as_ref())
                            .or_else(|| invites.last());
                        match chosen {
                            Some((group, _)) => {
                                let _ = store.set_group_joined(&group.id);
                                store.queue_account_change(
                                    session_tui_account::AccountChange::JoinGroup {
                                        id: group.id.clone(),
                                        name: group.name.clone(),
                                        auth_data: group.auth_data.clone(),
                                    },
                                );
                                let index = app.ensure_contact(&group.id);
                                app.conversations[index].name = group.name.clone();
                                let _ = store.save_contact_name(&group.id, &group.name);
                                app.selected = index;
                                last_sync = Instant::now();
                                start_sync(app, client, store, &mut sync_task);
                                app.status = format!("JOINING GROUP · {}", group.name);
                            }
                            None => app.status = "NO PENDING GROUP INVITES".into(),
                        }
                    }
                    _ => {
                        let body = app.input.trim().to_owned();
                        if body.is_empty() {
                            app.focus = FocusArea::Composer;
                            continue;
                        }
                        let Some(conversation) = app.conversations.get_mut(app.selected) else {
                            app.status = "ADD A CONTACT FIRST WITH CTRL+N".into();
                            continue;
                        };
                        if conversation.read_only {
                            app.status = "YOU CAN READ BUT NOT POST IN THIS GROUP".into();
                            continue;
                        }
                        if app.blocked.contains(&conversation.id) {
                            app.status = "THIS CONTACT IS BLOCKED · /unblock FIRST".into();
                            continue;
                        }
                        let peer = conversation.id.clone();
                        if peer.starts_with("05") && !app.approved.contains(&peer) {
                            // Messaging someone approves them, as in Session.
                            app.approved.insert(peer.clone());
                            store.queue_account_change(
                                session_tui_account::AccountChange::ApproveContact {
                                    id: peer.clone(),
                                    name: (conversation.name != short_id(&peer))
                                        .then(|| conversation.name.clone()),
                                },
                            );
                        }
                        let timestamp = next_outgoing_timestamp(&mut app.last_outgoing_ms);
                        let mut message = Message::new(expand_shortcodes(&body), timestamp, true);
                        message.send_state = SendState::Sending;
                        message.quote = app.reply_to.clone();
                        message.expiration = conversation.disappearing;
                        message.start_expiry(None);
                        // Saved (with its outbox entry) before the input is
                        // cleared: if that fails, nothing is lost.
                        if let Err(error) = queue_outgoing(store, &peer, &message) {
                            app.status = format!("NOT SENT · LOCAL SAVE FAILED · {error}");
                            continue;
                        }
                        app.reply_to = None;
                        conversation.messages.push(message);
                        conversation.selected_message = conversation.messages.len() - 1;
                        conversation.refresh_preview();
                        app.input.clear();
                        app.cursor = 0;
                        last_typing = None;
                        last_outbox_check = None;
                        app.sort_conversations();
                        app.status = "SENDING…".into();
                    }
                }
            }
            KeyCode::Backspace => {
                session_tui_input::backspace(&mut app.input, &mut app.cursor);
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                app.focus = FocusArea::Composer;
                let mut buffer = [0u8; 4];
                session_tui_input::insert(&mut app.input, &mut app.cursor, c.encode_utf8(&mut buffer));
                // Session-style typing indicator for 1:1 chats, at most every 10 s.
                if app.input_mode == InputMode::Message
                    && !app.input.starts_with('/')
                    && let Some(peer) = app
                        .conversations
                        .get(app.selected)
                        .map(|c| c.id.clone())
                        .filter(|id| id.starts_with("05") && *id != client.identity.session_id)
                    && last_typing
                        .as_ref()
                        .is_none_or(|(last_peer, at)| *last_peer != peer || at.elapsed() > Duration::from_secs(10))
                {
                    last_typing = Some((peer.clone(), Instant::now()));
                    let task_client = Arc::clone(client);
                    background_tasks.push((
                        spawn_network(move || async move { task_client.send_typing(&peer, true).await }),
                        "typing",
                    ));
                }
            }
            _ => {}
        }
    }
}

fn data_quote(quote: QuoteRef) -> DataQuote {
    DataQuote {
        id: quote.id,
        author: quote.author,
        text: Some(quote.text).filter(|text| !text.is_empty()),
        attachments: Vec::new(),
    }
}

/// Send a text message (already shown as "sending") in the background.
/// At most this many outbox items are sent at once.
const OUTBOX_PARALLEL: usize = 4;

/// Start one outbox item; `None` when its message no longer exists.
fn start_outbox(
    client: &Arc<SessionClient>,
    app: &mut App,
    entry: &OutboxEntry,
) -> Option<tokio::task::JoinHandle<Result<Option<String>, String>>> {
    let task_client = Arc::clone(client);
    let peer = entry.peer.clone();
    // Blocked since it was queued, or we may no longer post in the group:
    // don't send; it fails (and is kept for /retry once that changes).
    let expiry_work = matches!(entry.kind, OutboxKind::ExpireRead | OutboxKind::FetchExpiry);
    // (Expiry updates only touch our own swarm, so they always go ahead.)
    let refused = if expiry_work {
        None
    } else if app.blocked.contains(&entry.peer) {
        Some("contact is blocked")
    } else if app
        .conversations
        .iter()
        .any(|c| c.id == entry.peer && c.read_only)
        && entry.kind == OutboxKind::Text
    {
        Some("you can no longer post in this group")
    } else {
        None
    };
    if let Some(reason) = refused {
        return Some(tokio::spawn(async move { Err(reason.to_owned()) }));
    }
    match entry.kind {
        OutboxKind::Text | OutboxKind::SyncCopy => {
            let profile_name = app.profile_name.clone();
            let message = app
                .conversations
                .iter_mut()
                .find(|c| c.id == entry.peer)?
                .messages
                .iter_mut()
                .find(|m| m.outgoing && !m.system && m.timestamp_ms == entry.timestamp_ms)?;
            // Gone by the time it would go out: expired, so nothing to send.
            if message.expires_at.is_some_and(|at| at <= now_ms()) {
                return None;
            }
            let data_message = outgoing_data_message(&profile_name, message);
            let expiration = message.expiration;
            let timestamp_ms = message.timestamp_ms;
            if entry.kind == OutboxKind::Text {
                message.send_state = SendState::Sending;
                Some(spawn_network(move || async move {
                    task_client
                        .send_to_chat(&peer, data_message, expiration)
                        .await
                        .map(|()| None)
                }))
            } else {
                Some(spawn_network(move || async move {
                    let copy = task_client
                        .send_sync_copy(&peer, data_message, timestamp_ms, expiration)
                        .await;
                    if copy.sent {
                        Ok(copy.hash)
                    } else {
                        Err("sync copy failed".into())
                    }
                }))
            }
        }
        OutboxKind::ReadReceipt => {
            let timestamps: Vec<u64> = serde_json::from_slice(&entry.payload).ok()?;
            Some(spawn_network(move || async move {
                task_client.send_receipt(&peer, 1, timestamps).await.map(|()| None)
            }))
        }
        OutboxKind::ExpireRead | OutboxKind::FetchExpiry => {
            let message = outbox_message(app, entry)?;
            let hash = message.server_hash.clone()?;
            if entry.kind == OutboxKind::ExpireRead {
                let expiry = message.expires_at?;
                Some(spawn_network(move || async move {
                    task_client.expire_shorten(&hash, expiry).await.map(|()| None)
                }))
            } else {
                // Some(deadline), or None when the swarm no longer has it.
                Some(spawn_network(move || async move {
                    task_client
                        .swarm_expiry_of(&hash)
                        .await
                        .map(|expiry| Some(expiry.unwrap_or(0).to_string()))
                }))
            }
        }
    }
}

/// The message an outbox item belongs to: our outgoing message, or (for
/// expiry work) the received 1:1 message.
fn outbox_message<'a>(app: &'a mut App, entry: &OutboxEntry) -> Option<&'a mut Message> {
    let incoming = matches!(entry.kind, OutboxKind::ExpireRead | OutboxKind::FetchExpiry);
    app.conversations
        .iter_mut()
        .find(|c| c.id == entry.peer)?
        .messages
        .iter_mut()
        .find(|m| {
            m.outgoing != incoming
                && !m.system
                && m.timestamp_ms == entry.timestamp_ms
                && (!incoming || m.sender.is_none())
        })
}

/// Record the outcome of one outbox item: done (and the next step queued),
/// or failed with a later retry. The database is updated first, in one
/// transaction; the screen only changes once that has committed.
fn finish_outbox(
    app: &mut App,
    store: &LocalStore,
    entry: &OutboxEntry,
    result: Result<Option<String>, String>,
) {
    let local_id = app.local_id.clone();
    let mut updated = outbox_message(app, entry).map(|m| m.clone());
    let status;
    if let Err(error) = store.begin_batch() {
        // Left in the outbox as it was: tried again later.
        app.status = format!("SEND STATE NOT SAVED · {error}");
        return;
    }
    match &result {
        Ok(hash) => {
            debug_log("outbox.done", &format!("kind={}", entry.kind.as_str()));
            let _ = store.outbox_done(entry.id);
            status = match (entry.kind, updated.as_mut()) {
                (OutboxKind::Text, Some(message)) => {
                    message.send_state = SendState::Sent;
                    let _ = store.update_message(&entry.peer, message);
                    // Then its copy for our other devices, as its own step.
                    if entry.peer.starts_with("05") && entry.peer != local_id {
                        let _ = store.outbox_add(OutboxKind::SyncCopy, &entry.peer, entry.timestamp_ms, &[]);
                    }
                    Some("SENT".to_owned())
                }
                (OutboxKind::SyncCopy, Some(message)) => {
                    message.swarm_hashes.extend(hash.clone());
                    let _ = store.update_message(&entry.peer, message);
                    None
                }
                (OutboxKind::FetchExpiry, Some(message)) => {
                    // The deadline another device set (0: already gone).
                    // Never later than ours, as in the official clients.
                    let fetched = hash
                        .as_deref()
                        .and_then(|value| value.parse::<u64>().ok())
                        .map(|ms| if ms == 0 { now_ms() } else { ms });
                    if let Some(fetched) = fetched {
                        let deadline = message.expires_at.map_or(fetched, |ours| ours.min(fetched));
                        if message.expires_at != Some(deadline) {
                            message.expires_at = Some(deadline);
                            let _ = store.update_message(&entry.peer, message);
                        }
                    }
                    None
                }
                _ => None,
            };
        }
        Err(error) => {
            let attempts = entry.attempts + 1;
            let parked = attempts >= entry.kind.max_attempts();
            debug_log(
                "outbox.failed",
                &format!("kind={} attempt={attempts} parked={parked} error={error}", entry.kind.as_str()),
            );
            if parked
                && matches!(
                    entry.kind,
                    OutboxKind::ReadReceipt | OutboxKind::ExpireRead | OutboxKind::FetchExpiry
                )
            {
                // Receipts are only a courtesy: give up.
                let _ = store.outbox_done(entry.id);
            } else {
                // Out of automatic attempts: wait for /retry.
                let next = if parked { u64::MAX } else { now_ms() + outbox_backoff_ms(attempts) };
                let _ = store.outbox_failed(entry.id, attempts, next, error);
            }
            status = match (entry.kind, updated.as_mut()) {
                (OutboxKind::Text, Some(message)) => {
                    message.send_state = SendState::Failed;
                    let _ = store.update_message(&entry.peer, message);
                    Some(if parked {
                        format!("SEND FAILED · {error} · SELECT IT AND /retry")
                    } else {
                        format!(
                            "SEND FAILED · {error} · RETRYING IN {} S",
                            outbox_backoff_ms(attempts) / 1000
                        )
                    })
                }
                (OutboxKind::SyncCopy, Some(_)) if parked => {
                    Some("OTHER-DEVICE SYNC COPY FAILED · SELECT THE MESSAGE AND /retry".to_owned())
                }
                _ => None,
            };
        }
    }
    if let Err(error) = store.end_batch() {
        // Nothing changed: the item is retried as it was.
        debug_log("outbox.save_failed", &format!("error={error}"));
        app.status = format!("SEND STATE NOT SAVED · {error}");
        return;
    }
    if let (Some(updated), Some(message)) = (updated, outbox_message(app, entry)) {
        *message = updated;
    }
    if let Some(status) = status {
        app.status = status;
    }
}

/// Add or remove (if already ours) a reaction on a message and record it.
fn apply_reaction(message: &mut Message, emoji: &str, author: &str, remove: bool) {
    if let Some(entry) = message.reactions.iter_mut().find(|r| r.emoji == emoji) {
        entry.authors.retain(|a| a != author);
        if !remove {
            entry.authors.push(author.to_owned());
        }
    } else if !remove {
        message.reactions.push(ReactionEntry {
            emoji: emoji.to_owned(),
            authors: vec![author.to_owned()],
        });
    }
    message.reactions.retain(|r| !r.authors.is_empty());
}

/// Toggle our `emoji` reaction on the selected message (Session behaviour:
/// reacting again with the same emoji removes it).
fn react_to_selected(
    app: &mut App,
    client: &Arc<SessionClient>,
    store: &LocalStore,
    emoji: &str,
    tasks: &mut Vec<(tokio::task::JoinHandle<Result<(), String>>, &'static str)>,
) {
    let local_id = client.identity.session_id.clone();
    let Some(conversation) = app.conversations.get_mut(app.selected) else {
        return;
    };
    if conversation.read_only {
        app.status = "YOU CAN READ BUT NOT POST IN THIS GROUP".into();
        return;
    }
    let peer = conversation.id.clone();
    let expiration = conversation.disappearing;
    let Some(message) = conversation.messages.get_mut(conversation.selected_message) else {
        app.status = "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
        return;
    };
    if message.system || message.send_state != SendState::Sent {
        app.status = "THIS MESSAGE CAN'T TAKE REACTIONS".into();
        return;
    }
    let remove = message
        .reactions
        .iter()
        .any(|r| r.emoji == emoji && r.authors.contains(&local_id));
    let author = message.author(&peer, &local_id).to_owned();
    let target = message.timestamp_ms;
    apply_reaction(message, emoji, &local_id, remove);
    let _ = store.update_message(&peer, message);
    let timestamp = now_ms();
    let data_message = DataMessage {
        timestamp: Some(timestamp),
        reaction: Some(libsession::proto::session_protos::data_message::Reaction {
            id: target,
            author,
            emoji: Some(emoji.to_owned()),
            action: i32::from(remove),
        }),
        profile: profile_for(&app.profile_name, timestamp),
        ..Default::default()
    };
    let task_client = Arc::clone(client);
    tasks.push((
        spawn_network(move || async move {
            task_client
                .send_data_message(&peer, data_message, expiration)
                .await
                .map(|_| ())
        }),
        "reaction",
    ));
    app.status = if remove {
        format!("REACTION {emoji} REMOVED")
    } else {
        format!("REACTED {emoji}")
    };
}

/// Delete the selected message on this device, and for `everyone` also
/// unsend it (our own sent messages only). Returns the status line.
fn delete_selected(
    app: &mut App,
    client: &Arc<SessionClient>,
    store: &LocalStore,
    tasks: &mut Vec<(tokio::task::JoinHandle<Result<(), String>>, &'static str)>,
    everyone: bool,
) -> String {
    let Some(peer) = app.conversations.get(app.selected).map(|c| c.id.clone()) else {
        return "NO CHAT SELECTED".into();
    };
    let Some(removed) = app.remove_selected_message() else {
        return "SELECT A MESSAGE WITH ↑/↓ FIRST".into();
    };
    if everyone && removed.outgoing {
        // Removed here at once, like Session; the unsend request (to the
        // chat and to our other devices) goes out in the background.
        let task_client = Arc::clone(client);
        let timestamp = removed.timestamp_ms;
        let own_hashes = removed.swarm_hashes.clone();
        let task_peer = peer.clone();
        tasks.push((
            spawn_network(move || async move {
                task_client
                    .unsend_message(&task_peer, timestamp, own_hashes)
                    .await
            }),
            "unsend",
        ));
    }
    if let Err(error) = store.delete_message(&peer, &removed) {
        return format!("LOCAL DELETE ERROR · {error}");
    }
    if everyone {
        "MESSAGE DELETED FOR EVERYONE".into()
    } else {
        "MESSAGE DELETED ON THIS DEVICE".into()
    }
}

/// Delete disappearing messages whose timer has run out.
fn remove_expired_messages(app: &mut App, store: &LocalStore) {
    let now = now_ms();
    for conversation in &mut app.conversations {
        if !conversation
            .messages
            .iter()
            .any(|m| m.expires_at.is_some_and(|at| at <= now))
        {
            continue;
        }
        let peer = conversation.id.clone();
        conversation.messages.retain(|message| {
            let expired = message.expires_at.is_some_and(|at| at <= now);
            if expired {
                let _ = store.delete_message(&peer, message);
            }
            !expired
        });
        conversation.clamp_selection();
        conversation.refresh_preview();
    }
}

/// Bring the local view in line with the account config shared by this
/// account's devices.
fn apply_account_state(
    app: &mut App,
    store: &LocalStore,
    state: &session_tui_account::AccountState,
) {
    let pending = store.pending_account_changes();
    if let Some(name) = state.profile_name.as_deref()
        && !pending
            .iter()
            .any(|c| matches!(c, session_tui_account::AccountChange::ProfileName(_)))
        && app.profile_name != name
    {
        app.profile_name = name.to_owned();
        let _ = store.save_profile_name(name);
    }
    app.blocked.clear();
    app.approved.clear();
    for contact in &state.contacts {
        if contact.blocked {
            app.blocked.insert(contact.id.clone());
        }
        if contact.approved {
            app.approved.insert(contact.id.clone());
        }
        if contact.id == app.local_id || !(contact.approved || contact.blocked) {
            continue;
        }
        // Chat deleted (here or on another device): drop it unless new
        // messages arrived since.
        if contact.hidden {
            if let Some(index) = app.conversations.iter().position(|c| c.id == contact.id)
                && app.conversations[index].messages.is_empty()
            {
                app.conversations.remove(index);
                app.selected = app.selected.min(app.conversations.len().saturating_sub(1));
                let _ = store.delete_empty_contact(&contact.id);
            }
            continue;
        }
        let index = app.ensure_contact(&contact.id);
        let _ = store.save_contact(&contact.id);
        let conversation = &mut app.conversations[index];
        if let Some(name) = contact.name.as_deref()
            && conversation.name != name
        {
            conversation.name = name.to_owned();
            let _ = store.save_contact_name(&contact.id, name);
        }
        let expiry = contact.expiry.map(|(kind, seconds)| Expiration { kind, seconds });
        let pending_expiry = pending.iter().any(|c| {
            matches!(c, session_tui_account::AccountChange::ContactExpiry { id, .. } if *id == contact.id)
        });
        if !pending_expiry && conversation.disappearing != expiry {
            conversation.disappearing = expiry;
            let _ = store.set_disappearing(&contact.id, expiry);
        }
    }
    // Messages read on another device.
    let now = now_ms();
    for (conversation_id, last_read) in &state.last_read {
        let Some(conversation) = app.conversations.iter_mut().find(|c| c.id == *conversation_id)
        else {
            continue;
        };
        let peer = conversation.id.clone();
        for message in &mut conversation.messages {
            if !message.outgoing && !message.is_read && message.timestamp_ms as i64 <= *last_read {
                message.is_read = true;
                let _ = store.mark_message_read(&peer, message);
                if expires_after_read_on_our_swarm(&peer, message) {
                    // Read on another device. If that device already
                    // shortened the swarm copy, its deadline is the real
                    // one; else start now, shorten it ourselves and ask the
                    // swarm (the earlier deadline wins), as the official
                    // clients do.
                    let timer = message.expiration.map_or(0, |e| u64::from(e.seconds) * 1000);
                    match message.swarm_expiry.filter(|at| *at <= now + timer) {
                        Some(deadline) => message.expires_at = Some(deadline),
                        None => {
                            message.start_expiry(Some(now));
                            let _ = store.outbox_add(OutboxKind::ExpireRead, &peer, message.timestamp_ms, &[]);
                            let _ = store.outbox_add(OutboxKind::FetchExpiry, &peer, message.timestamp_ms, &[]);
                        }
                    }
                    let _ = store.update_message(&peer, message);
                } else if message.expiration.is_some() {
                    message.start_expiry(Some(now));
                    let _ = store.update_message(&peer, message);
                }
            }
        }
    }
    app.sort_conversations();
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
    let (cursor, group_cursors, local_groups) = match (
        store.get_last_hash(),
        store.get_group_cursors(),
        store.local_groups(true),
    ) {
        (Ok(hash), Ok(groups), Ok(local)) => {
            (hash, groups, local.into_iter().map(|(group, _)| group).collect())
        }
        (Err(error), _, _) | (_, Err(error), _) | (_, _, Err(error)) => {
            app.status = format!("SYNC CURSOR ERROR · {error}");
            return;
        }
    };
    app.status = "SYNCING IN BACKGROUND · TYPE /? FOR HELP".into();
    debug_log(
        "sync.spawn",
        &format!("cursor_present={}", cursor.is_some()),
    );
    let account_dumps = store.account_dumps();
    let account_changes = store.pending_account_changes();
    let client = Arc::clone(client);
    // Network bootstrap keeps ThreadRng across an await, making the future
    // !Send, so it runs on a dedicated current-thread runtime.
    *task = Some(spawn_network(move || async move {
        match tokio::time::timeout(
            Duration::from_secs(90),
            client.retrieve_messages(
                cursor.as_deref(),
                group_cursors,
                local_groups,
                account_dumps,
                account_changes,
            ),
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

/// Carry out a confirmed `/delete` or `/remove`; returns the status line.
fn delete_chat(app: &mut App, store: &LocalStore, action: ChatAction, id: &str) -> String {
    let Some(index) = app.conversations.iter().position(|c| c.id == id) else {
        return "CHAT NOT FOUND".into();
    };
    let removed = app.conversations.remove(index);
    for message in &removed.messages {
        let _ = store.delete_message(id, message);
    }
    let _ = store.delete_empty_contact(id);
    if app.selected > index || app.selected >= app.conversations.len() {
        app.selected = app.selected.saturating_sub(1);
    }
    let one_to_one = id.starts_with("05") && id != app.local_id;
    match action {
        ChatAction::Remove => {
            app.approved.remove(id);
            store.queue_account_change(session_tui_account::AccountChange::RemoveContact {
                id: id.to_owned(),
            });
            "CONTACT REMOVED · NEW MESSAGES FROM THEM ARRIVE AS A REQUEST".into()
        }
        ChatAction::Delete if one_to_one => {
            store.queue_account_change(session_tui_account::AccountChange::HideContact {
                id: id.to_owned(),
            });
            "CHAT DELETED".into()
        }
        ChatAction::Delete if id.starts_with("03") => {
            "GROUP HISTORY DELETED · THE GROUP STAYS UNTIL YOU LEAVE IT".into()
        }
        ChatAction::Delete => "CHAT DELETED".into(),
    }
}

/// Mark the open chat read. The read flags, disappear-after-read timers,
/// the read state for other devices and the read receipt are written in one
/// transaction and only then applied on screen: either all of it happens,
/// or none of it and it is tried again on the next pass. Returns true when
/// a read receipt was queued.
fn mark_current_conversation_read(app: &mut App, store: &LocalStore) -> bool {
    let Some(conversation) = app.conversations.get(app.selected) else {
        return false;
    };
    // A message request must not tell the stranger it was read; groups and
    // Note to Self get no receipts.
    let wants_receipt = !app.is_request(conversation)
        && conversation.id.starts_with("05")
        && conversation.id != app.local_id;
    let peer = conversation.id.clone();
    let now = now_ms();
    let updated: Vec<(usize, Message)> = conversation
        .messages
        .iter()
        .enumerate()
        .filter(|(_, m)| !m.outgoing && !m.is_read)
        .map(|(index, m)| {
            let mut m = m.clone();
            m.is_read = true;
            if m.expiration.is_some() {
                m.start_expiry(Some(now));
            }
            (index, m)
        })
        .collect();
    if updated.is_empty() {
        return false;
    }
    let timestamps: Vec<u64> = updated.iter().map(|(_, m)| m.timestamp_ms).collect();
    if let Err(error) = store.begin_batch() {
        app.status = format!("READ STATE SAVE FAILED · {error}");
        return false;
    }
    for (_, message) in &updated {
        let _ = store.mark_message_read(&peer, message);
        if message.expiration.is_some() {
            let _ = store.update_message(&peer, message);
        }
        if expires_after_read_on_our_swarm(&peer, message) {
            // Tell our swarm too, so other devices see the same deadline.
            let _ = store.outbox_add(OutboxKind::ExpireRead, &peer, message.timestamp_ms, &[]);
        }
    }
    if let Some(latest) = timestamps.iter().max() {
        store.queue_account_change(session_tui_account::AccountChange::ReadUpTo {
            conversation: peer.clone(),
            timestamp_ms: *latest as i64,
        });
    }
    if wants_receipt {
        let payload = serde_json::to_vec(&timestamps).unwrap_or_default();
        let _ = store.outbox_add(OutboxKind::ReadReceipt, &peer, 0, &payload);
    }
    if let Err(error) = store.end_batch() {
        app.status = format!("READ STATE SAVE FAILED · {error}");
        return false;
    }
    let conversation = &mut app.conversations[app.selected];
    for (index, message) in updated {
        conversation.messages[index] = message;
    }
    wants_receipt
}

/// A received 1:1 message that disappears after being read and lives in our
/// own swarm, whose expiry we can update there.
fn expires_after_read_on_our_swarm(peer: &str, message: &Message) -> bool {
    !message.outgoing
        && message.sender.is_none()
        && peer.starts_with("05")
        && message.server_hash.is_some()
        && message.expiration.is_some_and(|e| e.kind == 1 && e.seconds > 0)
}

/// Which messages a group "delete content" command removes.
struct DeleteContent<'a> {
    /// Carries a valid admin signature.
    admin: bool,
    /// Who sent the command.
    author: &'a str,
    ids: &'a [String],
    hashes: &'a [String],
    /// Signature timestamp: later messages are never affected.
    before_ms: u64,
}

impl DeleteContent<'_> {
    fn matches(&self, message: &Message, local_id: &str) -> bool {
        if message.system || message.timestamp_ms > self.before_ms {
            return false;
        }
        let author = if message.outgoing {
            Some(local_id)
        } else {
            message.sender.as_deref()
        };
        let by_hash = message
            .server_hash
            .as_ref()
            .is_some_and(|hash| self.hashes.contains(hash));
        if self.admin {
            let by_member = author.is_some_and(|author| {
                author.starts_with("05") && self.ids.iter().any(|id| id == author)
            });
            by_member || by_hash
        } else {
            by_hash && author == Some(self.author)
        }
    }
}

/// Check a `GroupUpdateDeleteMemberContentMessage` admin signature: Ed25519
/// by the group key (the group ID without its `03` prefix) over
/// `"DELETE_CONTENT" ‖ timestamp ‖ member IDs ‖ message hashes`, as the
/// official clients sign it.
fn verify_delete_content_signature(
    group_id: &str,
    timestamp_ms: u64,
    ids: &[String],
    hashes: &[String],
    signature: &[u8],
) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let Some(key) = group_id
        .strip_prefix("03")
        .and_then(|hex_key| hex::decode(hex_key).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .and_then(|bytes| VerifyingKey::from_bytes(&bytes).ok())
    else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    let signed = format!("DELETE_CONTENT{timestamp_ms}{}{}", ids.concat(), hashes.concat());
    key.verify(signed.as_bytes(), &signature).is_ok()
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

/// Network work kept in the `outbox` table until it succeeds, so a restart,
/// lost connection or crash doesn't lose it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutboxKind {
    /// An outgoing message (the row in `messages`) to its chat.
    Text,
    /// Its copy for this account's other devices (1:1 chats), sent after
    /// the message itself; retried on its own.
    SyncCopy,
    /// Read receipt; payload is the JSON list of message timestamps.
    ReadReceipt,
    /// We read a received disappear-after-read message: shorten its life
    /// on our swarm to the local deadline.
    ExpireRead,
    /// It was read on another device: fetch the deadline that device set.
    FetchExpiry,
}

impl OutboxKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::SyncCopy => "sync_copy",
            Self::ReadReceipt => "read_receipt",
            Self::ExpireRead => "expire_read",
            Self::FetchExpiry => "fetch_expiry",
        }
    }

    fn parse(kind: &str) -> Option<Self> {
        match kind {
            "text" => Some(Self::Text),
            "sync_copy" => Some(Self::SyncCopy),
            "read_receipt" => Some(Self::ReadReceipt),
            "expire_read" => Some(Self::ExpireRead),
            "fetch_expiry" => Some(Self::FetchExpiry),
            _ => None,
        }
    }

    /// Automatic attempts before giving up (a message then waits for /retry).
    fn max_attempts(self) -> u32 {
        match self {
            Self::Text | Self::SyncCopy => 10,
            Self::ReadReceipt | Self::ExpireRead | Self::FetchExpiry => 6,
        }
    }
}

#[derive(Clone, Debug)]
struct OutboxEntry {
    id: i64,
    kind: OutboxKind,
    peer: String,
    timestamp_ms: u64,
    payload: Vec<u8>,
    attempts: u32,
}

/// Wait before automatic attempt `attempts + 1`: 5 s, 15 s, 45 s … up to
/// 15 minutes, so a flaky connection is retried quickly and a dead one
/// isn't hammered.
fn outbox_backoff_ms(attempts: u32) -> u64 {
    (5_000u64.saturating_mul(3u64.saturating_pow(attempts.saturating_sub(1)))).min(15 * 60 * 1000)
}

/// The DataMessage of a stored outgoing message, rebuilt for (re)sending:
/// same timestamp, so a repeat is recognised as the same message.
fn outgoing_data_message(profile_name: &str, message: &Message) -> DataMessage {
    DataMessage {
        body: (!message.body.is_empty() || message.attachments.is_empty())
            .then(|| message.body.clone()),
        timestamp: Some(message.timestamp_ms),
        attachments: message.attachments.iter().map(attachment_pointer_from_meta).collect(),
        profile: profile_for(profile_name, message.timestamp_ms),
        quote: message.quote.clone().map(data_quote),
        ..Default::default()
    }
}

/// Timestamp for a new outgoing message: the current time, but always
/// later than the previous one. The timestamp is the message's identity in
/// the protocol and in the database, so two messages sent in the same
/// millisecond must not share it.
fn next_outgoing_timestamp(last: &mut u64) -> u64 {
    let timestamp = now_ms().max(*last + 1);
    *last = timestamp;
    timestamp
}

/// Queue a new outgoing text: saved with its outbox entry in one
/// transaction before anything is sent, so it survives a crash or restart.
fn queue_outgoing(store: &LocalStore, peer: &str, message: &Message) -> Result<(), String> {
    store.begin_batch()?;
    // A new message must be a new row: a clash is an error, not "already
    // known" as for messages fetched from the network.
    let _ = store.insert_new_message(peer, message);
    let _ = store.outbox_add(OutboxKind::Text, peer, message.timestamp_ms, &[]);
    store.end_batch()
}

/// App state as it was before a sync was applied (restored on rollback).
struct SyncSnapshot {
    conversations: Vec<Conversation>,
    display_names: HashMap<String, String>,
    approved: HashSet<String>,
    blocked: HashSet<String>,
    profile_name: String,
    seen_hashes: HashSet<String>,
    selected: usize,
    downloads: usize,
}

fn finish_sync(
    app: &mut App,
    store: &LocalStore,
    local_id: &str,
    result: Result<RetrieveResult, String>,
    download_queue: &mut std::collections::VecDeque<PendingDownload>,
    committed_cursors: Option<&Mutex<HashMap<String, String>>>,
) -> usize {
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            debug_log("sync.failed", "request_failed=true");
            app.status = format!("SYNC FAILED · {error}");
            return 0;
        }
    };
    let mut notify = 0usize;
    let mut result = result;
    // Everything from this sync is written in one transaction, and the
    // sync cursor and "seen" marks commit together with the messages. If any
    // write fails, the database rolls back and the in-memory state is put
    // back as it was, so the next sync fetches and saves the same messages
    // again: "retry", never "skipped".
    if let Err(error) = store.begin_batch() {
        app.status = format!("SYNC SAVE ERROR · WILL RETRY · {error}");
        return 0;
    }
    // Anything in the result that can change the in-memory state needs a
    // snapshot to roll back to.
    let changes_state = !result.messages.is_empty()
        || result.account.is_some()
        || !result.groups.is_empty()
        || !result.invite_responses.is_empty();
    let snapshot = changes_state.then(|| SyncSnapshot {
        conversations: app.conversations.clone(),
        display_names: app.display_names.clone(),
        approved: app.approved.clone(),
        blocked: app.blocked.clone(),
        profile_name: app.profile_name.clone(),
        seen_hashes: app.seen_hashes.clone(),
        selected: app.selected,
        downloads: download_queue.len(),
    });
    if let Some(account) = result.account.take() {
        for (slot, dump) in account.dumps.iter().enumerate() {
            if let Some(dump) = dump {
                let _ = store.save_account_dump(slot, dump);
            }
        }
        if !account.applied.is_empty() {
            // Changes queued while this sync ran stay pending.
            let mut pending = store.pending_account_changes();
            for applied in &account.applied {
                if let Some(index) = pending.iter().position(|change| change == applied) {
                    pending.remove(index);
                }
            }
            let _ = store.set_pending_account_changes(&pending);
        }
        apply_account_state(app, store, &account.state);
    }
    let groups_found = result.groups.len();
    for group in result.groups.iter() {
        let index = app.ensure_contact(&group.id);
        app.conversations[index].name = group.name.clone();
        app.conversations[index].read_only = !group.can_write;
        let _ = store.save_contact_name(&group.id, &group.name);
    }
    for group in &result.invite_responses {
        let _ = store.set_group_responded(group);
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
    let last_hash = result.last_hash.take();
    let group_cursors = std::mem::take(&mut result.group_cursors);
    let node_cursors = std::mem::take(&mut result.node_cursors);
    let mut added = 0;
    for mut message in result.messages {
        let is_new = store.mark_seen(&message.hash).unwrap_or(false);
        if !is_new || !app.seen_hashes.insert(message.hash.clone()) {
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
            // A receipt can arrive before the message it confirms (e.g. the
            // sync copy of something sent from the phone): keep it, and
            // apply it when that message shows up.
            for timestamp in &timestamps {
                let known = app
                    .conversations
                    .iter()
                    .find(|c| c.id == message.sender_id)
                    .is_some_and(|c| c.messages.iter().any(|m| m.outgoing && m.timestamp_ms == *timestamp));
                if !known {
                    let _ = store.save_pending_receipt(&message.sender_id, *timestamp, status);
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
        if !message.outgoing && app.blocked.contains(&message.sender_id) && !is_group {
            // Session drops 1:1 messages from blocked contacts.
            continue;
        }
        if let Some(started) = message.typing {
            if !message.outgoing
                && let Some(conversation) =
                    app.conversations.iter_mut().find(|c| c.id == message.contact_id)
            {
                let fresh = now_ms().saturating_sub(message.timestamp_ms) < 20_000;
                conversation.typing_until = (started && fresh)
                    .then(|| Instant::now() + Duration::from_secs(15));
            }
            continue;
        }
        if let Some((target, target_author, emoji, remove)) = message.reaction.take() {
            let author = message.sender_id.clone();
            if let Some(conversation) =
                app.conversations.iter_mut().find(|c| c.id == message.contact_id)
            {
                let peer = conversation.id.clone();
                if let Some(target_message) = conversation.messages.iter_mut().find(|m| {
                    m.timestamp_ms == target && m.author(&peer, local_id) == target_author
                }) {
                    apply_reaction(target_message, &emoji, &author, remove);
                    let _ = store.update_message(&peer, target_message);
                    added += 1;
                }
            }
            continue;
        }
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
        if let Some(event) = message.event.take() {
            let actor = if message.outgoing {
                "You".to_owned()
            } else {
                app.sender_label(&message.sender_id)
            };
            let text = match event {
                ChatEvent::Notice(text) => format!("{actor} {text}"),
                ChatEvent::TimerChanged(setting) => {
                    let index = app.ensure_contact(&message.contact_id);
                    app.conversations[index].disappearing = setting;
                    let _ = store.set_disappearing(&message.contact_id, setting);
                    format!(
                        "{actor} set disappearing messages to {}",
                        Expiration::describe(setting)
                    )
                }
                ChatEvent::Members { action, ids } => {
                    let names: Vec<String> = ids.iter().map(|id| app.sender_label(id)).collect();
                    format!("{actor} {action} {}", names.join(", "))
                }
                ChatEvent::Invite(group) => {
                    if !group.id.starts_with("03") || group.id.len() != 66 {
                        continue;
                    }
                    let _ = store.save_invite(&group, &message.sender_id);
                    format!(
                        "{actor} invited you to the group \"{}\" · type /accept to join",
                        group.name
                    )
                }
                ChatEvent::DeleteMemberContent {
                    ids,
                    hashes,
                    signature,
                } => {
                    // As the official clients: without an admin signature the
                    // sender may delete only their own messages, by hash; a
                    // valid admin signature (group key) allows deleting by
                    // member and by hash; an invalid one drops the command.
                    // Only messages sent up to the command's time count.
                    let signature = signature.filter(|s| !s.is_empty());
                    let admin = match signature.as_deref() {
                        None => false,
                        Some(signature) => {
                            if !verify_delete_content_signature(
                                &message.contact_id,
                                message.timestamp_ms,
                                &ids,
                                &hashes,
                                signature,
                            ) {
                                debug_log("group.delete_content", "invalid_signature=true dropped=true");
                                continue;
                            }
                            true
                        }
                    };
                    let rule = DeleteContent {
                        admin,
                        author: &message.sender_id,
                        ids: &ids,
                        hashes: &hashes,
                        before_ms: message.timestamp_ms,
                    };
                    let mut removed = 0usize;
                    if let Some(conversation) =
                        app.conversations.iter_mut().find(|c| c.id == message.contact_id)
                    {
                        let peer = conversation.id.clone();
                        conversation.messages.retain(|m| {
                            let remove = rule.matches(m, local_id);
                            if remove {
                                removed += 1;
                                let _ = store.delete_message(&peer, m);
                            }
                            !remove
                        });
                        conversation.clamp_selection();
                        conversation.refresh_preview();
                    }
                    if removed == 0 {
                        continue;
                    }
                    format!("{actor} removed {removed} message(s)")
                }
            };
            let index = app.ensure_contact(&message.contact_id);
            let conversation = &mut app.conversations[index];
            if conversation
                .messages
                .iter()
                .any(|m| m.system && m.body == text && m.timestamp_ms == message.timestamp_ms)
            {
                continue;
            }
            let notice = Message::system(text, message.timestamp_ms);
            let _ = store.save_message(&message.contact_id, &notice);
            let position = conversation
                .messages
                .iter()
                .position(|m| m.timestamp_ms > notice.timestamp_ms)
                .unwrap_or(conversation.messages.len());
            conversation.messages.insert(position, notice);
            conversation.clamp_selection();
            added += 1;
            continue;
        }
        let body = message.body.take().unwrap_or_default();
        if body.is_empty() && message.attachments.is_empty() {
            continue;
        }
        if let Some(conversation) =
            app.conversations.iter_mut().find(|c| c.id == message.contact_id)
            && !message.outgoing
        {
            conversation.typing_until = None;
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
        if let Some(existing) = convo.messages.iter_mut().find(|m| {
            m.timestamp_ms == message.timestamp_ms
                && m.outgoing == message.outgoing
                && (m.sender.is_none() || m.sender == sender)
        }) {
            // Our own sync copy coming back: remember its swarm hash so an
            // unsend can delete it.
            if message.outgoing && !is_group && !existing.swarm_hashes.contains(&message.hash) {
                existing.swarm_hashes.push(message.hash.clone());
                let _ = store.update_message(&message.contact_id, existing);
            }
            if is_group && existing.server_hash.is_none() {
                existing.server_hash = Some(message.hash.clone());
                let _ = store.update_message(&message.contact_id, existing);
            }
            continue;
        }
        let mut local_message = Message::new(body, message.timestamp_ms, message.outgoing);
        // Incoming messages stay unread until the chat is on screen; the
        // main loop then marks them read and sends the read receipt.
        local_message.is_read = message.outgoing;
        local_message.sender = sender;
        if message.outgoing && !is_group {
            // Sent from another of our devices: this is its copy in our swarm.
            local_message.swarm_hashes.push(message.hash.clone());
        }
        if is_group || !message.outgoing {
            local_message.server_hash = Some(message.hash.clone());
        }
        if !is_group && !message.outgoing {
            local_message.swarm_expiry = message.swarm_expiry;
        }
        local_message.quote = message.quote.take();
        local_message.links = std::mem::take(&mut message.links);
        local_message.expiration = message.expiration;
        local_message.start_expiry(None);
        local_message.image_previews = vec![None; message.attachments.len()];
        if local_message.outgoing
            && let Some(status) = store.take_pending_receipt(&message.contact_id, message.timestamp_ms)
        {
            local_message.receipt_status = local_message.receipt_status.max(status);
        }
        for (attachment_index, meta) in message.attachments.iter().enumerate() {
            download_queue.push_back(PendingDownload {
                peer: message.contact_id.clone(),
                sender: local_message.sender.clone(),
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
        if !message.outgoing && (index != app.selected || !app.window_focused) {
            notify += 1;
        }
    }
    if let Some(index) = app
        .conversations
        .iter()
        .position(|c| c.id == local_id && c.messages.is_empty())
        && index != app.selected
    {
        let _ = store.delete_empty_contact(local_id);
        let selected_id = app.conversations.get(app.selected).map(|c| c.id.clone());
        app.conversations.remove(index);
        app.selected = selected_id
            .and_then(|id| app.conversations.iter().position(|c| c.id == id))
            .unwrap_or(0);
    }
    // Cursors last, then commit only if every write of this sync worked.
    if let Some(last_hash) = last_hash.as_deref() {
        let _ = store.set_last_hash(last_hash);
    }
    for (group, hash) in &group_cursors {
        let _ = store.set_group_cursor(group, hash);
    }
    for (key, hash) in &node_cursors {
        let _ = store.set_node_cursor(key, hash);
    }
    if let Err(error) = store.end_batch() {
        if let Some(snapshot) = snapshot {
            app.conversations = snapshot.conversations;
            app.display_names = snapshot.display_names;
            app.approved = snapshot.approved;
            app.blocked = snapshot.blocked;
            app.profile_name = snapshot.profile_name;
            app.seen_hashes = snapshot.seen_hashes;
            app.selected = snapshot.selected;
            download_queue.truncate(snapshot.downloads);
        }
        debug_log("sync.rollback", &format!("error={error}"));
        app.status = format!("SYNC SAVE ERROR · WILL RETRY · {error}");
        return 0;
    }
    // Committed: the next sync may start from these cursors.
    if let Some(cursors) = committed_cursors
        && let Ok(mut cursors) = cursors.lock()
    {
        cursors.extend(node_cursors);
    }
    if added > 0 {
        app.sort_conversations();
    }
    app.status = format!(
        "SYNC · {added} NEW · {groups_found} GROUPS · {} QUEUED · {} DECRYPT FAIL · {} BAD ENVELOPE · {} BAD CONTENT",
        result.queued, result.undecryptable, result.bad_envelope, result.bad_content
    );
    notify
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
    let image_area = draw_screen(frame, app);
    sanitize_buffer(frame.buffer_mut(), image_area);
}

/// Remove control characters from what is about to be written to the
/// terminal. Names, messages, file names and link titles come from other
/// people; written raw, ESC/OSC sequences in them could clear or fake the
/// screen, retitle the window or overwrite the clipboard (OSC 52). The
/// image viewer's own escape sequences (`image_area`) are left alone.
fn sanitize_buffer(buffer: &mut ratatui::buffer::Buffer, image_area: Option<Rect>) {
    let area = buffer.area;
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            if image_area.is_some_and(|r| x >= r.x && x < r.right() && y >= r.y && y < r.bottom()) {
                continue;
            }
            let cell = &mut buffer[(x, y)];
            if cell.symbol().chars().any(char::is_control) {
                let clean: String = cell.symbol().chars().filter(|c| !c.is_control()).collect();
                cell.set_symbol(if clean.is_empty() { " " } else { &clean });
            }
        }
    }
}

fn draw_screen(frame: &mut ratatui::Frame<'_>, app: &mut App) -> Option<Rect> {
    let mut image_area = None;
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
    app.header_area = Some(root[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(clamp_sidebar_width(app.sidebar_width, root[1].width)),
            Constraint::Min(0),
        ])
        .split(root[1]);
    app.sidebar_width = columns[0].width;
    app.divider = Some(Rect {
        x: columns[0].right().saturating_sub(1),
        width: 1,
        ..columns[0]
    });
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
        Span::styled("⇧Enter", Style::default().fg(TEAL)),
        Span::styled(" new line  ", Style::default().fg(MUTED)),
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
        draw_help(frame, area, app.help_scroll);
    }
    if let Some(can_unsend) = app.delete_prompt {
        let text = if can_unsend {
            "  1 Delete on this device only    2 Delete for everyone    Esc cancel"
        } else {
            "  1 Delete on this device only    Esc cancel"
        };
        let width = (text.chars().count() as u16 + 4).min(area.width);
        let popup = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y + area.height.saturating_sub(6),
            width,
            height: 3.min(area.height),
        };
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, Style::default().fg(TEXT)))).block(
                Block::default()
                    .title(" Delete message ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(PANEL)),
            ),
            popup,
        );
    }
    if let Some((action, id)) = &app.chat_prompt {
        let name = app
            .conversations
            .iter()
            .find(|c| c.id == *id)
            .map_or("", |c| c.title(&app.local_id));
        let (title, text) = match action {
            ChatAction::Delete => (
                " Delete chat ",
                format!("  Delete the chat with {name} and all its messages?    Y yes    Esc no"),
            ),
            ChatAction::Remove => (
                " Remove contact ",
                format!("  Remove {name} from your contacts and delete the chat?    Y yes    Esc no"),
            ),
        };
        let width = (text.chars().count() as u16 + 4).min(area.width);
        let popup = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y + area.height.saturating_sub(6),
            width,
            height: 3.min(area.height),
        };
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, Style::default().fg(TEXT)))).block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(PANEL)),
            ),
            popup,
        );
    }
    if app.reaction_picker {
        let width = 46.min(area.width);
        let popup = Rect {
            x: area.x + area.width.saturating_sub(width) / 2,
            y: area.y + area.height.saturating_sub(6),
            width,
            height: 3.min(area.height),
        };
        frame.render_widget(Clear, popup);
        let mut spans = Vec::new();
        for (index, emoji) in QUICK_REACTIONS.iter().enumerate() {
            spans.push(Span::styled(format!(" {}", index + 1), Style::default().fg(TEAL)));
            spans.push(Span::styled(format!(" {emoji} "), Style::default().fg(TEXT)));
        }
        frame.render_widget(
            Paragraph::new(Line::from(spans)).block(
                Block::default()
                    .title(" React · 1-6 · Esc ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(TEAL))
                    .style(Style::default().bg(PANEL)),
            ),
            popup,
        );
    }
    if app.show_emoji {
        let popup = centered_rect(80, 60, area);
        frame.render_widget(Clear, popup);
        let entries: Vec<String> = EMOJI_SHORTCODES
            .iter()
            .map(|(code, emoji)| format!("{emoji} :{code}:"))
            .collect();
        let lines: Vec<Line<'_>> = entries
            .chunks(4)
            .map(|row| {
                Line::from(
                    row.iter()
                        .map(|entry| format!("{entry:<20}"))
                        .collect::<String>(),
                )
            })
            .collect();
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .title(" Emoji shortcodes · type :name: in a message or /react · any key closes ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(TEAL))
                    .style(Style::default().bg(PANEL)),
            ),
            popup,
        );
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
        image_area = Some(inner);
    }
    image_area
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
        Line::from(Span::styled(
            "Press C or click to copy · Enter when saved",
            Style::default().fg(TEAL),
        )),
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

/// Keep the chat list wide enough to read and the chat window usable.
fn clamp_sidebar_width(width: u16, total: u16) -> u16 {
    let max = total.saturating_sub(MIN_CHAT_WIDTH).max(MIN_SIDEBAR_WIDTH);
    width.clamp(MIN_SIDEBAR_WIDTH, max).min(total)
}

fn draw_conversations(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    let active = app.focus == FocusArea::Contacts;
    // Room for text: minus the marker, padding and the right border.
    let text_width = (area.width as usize).saturating_sub(4);
    let requests = app.conversations.iter().filter(|c| app.is_request(c)).count();
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
        Span::styled(
            if requests > 0 {
                format!("  {requests} request{}", if requests == 1 { "" } else { "s" })
            } else {
                String::new()
            },
            Style::default().fg(Color::Yellow),
        ),
        Span::styled("  Ctrl+N +", Style::default().fg(TEAL)),
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
            let request = app.is_request(c);
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
                            " {}{}{}",
                            // The number `/N` switches to.
                            if i < 9 { format!("{} ", i + 1) } else { "  ".to_owned() },
                            if c.id.starts_with("03") { "# " } else { "" },
                            c.title(&app.local_id)
                        ),
                        Style::default()
                            .fg(entry_color)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(unread, Style::default().fg(BLUE)),
                ]),
                if request {
                    Line::from(Span::styled(
                        "   REQUEST · /accept /decline",
                        Style::default().fg(Color::Yellow),
                    ))
                } else {
                    Line::from(Span::styled(
                        format!(
                            "   {}",
                            c.preview.chars().take(text_width.saturating_sub(1)).collect::<String>()
                        ),
                        Style::default().fg(MUTED),
                    ))
                },
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

/// Every Line is exactly one screen row: text is wrapped here, so scroll
/// positions and click targets are exact.
fn push_wrapped(lines: &mut Vec<Line<'static>>, width: usize, indent: &str, text: &str, style: Style) {
    let (rows, _) = session_tui_input::wrap(text, 0, width.saturating_sub(indent.len()).max(4));
    for row in rows {
        lines.push(Line::from(Span::styled(format!("{indent}{row}"), style)));
    }
}

/// Everything that decides how many rows a message takes at `width`.
/// Selection, ticks and timers only change the content of a row.
fn message_layout_key(app: &App, message: &Message, width: usize) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    width.hash(&mut hasher);
    message.system.hash(&mut hasher);
    message.body.hash(&mut hasher);
    message.timestamp_ms.hash(&mut hasher);
    if let Some(quote) = &message.quote {
        app.sender_label(&quote.author).hash(&mut hasher);
        quote.text.lines().next().hash(&mut hasher);
    }
    for (index, attachment) in message.attachments.iter().enumerate() {
        attachment.file_name.hash(&mut hasher);
        attachment.content_type.hash(&mut hasher);
        message
            .image_previews
            .get(index)
            .map(|p| p.as_ref().map(|p| p.rows.len()))
            .hash(&mut hasher);
    }
    message.links.hash(&mut hasher);
    for reaction in &message.reactions {
        reaction.emoji.hash(&mut hasher);
        reaction.authors.len().hash(&mut hasher);
    }
    hasher.finish()
}

/// Rows of one message, and its attachments' row ranges within them.
#[allow(clippy::type_complexity)]
/// One-line excerpt of the quoted message. Some clients send the quote
/// without its text, so fall back to the original in local history
/// (the quote id is the original's timestamp).
fn quote_preview(c: &Conversation, quote: &QuoteRef) -> String {
    const MAX: usize = 40;
    let mut text = quote.text.trim().to_string();
    if text.is_empty() {
        if let Some(original) = c.messages.iter().find(|m| m.timestamp_ms == quote.id) {
            text = original.body.trim().to_string();
            if text.is_empty() {
                if let Some(a) = original.attachments.first() {
                    text = format!("[{}]", a.file_name);
                }
            }
        }
    }
    let line = text.lines().next().unwrap_or_default();
    if line.chars().count() > MAX {
        format!("{}…", line.chars().take(MAX).collect::<String>())
    } else if text.lines().nth(1).is_some() {
        format!("{line} …")
    } else {
        line.to_string()
    }
}

fn message_lines(
    app: &App,
    c: &Conversation,
    message_index: usize,
    text_width: usize,
    message_active: bool,
    last_sent: Option<usize>,
) -> (Vec<Line<'static>>, Vec<(usize, usize, usize)>) {
    let message = &c.messages[message_index];
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut attachment_ranges = Vec::new();
    let push_wrapped = |lines: &mut Vec<Line<'static>>, indent: &str, text: &str, style: Style| {
        push_wrapped(lines, text_width, indent, text, style)
    };
    let selected_message = message_index == c.selected_message;
    let marker = if selected_message && message_active {
        "▸"
    } else {
        " "
    };
    if message.system {
        push_wrapped(
            &mut lines,
            "",
            &format!(
                " {marker}  ── {} · {} ──",
                format_time(message.timestamp_ms),
                message.body
            ),
            Style::default().fg(MUTED).add_modifier(Modifier::ITALIC),
        );
        lines.push(Line::from(" "));
        return (lines, attachment_ranges);
    }
    let (tag, color) = if message.outgoing {
        ("YOU".to_owned(), TEAL)
    } else if let Some(sender) = message.sender.as_deref() {
        (app.sender_label(sender), BLUE)
    } else {
        (c.title(&app.local_id).to_owned(), BLUE)
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
        // Like the official apps, delivery/read ticks are shown only on
        // the latest sent message; sending/failed show everywhere.
        let ticks = match (message.send_state, message.receipt_status) {
            (SendState::Sending, _) => Some((" ⋯ sending", MUTED)),
            (SendState::Failed, _) => Some((" ✗ failed · /retry", Color::Red)),
            _ if Some(message_index) != last_sent => None,
            (_, 2) => Some((" ✓✓", TEAL)),
            (_, 1) => Some((" ✓✓", MUTED)),
            _ => Some((" ✓", MUTED)),
        };
        if let Some((ticks, tick_color)) = ticks {
            metadata.push(Span::styled(
                ticks,
                Style::default().fg(tick_color).add_modifier(Modifier::BOLD),
            ));
        }
    }
    if let Some(expires_at) = message.expires_at {
        let left = expires_at.saturating_sub(now_ms()) / 1000;
        metadata.push(Span::styled(
            format!("  ⏱ {}", format_duration(left.max(1) as u32)),
            Style::default().fg(MUTED),
        ));
    } else if message.expiration.is_some() {
        metadata.push(Span::styled("  ⏱", Style::default().fg(MUTED)));
    }
    lines.push(Line::from(metadata));
    if let Some(quote) = message.quote.as_ref() {
        push_wrapped(
            &mut lines,
            "    ┃ ",
            &format!(
                "↪ {}: {}",
                app.sender_label(&quote.author),
                quote_preview(c, quote)
            ),
            Style::default().fg(MUTED),
        );
    }
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
        push_wrapped(
            &mut lines,
            "    ",
            &format!(
                "{numbering}{}{}",
                attachment_label(attachment),
                if pending { "  (loading…)" } else { "" }
            ),
            Style::default().fg(TEXT),
        );
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
        attachment_ranges.push((attachment_start, lines.len(), attachment_index));
    }
    for text_line in message.body.lines() {
        push_wrapped(&mut lines, "    ", text_line, Style::default().fg(TEXT));
    }
    for (url, title) in &message.links {
        let text = match title {
            Some(title) if !title.is_empty() => format!("🔗 {title} · {url}"),
            _ => format!("🔗 {url}"),
        };
        push_wrapped(&mut lines, "    ", &text, Style::default().fg(BLUE));
    }
    if !message.reactions.is_empty() {
        let mut spans = vec![Span::raw("    ")];
        for reaction in &message.reactions {
            let mine = reaction.authors.iter().any(|a| *a == app.local_id);
            spans.push(Span::styled(
                format!(" {} {} ", reaction.emoji, reaction.authors.len()),
                if mine {
                    Style::default().fg(BG).bg(TEAL)
                } else {
                    Style::default().fg(TEXT).bg(PANEL)
                },
            ));
            spans.push(Span::raw(" "));
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(" "));
    (lines, attachment_ranges)
}

fn draw_chat(frame: &mut ratatui::Frame<'_>, area: Rect, app: &mut App) {
    // The composer grows with its content (2–8 rows) and soft-wraps.
    let composer_width = area.width.saturating_sub(4).max(2) as usize;
    let (composer_rows, (cursor_row, cursor_column)) =
        session_tui_input::wrap(&app.input, app.cursor, composer_width);
    let visible_composer_rows = composer_rows.len().clamp(2, 8);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(visible_composer_rows as u16 + 1),
        ])
        .split(area);
    let selected = app.conversations.get(app.selected);
    let title_name = selected
        .map(|c| c.title(&app.local_id))
        .unwrap_or("No conversation selected");
    // The full ID is never on screen (screenshots, onlookers): a short form,
    // or nothing when the name already is that short form. Double-click
    // copies the full ID.
    let title_id = selected
        .map(|c| {
            let short = short_id(&c.id);
            if title_name == short {
                "· double-click to copy ID".to_owned()
            } else {
                format!("{short} · double-click to copy")
            }
        })
        .unwrap_or_else(|| "Ctrl+N to add a contact".to_owned());
    let title = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" {}", title_name),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("   {}", title_id), Style::default().fg(MUTED)),
        Span::styled(
            selected
                .map(|c| {
                    let mut tags = Vec::new();
                    if c.typing_until.is_some_and(|until| until > Instant::now()) {
                        tags.push("typing…".to_owned());
                    }
                    if let Some(setting) = c.disappearing {
                        tags.push(format!("⏱ {}", Expiration::describe(Some(setting))));
                    }
                    if c.read_only {
                        tags.push("read-only".to_owned());
                    }
                    if app.blocked.contains(&c.id) {
                        tags.push("blocked".to_owned());
                    }
                    if tags.is_empty() {
                        String::new()
                    } else {
                        format!("   {}", tags.join(" · "))
                    }
                })
                .unwrap_or_default(),
            Style::default().fg(TEAL),
        ),
    ]))
    .block(
        Block::default()
            .borders(Borders::BOTTOM)
            .border_style(Style::default().fg(Color::Rgb(35, 55, 62)))
            .style(Style::default().bg(PANEL)),
    );
    frame.render_widget(title, rows[0]);
    app.chat_title_area = Some(rows[0]);

    let message_active = app.focus == FocusArea::Messages;
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
    let text_width = transcript_area.width.max(8) as usize;
    // Only the messages on screen are laid out; the rest are measured from
    // a cache of row counts, so long chats cost the same as short ones.
    let mut heights = std::mem::take(&mut app.layout_heights);
    let mut message_ranges = Vec::new();
    let mut total = 1; // blank first row
    let mut last_sent = None;
    if let Some(c) = selected {
        if heights.0 != c.id {
            heights = (c.id.clone(), HashMap::new());
        }
        last_sent = c
            .messages
            .iter()
            .rposition(|m| m.outgoing && !m.system && m.send_state == SendState::Sent);
        let mut live = HashMap::with_capacity(c.messages.len());
        for (message_index, message) in c.messages.iter().enumerate() {
            let key = message_layout_key(app, message, text_width);
            let height = match heights.1.get(&key) {
                Some(&height) => height,
                None => {
                    message_lines(app, c, message_index, text_width, message_active, last_sent)
                        .0
                        .len()
                }
            };
            live.insert(key, height);
            message_ranges.push((total, total + height, message_index));
            total += height;
        }
        heights.1 = live;
    }
    app.message_viewport = Some(transcript_area);
    let visible_height = transcript_area.height as usize;
    let max_scroll = total.saturating_sub(visible_height);
    let manual_scroll = selected.and_then(|c| c.scroll);
    let scroll = if let Some(top) = manual_scroll {
        // Mouse wheel scrolled the view freely.
        top.min(max_scroll)
    } else if message_active && selected.is_some_and(|c| c.follow_selection) {
        // Keep the selected message visible with the smallest move from the
        // previous position (no jumps while stepping through messages).
        let previous = if app.transcript_conversation == app.selected {
            app.transcript_scroll.0
        } else {
            max_scroll
        };
        selected
            .and_then(|c| message_ranges.get(c.selected_message).copied())
            .map(|(start, end, _)| {
                if start < previous {
                    start
                } else if end > previous + visible_height {
                    start.max(end.saturating_sub(visible_height))
                } else {
                    previous
                }
            })
            .unwrap_or(max_scroll)
            .min(max_scroll)
    } else {
        max_scroll
    };
    app.transcript_scroll = (scroll, max_scroll);
    app.transcript_conversation = app.selected;
    let visible_end = scroll.saturating_add(visible_height);
    // Lay out the visible messages; `first_row` is the transcript row of
    // `lines[0]`.
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut first_row = 0;
    let mut hitboxes = Vec::new();
    match selected {
        Some(c) => {
            if scroll == 0 {
                lines.push(Line::from(" "));
            } else {
                first_row = message_ranges
                    .iter()
                    .find(|(_, end, _)| *end > scroll)
                    .map_or(total, |(start, _, _)| *start);
            }
            for &(start, end, message_index) in &message_ranges {
                if end <= scroll || start >= visible_end {
                    continue;
                }
                let (message_lines, attachments) =
                    message_lines(app, c, message_index, text_width, message_active, last_sent);
                let base = first_row + lines.len();
                hitboxes.push((base, base + message_lines.len(), message_index, None));
                for (a_start, a_end, attachment) in attachments {
                    hitboxes.push((base + a_start, base + a_end, message_index, Some(attachment)));
                }
                lines.extend(message_lines);
            }
        }
        None => {
            lines.push(Line::from(" "));
            lines.push(Line::from(Span::styled(
                "  Add a contact with Ctrl+N. Use /rsync to sync the inbox.",
                Style::default().fg(MUTED),
            )));
        }
    }
    app.layout_heights = heights;
    // Attachment hitboxes come after their message's, as click handling expects.
    app.message_hitboxes.clear();
    let mut ordered: Vec<_> = hitboxes.iter().filter(|h| h.3.is_none()).copied().collect();
    ordered.extend(hitboxes.iter().filter(|h| h.3.is_some()).copied());
    for (start, end, message_index, attachment_index) in ordered {
        if end <= scroll || start >= visible_end {
            continue;
        }
        let y_start = transcript_area.y + (start.max(scroll) - scroll).min(u16::MAX as usize) as u16;
        let y_end = transcript_area.y
            + (end.min(visible_end) - scroll).saturating_sub(1).min(u16::MAX as usize) as u16;
        app.message_hitboxes
            .push((y_start, y_end, message_index, attachment_index));
    }
    let transcript = Paragraph::new(lines)
        .scroll(((scroll - first_row.min(scroll)).min(u16::MAX as usize) as u16, 0))
        .style(Style::default().bg(BG))
        .block(transcript_block);
    frame.render_widget(transcript, rows[1]);

    let composer_active = app.focus == FocusArea::Composer;
    let first_row = (cursor_row + 1).saturating_sub(visible_composer_rows);
    let prompt_lines: Vec<Line<'_>> = if app.input.is_empty() {
        vec![Line::from(vec![
            Span::styled(
                "  › ",
                Style::default()
                    .fg(if composer_active { TEAL } else { MUTED })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                if app.input_mode == InputMode::ContactId {
                    "Paste a Session ID (05…)…"
                } else {
                    "Write a message… (Shift+Enter or Ctrl+J for a new line)"
                },
                Style::default().fg(MUTED),
            ),
        ])]
    } else {
        composer_rows
            .iter()
            .enumerate()
            .skip(first_row)
            .take(visible_composer_rows)
            .map(|(index, row)| {
                Line::from(vec![
                    Span::styled(
                        if index == 0 { "  › " } else { "    " },
                        Style::default()
                            .fg(if composer_active { TEAL } else { MUTED })
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(row.clone(), Style::default().fg(TEXT)),
                ])
            })
            .collect()
    };
    if composer_active
        && app.image_viewer.is_none()
        && !app.show_help
        && !app.show_emoji
        && !app.reaction_picker
        && app.delete_prompt.is_none()
        && app.chat_prompt.is_none()
        && app.recovery_seed.is_none()
    {
        frame.set_cursor_position((
            rows[2].x + 4 + cursor_column.min(u16::MAX as usize) as u16,
            rows[2].y + 1 + (cursor_row - first_row) as u16,
        ));
    }
    let prompt = Paragraph::new(prompt_lines)
    .block(
        Block::default()
            .title(match app.reply_to.as_ref() {
                Some(quote) => format!(
                    " ↪ REPLYING TO {}: {} · Esc cancels ",
                    app.sender_label(&quote.author),
                    quote.text.chars().take(40).collect::<String>()
                ),
                None if app.focus == FocusArea::Composer => {
                    " COMPOSER · FOCUS · Tab to change ".to_owned()
                }
                None => " COMPOSER · Tab to focus ".to_owned(),
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

const HELP: &[(&str, &[(&str, &str)])] = &[
    (
        "Navigation",
        &[
            ("Tab / Shift+Tab", "Move focus: chats → messages → composer"),
            ("← / →", "Previous / next chat (when the composer is empty)"),
            ("↑ / ↓", "Move in the focused list"),
            ("Mouse", "Click a chat, message or image; wheel moves the selection"),
            ("/? · Esc", "Open / close this help (↑/↓ scroll)"),
            ("/exit · Ctrl+C", "Quit"),
        ],
    ),
    (
        "Composer",
        &[
            ("Enter", "Send"),
            ("Shift+Enter · Alt+Enter · Ctrl+J", "New line"),
            ("← → ↑ ↓ Home End", "Move the cursor (Ctrl+A / Ctrl+E: line start / end)"),
            ("Backspace · Delete", "Delete before / after the cursor"),
            ("Ctrl+W · Ctrl+U", "Delete previous word · clear everything"),
            ("Paste", "Inserted at the cursor, line breaks kept"),
            (":joy: :heart: :+1:", "Emoji shortcodes (/emoji lists them; Win+. on Windows)"),
        ],
    ),
    (
        "Messages (focus the message list)",
        &[
            ("r", "Reply to the selected message (Esc cancels)"),
            ("e  then 1-6", "Reaction bar: 😂 🥰 😢 😡 😮 😈"),
            ("+", "React 👍"),
            ("/react EMOJI", "React with any emoji or :shortcode: (again removes it)"),
            ("Delete", "Delete: 1 on this device only · 2 for everyone (your messages)"),
            ("/retry", "Resend the selected failed message"),
            ("✓ / ✓✓ / teal ✓✓", "Sent / delivered / read"),
        ],
    ),
    (
        "Attachments",
        &[
            ("/attach P1 [P2…] [-- caption]", "Send files as one message (max 32; quote paths with spaces)"),
            ("/view [N]", "Open image N of the selected message; ←/→ next/previous"),
            ("/paste [-- caption]", "Send the image on the clipboard (e.g. a screenshot)"),
            ("/save [N] [PATH]", "Save attachment N, or all, to PATH or the current folder"),
        ],
    ),
    (
        "Chats and groups",
        &[
            ("Ctrl+N", "Start a chat with a Session ID"),
            ("/disappear off | read 12h | send 1d", "Disappearing messages for this 1:1 chat"),
            ("/1 … /9", "Switch to chat N (the number shown in the chat list)"),
            ("/accept", "Accept a message request, or join the group you were invited to"),
            ("/decline", "Decline a message request (deletes it)"),
            ("/delete", "Delete this chat and its messages (the contact stays)"),
            ("/remove", "Remove this contact from your account and delete the chat"),
            ("/block · /unblock", "Block / unblock this 1:1 contact on all your devices"),
            ("/rsync", "Fetch messages now (also automatic)"),
        ],
    ),
    (
        "Settings",
        &[
            ("/name [NAME]", "Show / set your display name (synced to your other devices)"),
            ("/bell on|off", "Terminal bell for new messages (title shows unread count)"),
            ("--debug", "Start with a debug log (session-tui-debug.log)"),
            ("--forget-seed", "Start and delete the saved seed"),
        ],
    ),
];

fn draw_help(frame: &mut ratatui::Frame<'_>, area: Rect, scroll: u16) {
    let popup = centered_rect(90, 90, area);
    frame.render_widget(Clear, popup);
    let key_width = HELP
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .map(|(key, _)| key.chars().count())
        .max()
        .unwrap_or(10)
        .min(36);
    let mut lines = Vec::new();
    for (section, entries) in HELP {
        lines.push(Line::from(Span::styled(
            *section,
            Style::default().fg(TEAL).add_modifier(Modifier::BOLD),
        )));
        for (key, description) in *entries {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key:<key_width$}  "), Style::default().fg(Color::Yellow)),
                Span::styled(*description, Style::default().fg(TEXT)),
            ]));
        }
        lines.push(Line::from(" "));
    }
    lines.push(Line::from(Span::styled(
        "Voice and video calls are not supported.",
        Style::default().fg(MUTED),
    )));
    let help = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Help · ↑/↓ scroll · Esc closes ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(TEAL))
                .style(Style::default().bg(PANEL)),
        )
        .wrap(Wrap { trim: false })
        .scroll((scroll, 0));
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

#[cfg(test)]
mod seed_file_tests {
    use super::*;

    #[test]
    fn seed_file_round_trip_and_wrong_passphrase() {
        let seed = [42u8; 32];
        let data = encrypt_seed_file(&seed, "correct horse").unwrap();
        assert_eq!(decrypt_seed_file(&data, "correct horse").unwrap(), seed);
        assert!(decrypt_seed_file(&data, "wrong").is_err());
        assert!(decrypt_seed_file(b"garbage", "x").is_err());
    }

    #[test]
    fn durations_parse_and_format() {
        assert_eq!(parse_duration("12h"), Some(43_200));
        assert_eq!(parse_duration("1d"), Some(86_400));
        assert_eq!(parse_duration("0m"), None);
        assert_eq!(parse_duration("5"), None);
        assert_eq!(format_duration(86_400), "1d");
        assert_eq!(format_duration(90), "90s");
        assert_eq!(
            Expiration::parse("read 5m").unwrap(),
            Some(Expiration { kind: 1, seconds: 300 })
        );
        assert_eq!(Expiration::parse("off").unwrap(), None);
        assert!(Expiration::parse("later").is_err());
    }

    #[test]
    fn reactions_toggle_per_author() {
        let mut message = Message::new("hi".into(), 1, false);
        apply_reaction(&mut message, "👍", "05a", false);
        apply_reaction(&mut message, "👍", "05b", false);
        assert_eq!(message.reactions[0].authors.len(), 2);
        apply_reaction(&mut message, "👍", "05a", true);
        apply_reaction(&mut message, "👍", "05b", true);
        assert!(message.reactions.is_empty());
    }

    #[test]
    fn content_parser_handles_session_message_types() {
        use libsession::proto::session_protos::{
            data_message::Reaction, DataExtractionNotification, ReceiptMessage,
        };
        let me = "05".to_owned() + &"11".repeat(32);
        let peer = "05".to_owned() + &"22".repeat(32);
        let parse = |content: Content| {
            parse_content(&me, "h".into(), peer.clone(), peer.clone(), 1000, content)
        };
        // Album with caption and reply.
        let pointer = |name: &str| AttachmentPointer {
            id: 1,
            content_type: Some("image/jpeg".into()),
            file_name: Some(name.into()),
            ..Default::default()
        };
        let album = parse(Content {
            data_message: Some(DataMessage {
                body: Some("look".into()),
                timestamp: Some(5),
                attachments: vec![pointer("a.jpg"), pointer("b.jpg"), pointer("c.jpg")],
                quote: Some(DataQuote {
                    id: 3,
                    author: me.clone(),
                    text: Some("earlier".into()),
                    attachments: Vec::new(),
                }),
                ..Default::default()
            }),
            expiration_type: Some(2),
            expiration_timer: Some(60),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(album.attachments.len(), 3);
        assert_eq!(album.body.as_deref(), Some("look"));
        assert_eq!(album.quote.as_ref().unwrap().id, 3);
        assert_eq!(album.expiration, Some(Expiration { kind: 2, seconds: 60 }));
        // Reaction.
        let reaction = parse(Content {
            data_message: Some(DataMessage {
                timestamp: Some(6),
                reaction: Some(Reaction {
                    id: 5,
                    author: me.clone(),
                    emoji: Some("❤".into()),
                    action: 0,
                }),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(reaction.reaction, Some((5, me.clone(), "❤".into(), false)));
        // Screenshot notice and receipts.
        let notice = parse(Content {
            data_extraction_notification: Some(DataExtractionNotification {
                r#type: 1,
                timestamp: Some(7),
            }),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(notice.event, Some(ChatEvent::Notice(_))));
        let receipt = parse(Content {
            receipt_message: Some(ReceiptMessage {
                r#type: 1,
                timestamp: vec![5],
            }),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(receipt.receipt, Some((1, vec![5])));
        // Timer update from the peer.
        let timer = parse(Content {
            data_message: Some(DataMessage {
                timestamp: Some(8),
                flags: Some(2),
                ..Default::default()
            }),
            expiration_type: Some(1),
            expiration_timer: Some(3600),
            ..Default::default()
        })
        .unwrap();
        assert!(matches!(
            timer.event,
            Some(ChatEvent::TimerChanged(Some(Expiration { kind: 1, seconds: 3600 })))
        ));
    }
}

#[cfg(test)]
mod emoji_tests {
    use super::*;

    #[test]
    fn shortcodes_expand_only_known_names() {
        assert_eq!(expand_shortcodes("ok :+1: :joy:"), "ok 👍 😂");
        assert_eq!(expand_shortcodes("time 12:30 :nope: x"), "time 12:30 :nope: x");
        assert_eq!(expand_shortcodes(":heart::fire:"), "❤️🔥");
        assert_eq!(expand_shortcodes("a:"), "a:");
    }

    #[test]
    fn store_response_hash_is_found() {
        let flat: Value = serde_json::json!({"hash": "abc"});
        let nested: Value =
            serde_json::json!({"swarm": {"node1": {"hash": "def", "signature": "x"}}});
        assert_eq!(find_message_hash(&flat).as_deref(), Some("abc"));
        assert_eq!(find_message_hash(&nested).as_deref(), Some("def"));
        assert_eq!(find_message_hash(&serde_json::json!({"ok": true})), None);
    }
}

#[cfg(test)]
mod scroll_tests {
    use super::*;
    use crossterm::event::{KeyModifiers, MouseEvent};
    use ratatui::backend::TestBackend;

    fn wheel(app: &mut App, kind: MouseEventKind) {
        let area = app.message_viewport.expect("drawn");
        handle_mouse(
            app,
            MouseEvent {
                kind,
                column: area.x + 2,
                row: area.y + 2,
                modifiers: KeyModifiers::NONE,
            },
        );
    }

    #[test]
    fn wheel_scrolls_by_fixed_rows_and_resumes_following() {
        let local = "05".to_owned() + &"11".repeat(32);
        let peer = "05".to_owned() + &"22".repeat(32);
        let mut app = App::new(local);
        let index = app.ensure_contact(&peer);
        for i in 0..200u64 {
            let body = if i % 7 == 0 {
                "a long message that has to wrap over several rows ".repeat(4)
            } else {
                format!("message {i}")
            };
            app.conversations[index].messages.push(Message::new(body, 1_000 + i, i % 2 == 0));
        }
        app.selected = index;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let (bottom, max_scroll) = app.transcript_scroll;
        assert_eq!(bottom, max_scroll, "starts at the newest messages");
        assert!(max_scroll > 100);

        for step in 1..=5 {
            wheel(&mut app, MouseEventKind::ScrollUp);
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            assert_eq!(app.transcript_scroll.0, max_scroll - step * WHEEL_ROWS);
        }
        for _ in 0..5 {
            wheel(&mut app, MouseEventKind::ScrollDown);
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        }
        assert_eq!(app.transcript_scroll.0, max_scroll);
        assert_eq!(app.conversations[index].scroll, None, "follows new messages again");
        // A new message keeps the view at the bottom.
        app.conversations[index].messages.push(Message::new("new".into(), 9_999, false));
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        assert_eq!(app.transcript_scroll.0, app.transcript_scroll.1);
    }
    #[test]
    fn partial_layout_matches_full_layout_at_every_scroll() {
        let local = "05".to_owned() + &"11".repeat(32);
        let peer = "05".to_owned() + &"22".repeat(32);
        let mut app = App::new(local);
        let index = app.ensure_contact(&peer);
        for i in 0..120u64 {
            let body = if i % 5 == 0 {
                format!("{i} wraps over rows ").repeat(9)
            } else {
                format!("message {i}\nsecond line")
            };
            app.conversations[index].messages.push(Message::new(body, 1_000 + i, i % 3 == 0));
        }
        app.selected = index;
        let mut terminal = Terminal::new(TestBackend::new(90, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let area = app.message_viewport.unwrap();
        let width = area.width.max(8) as usize;
        let row_text = |line: &Line<'_>| -> String {
            line.spans.iter().map(|s| s.content.as_ref()).collect::<String>()
        };
        let conversation = &app.conversations[index];
        let last_sent = conversation.messages.iter().rposition(|m| m.outgoing);
        let mut full = vec![" ".to_owned()];
        for i in 0..conversation.messages.len() {
            full.extend(
                message_lines(&app, conversation, i, width, false, last_sent)
                    .0
                    .iter()
                    .map(row_text),
            );
        }
        let max_scroll = app.transcript_scroll.1;
        assert_eq!(max_scroll, full.len() - area.height as usize);
        for top in [0, 1, 2, 7, 33, max_scroll / 2, max_scroll - 1, max_scroll] {
            app.conversations[index].scroll = Some(top);
            terminal.draw(|frame| draw(frame, &mut app)).unwrap();
            let buffer = terminal.backend().buffer();
            for row in 0..area.height {
                let shown: String = (0..area.width)
                    .map(|x| buffer[(area.x + x, area.y + row)].symbol().to_owned())
                    .collect();
                let expected = full.get(top + row as usize).cloned().unwrap_or_default();
                assert_eq!(shown.trim_end(), expected.trim_end(), "scroll {top} row {row}");
            }
        }
    }
}


#[cfg(test)]
mod history_key_tests {
    use super::*;

    fn group_message(sender: &str, body: &str) -> Message {
        let mut message = Message::new(body.into(), 5_000, false);
        message.sender = Some(sender.into());
        message
    }

    /// Tests with a real store share one data folder (set once) and run one
    /// at a time; each uses its own account, so its own database file.
    fn test_store(account: u8) -> (std::sync::MutexGuard<'static, ()>, Identity, LocalStore) {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        static DIR: OnceLock<std::path::PathBuf> = OnceLock::new();
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("stui-store-test-{}", std::process::id()));
            // SAFETY: set once, before any store is opened, under LOCK.
            unsafe {
                std::env::remove_var("APPDATA");
                std::env::set_var("XDG_DATA_HOME", &dir);
            }
            dir
        });
        let identity = Identity {
            session_id: format!("05{}", format!("{account:02x}").repeat(32)),
            ed_public: [account; 32],
            ed_secret: [account; 64],
            recovery_phrase: None,
        };
        let root = session_data_dir().unwrap();
        let _ = std::fs::remove_file(root.join(format!("{}.sqlite3", identity.session_id)));
        let store = LocalStore::open(&identity).unwrap();
        (guard, identity, store)
    }

    fn incoming(peer: &str, hash: &str, timestamp_ms: u64) -> IncomingMessage {
        let me = "05".to_owned() + &"11".repeat(32);
        let content = Content {
            data_message: Some(DataMessage {
                body: Some(format!("hello {hash}")),
                timestamp: Some(timestamp_ms),
                ..Default::default()
            }),
            ..Default::default()
        };
        parse_content(&me, hash.into(), peer.into(), peer.into(), timestamp_ms, content).unwrap()
    }

    fn retrieved(messages: Vec<IncomingMessage>, cursor: &str) -> RetrieveResult {
        RetrieveResult {
            messages,
            queued: 0,
            undecryptable: 0,
            bad_envelope: 0,
            bad_content: 0,
            last_hash: Some(cursor.into()),
            groups: Vec::new(),
            group_cursors: HashMap::new(),
            node_cursors: Vec::new(),
            invite_responses: Vec::new(),
            account: None,
        }
    }

    #[test]
    fn a_failed_write_keeps_the_cursor_and_the_retry_saves_the_message() {
        let (_guard, identity, store) = test_store(0x61);
        let peer = "05".to_owned() + &"22".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        let mut downloads = std::collections::VecDeque::new();
        let count = |store: &LocalStore| -> i64 {
            store.connection.query_row("SELECT count(*) FROM messages", [], |r| r.get(0)).unwrap()
        };
        // Inject a failing write, as a full disk would.
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let first = retrieved(vec![incoming(&peer, "hash-1", 1_000)], "cursor-1");
        assert_eq!(finish_sync(&mut app, &store, &identity.session_id, Ok(first), &mut downloads, None), 0);
        assert_eq!(count(&store), 0);
        assert_eq!(store.get_last_hash().unwrap(), None, "cursor must not advance");
        assert!(app.conversations.iter().all(|c| c.messages.is_empty()), "memory rolled back");
        assert!(app.status.contains("WILL RETRY"));

        // Same messages again after the problem is gone: saved this time.
        store.connection.execute_batch("DROP TRIGGER fail;").unwrap();
        let retry = retrieved(vec![incoming(&peer, "hash-1", 1_000)], "cursor-1");
        finish_sync(&mut app, &store, &identity.session_id, Ok(retry), &mut downloads, None);
        assert_eq!(count(&store), 1);
        assert_eq!(store.get_last_hash().unwrap().as_deref(), Some("cursor-1"));
    }

    #[test]
    fn outbox_keeps_unsent_messages_across_a_restart_and_retries_with_backoff() {
        let (_guard, identity, store) = test_store(0x65);
        let peer = "05".to_owned() + &"25".repeat(32);
        let group = "03".to_owned() + &"26".repeat(32);
        let mut message = Message::new("hello".into(), 7_000, true);
        message.send_state = SendState::Sending;
        queue_outgoing(&store, &peer, &message).unwrap();
        let mut in_group = Message::new("hi all".into(), 7_001, true);
        in_group.send_state = SendState::Sending;
        queue_outgoing(&store, &group, &in_group).unwrap();

        // "Restart": everything comes back from the database.
        let mut app = App::new(identity.session_id.clone());
        store.load(&mut app).unwrap();
        let state = |app: &App, peer: &str| {
            app.conversations.iter().find(|c| c.id == peer).unwrap().messages[0].send_state
        };
        assert_eq!(state(&app, &peer), SendState::Sending);
        let due = store.outbox_due(now_ms());
        assert_eq!(due.len(), 2);
        let entry = due.iter().find(|e| e.peer == peer).unwrap().clone();
        assert_eq!(entry.kind, OutboxKind::Text);

        // A failure: marked failed, retried later, not right away.
        finish_outbox(&mut app, &store, &entry, Err("offline".into()));
        assert_eq!(state(&app, &peer), SendState::Failed);
        assert!(store.outbox_due(now_ms()).iter().all(|e| e.id != entry.id));
        assert!(store.outbox_due(now_ms() + outbox_backoff_ms(1)).iter().any(|e| e.id == entry.id));
        assert!(app.status.contains("RETRYING IN 5 S"), "{}", app.status);

        // Out of automatic attempts: parked until /retry.
        let mut last = entry.clone();
        last.attempts = OutboxKind::Text.max_attempts() - 1;
        finish_outbox(&mut app, &store, &last, Err("offline".into()));
        assert!(store.outbox_due(now_ms() + 10 * 365 * 24 * 3_600_000).iter().all(|e| e.id != entry.id));
        assert!(app.status.contains("/retry"));
        assert!(store.outbox_retry_now(&peer, 7_000).unwrap());
        let retried = store.outbox_due(now_ms()).into_iter().find(|e| e.id == entry.id).unwrap();
        assert_eq!(retried.attempts, 0);

        // Success: sent, saved as sent, and the sync copy queued (1:1 only).
        finish_outbox(&mut app, &store, &retried, Ok(None));
        assert_eq!(state(&app, &peer), SendState::Sent);
        let due = store.outbox_due(now_ms());
        assert!(due.iter().any(|e| e.peer == peer && e.kind == OutboxKind::SyncCopy));
        let group_entry = due.iter().find(|e| e.peer == group).unwrap().clone();
        finish_outbox(&mut app, &store, &group_entry, Ok(None));
        assert!(store.outbox_due(now_ms()).iter().all(|e| e.peer != group), "no sync copy for groups");
        let mut reloaded = App::new(identity.session_id.clone());
        store.load(&mut reloaded).unwrap();
        assert_eq!(state(&reloaded, &peer), SendState::Sent);

        // Deleting the message drops its remaining work.
        let sent = reloaded.conversations.iter().find(|c| c.id == peer).unwrap().messages[0].clone();
        store.delete_message(&peer, &sent).unwrap();
        assert!(store.outbox_due(now_ms()).iter().all(|e| e.peer != peer));
    }

    #[test]
    fn a_parked_sync_copy_can_be_retried_without_resending_the_message() {
        let (_guard, identity, store) = test_store(0x67);
        let peer = "05".to_owned() + &"27".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        let mut message = Message::new("done".into(), 8_000, true);
        message.send_state = SendState::Sending;
        queue_outgoing(&store, &peer, &message).unwrap();
        store.load(&mut app).unwrap();
        let text = store.outbox_due(now_ms()).pop().unwrap();
        finish_outbox(&mut app, &store, &text, Ok(None));
        let mut copy = store.outbox_due(now_ms()).pop().unwrap();
        assert_eq!(copy.kind, OutboxKind::SyncCopy);
        copy.attempts = OutboxKind::SyncCopy.max_attempts() - 1;
        finish_outbox(&mut app, &store, &copy, Err("offline".into()));
        assert!(app.status.contains("/retry"));
        // Still sent; /retry reschedules only the copy.
        let state = app.conversations.iter().find(|c| c.id == peer).unwrap().messages[0].send_state;
        assert_eq!(state, SendState::Sent);
        assert!(store.outbox_retry_now(&peer, 8_000).unwrap());
        let due = store.outbox_due(now_ms());
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].kind, OutboxKind::SyncCopy);
    }

    #[test]
    fn read_state_and_its_receipt_are_saved_together() {
        let (_guard, identity, store) = test_store(0x68);
        let peer = "05".to_owned() + &"28".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        app.approved.insert(peer.clone());
        let mut incoming = Message::new("hi".into(), 9_000, false);
        incoming.is_read = false;
        store.save_message(&peer, &incoming).unwrap();
        store.load(&mut app).unwrap();
        app.selected = app.conversations.iter().position(|c| c.id == peer).unwrap();
        let read_in_db = |store: &LocalStore| -> bool {
            store.connection.query_row("SELECT is_read FROM messages", [], |r| r.get(0)).unwrap()
        };
        store
            .connection
            .execute_batch("CREATE TRIGGER fail BEFORE INSERT ON outbox BEGIN SELECT RAISE(ABORT, 'disk full'); END;")
            .unwrap();
        assert!(!mark_current_conversation_read(&mut app, &store));
        assert!(!read_in_db(&store), "no receipt queued, so not marked read either");
        assert!(!app.conversations[app.selected].messages[0].is_read);
        store.connection.execute_batch("DROP TRIGGER fail;").unwrap();
        assert!(mark_current_conversation_read(&mut app, &store));
        assert!(read_in_db(&store));
        assert!(app.conversations[app.selected].messages[0].is_read);
        assert_eq!(store.outbox_due(now_ms())[0].kind, OutboxKind::ReadReceipt);
    }

    #[test]
    fn new_messages_never_share_a_timestamp() {
        let (_guard, _identity, store) = test_store(0x69);
        let mut last = now_ms() + 60_000; // e.g. a message sent "in the future"
        let a = next_outgoing_timestamp(&mut last);
        let b = next_outgoing_timestamp(&mut last);
        assert!(b > a);
        let peer = "05".to_owned() + &"29".repeat(32);
        queue_outgoing(&store, &peer, &Message::new("one".into(), 123, true)).unwrap();
        assert!(queue_outgoing(&store, &peer, &Message::new("two".into(), 123, true)).is_err());
        assert_eq!(store.outbox_due(now_ms()).len(), 1, "the clash queued nothing");
    }

    #[test]
    fn a_send_result_that_cannot_be_saved_changes_nothing() {
        let (_guard, identity, store) = test_store(0x6a);
        let peer = "05".to_owned() + &"2a".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        let mut message = Message::new("x".into(), 10_000, true);
        message.send_state = SendState::Sending;
        queue_outgoing(&store, &peer, &message).unwrap();
        store.load(&mut app).unwrap();
        let entry = store.outbox_due(now_ms()).pop().unwrap();
        store
            .connection
            .execute_batch("CREATE TRIGGER fail BEFORE UPDATE ON messages BEGIN SELECT RAISE(ABORT, 'disk full'); END;")
            .unwrap();
        finish_outbox(&mut app, &store, &entry, Ok(None));
        let state = app.conversations.iter().find(|c| c.id == peer).unwrap().messages[0].send_state;
        assert_eq!(state, SendState::Sending, "screen unchanged");
        assert_eq!(store.outbox_due(now_ms()).len(), 1, "still queued");
        assert!(app.status.contains("NOT SAVED"));
    }

    #[test]
    fn a_receipt_that_arrives_before_its_message_is_applied_later() {
        let (_guard, identity, store) = test_store(0x6b);
        let me = identity.session_id.clone();
        let peer = "05".to_owned() + &"2b".repeat(32);
        let mut app = App::new(me.clone());
        app.ensure_contact(&peer);
        let mut downloads = std::collections::VecDeque::new();
        // 1st sync: the peer's read receipt for our message 100 …
        let mut receipt = IncomingMessage::control("r1".into(), peer.clone(), peer.clone(), 150);
        receipt.receipt = Some((1, vec![100]));
        finish_sync(&mut app, &store, &me, Ok(retrieved(vec![receipt], "c1")), &mut downloads, None);
        // … a restart …
        let mut app = App::new(me.clone());
        store.load(&mut app).unwrap();
        // … 2nd sync: the copy of message 100, sent from our phone.
        let content = Content {
            data_message: Some(DataMessage {
                body: Some("from my phone".into()),
                timestamp: Some(100),
                sync_target: Some(peer.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let copy = parse_content(&me, "s1".into(), me.clone(), me.clone(), 100, content).unwrap();
        finish_sync(&mut app, &store, &me, Ok(retrieved(vec![copy], "c2")), &mut downloads, None);
        let status: u8 = store
            .connection
            .query_row("SELECT receipt_status FROM messages WHERE timestamp_ms = 100", [], |r| r.get(0))
            .unwrap();
        assert_eq!(status, 2, "read");
        let left: i64 = store
            .connection
            .query_row("SELECT count(*) FROM pending_receipts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(left, 0);
    }

    fn after_read(peer_hash: &str, timestamp_ms: u64, seconds: u32) -> Message {
        let mut message = Message::new("vanishing".into(), timestamp_ms, false);
        message.is_read = false;
        message.server_hash = Some(peer_hash.into());
        message.expiration = Some(Expiration { kind: 1, seconds });
        message
    }

    #[test]
    fn reading_an_after_read_message_shortens_it_on_our_swarm() {
        let (_guard, identity, store) = test_store(0x6c);
        let peer = "05".to_owned() + &"2c".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        app.approved.insert(peer.clone());
        store.save_message(&peer, &after_read("h-dar", 11_000, 60)).unwrap();
        let mut plain = Message::new("stays".into(), 11_001, false);
        plain.is_read = false;
        plain.server_hash = Some("h-plain".into());
        store.save_message(&peer, &plain).unwrap();
        store.load(&mut app).unwrap();
        app.selected = app.conversations.iter().position(|c| c.id == peer).unwrap();
        mark_current_conversation_read(&mut app, &store);
        let due = store.outbox_due(now_ms());
        let expire: Vec<_> = due.iter().filter(|e| e.kind == OutboxKind::ExpireRead).collect();
        assert_eq!(expire.len(), 1, "only the after-read message");
        assert_eq!(expire[0].timestamp_ms, 11_000);
        let message = outbox_message(&mut app, expire[0]).unwrap();
        let deadline = message.expires_at.unwrap();
        assert!(deadline > now_ms() + 55_000 && deadline <= now_ms() + 60_000);
    }

    #[test]
    fn a_message_read_on_another_device_keeps_that_devices_deadline() {
        let (_guard, identity, store) = test_store(0x6d);
        let peer = "05".to_owned() + &"2d".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        let now = now_ms();
        // Already shortened by the other device: 20 s left of a 60 s timer.
        let mut shortened = after_read("h-1", 12_000, 60);
        shortened.swarm_expiry = Some(now + 20_000);
        // Not shortened yet: the swarm still has the original 14 days.
        let mut original = after_read("h-2", 12_001, 60);
        original.swarm_expiry = Some(now + 14 * 24 * 3_600_000);
        store.save_message(&peer, &shortened).unwrap();
        store.save_message(&peer, &original).unwrap();
        store.load(&mut app).unwrap();
        let state = session_tui_account::AccountState {
            last_read: vec![(peer.clone(), 12_001)],
            ..Default::default()
        };
        apply_account_state(&mut app, &store, &state);
        let messages = &app.conversations.iter().find(|c| c.id == peer).unwrap().messages;
        assert_eq!(messages[0].expires_at, Some(now + 20_000));
        assert!(messages[1].expires_at.unwrap() <= now_ms() + 60_000);
        let due = store.outbox_due(now_ms());
        assert!(due.iter().all(|e| e.timestamp_ms == 12_001), "nothing to do for the first");
        assert!(due.iter().any(|e| e.kind == OutboxKind::ExpireRead));
        let fetch = due.iter().find(|e| e.kind == OutboxKind::FetchExpiry).unwrap().clone();
        // The swarm reports an earlier deadline (set by the other device): adopted.
        finish_outbox(&mut app, &store, &fetch, Ok(Some((now + 5_000).to_string())));
        let messages = &app.conversations.iter().find(|c| c.id == peer).unwrap().messages;
        assert_eq!(messages[1].expires_at, Some(now + 5_000));
    }

    #[test]
    fn expiry_replies_are_read_in_both_shapes() {
        let direct = serde_json::json!({"expiries": {"h": 42}});
        assert_eq!(parse_expiry(&direct, "h"), Some(42));
        let swarm = serde_json::json!({"swarm": {"a": {"expiries": {"h": 50}}, "b": {"expiries": {"h": 40}}}});
        assert_eq!(parse_expiry(&swarm, "h"), Some(40));
        assert_eq!(parse_expiry(&direct, "gone"), None);
    }

    #[test]
    fn receipts_are_dropped_after_their_attempts_and_backoff_is_capped() {
        let (_guard, identity, store) = test_store(0x66);
        let mut app = App::new(identity.session_id.clone());
        store.outbox_add(OutboxKind::ReadReceipt, "05ab", 0, b"[1,2]").unwrap();
        let mut entry = store.outbox_due(now_ms()).pop().unwrap();
        entry.attempts = OutboxKind::ReadReceipt.max_attempts() - 1;
        finish_outbox(&mut app, &store, &entry, Err("offline".into()));
        assert!(store.outbox_due(now_ms() + 10 * 365 * 24 * 3_600_000).is_empty());
        assert_eq!(outbox_backoff_ms(1), 5_000);
        assert_eq!(outbox_backoff_ms(2), 15_000);
        assert_eq!(outbox_backoff_ms(50), 15 * 60 * 1000);
    }

    #[test]
    fn attachment_cache_keys_separate_direction_author_and_account() {
        let root = std::path::Path::new("/cache");
        let path = |owner: &str| session_tui_media::attachment_blob_path(root, owner, 7, 0);
        let peer = "05ab";
        assert_ne!(path(&blob_owner(peer, None, true)), path(&blob_owner(peer, None, false)));
        assert_ne!(
            path(&blob_owner(peer, Some("05x"), false)),
            path(&blob_owner(peer, Some("05y"), false))
        );
        assert!(blob_owner(peer, None, false).contains(BLOB_ACCOUNT.get().map_or("", String::as_str)));
    }

    #[test]
    fn a_download_for_a_deleted_message_writes_nothing() {
        let (_guard, identity, store) = test_store(0x64);
        let peer = "05".to_owned() + &"24".repeat(32);
        let mut app = App::new(identity.session_id.clone());
        app.ensure_contact(&peer);
        let (encrypted, key, digest) = session_tui_media::encrypt_attachment(b"hello").unwrap();
        let meta = AttachmentMeta {
            file_name: "a.txt".into(),
            content_type: "text/plain".into(),
            url: "u".into(),
            key,
            digest,
            size: 5,
            deterministic: false,
            width: None,
            height: None,
        };
        let job = PendingDownload {
            peer: peer.clone(),
            sender: None,
            timestamp_ms: 4_242,
            outgoing: false,
            index: 0,
            meta,
        };
        let path = session_tui_media::attachment_blob_path(
            &session_data_dir().unwrap(),
            &blob_owner(&peer, None, false),
            4_242,
            0,
        );
        finish_download(&mut app, &store, Ok(DownloadedAttachment { job, encrypted, preview: None }));
        assert!(!path.exists(), "no message, no cache file");
    }

    #[test]
    fn saving_writes_complete_files_only() {
        let dir = std::env::temp_dir().join(format!("stui-save-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("out.bin");
        write_file_atomically(&target, b"complete").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"complete");
        // Only the final file is left behind.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_cursors_move_only_when_the_sync_commits() {
        let (_guard, identity, store) = test_store(0x62);
        let peer = "05".to_owned() + &"23".repeat(32);
        let committed = Mutex::new(HashMap::from([("me/0/node".to_owned(), "old-hash".to_owned())]));
        let mut app = App::new(identity.session_id.clone());
        let mut downloads = std::collections::VecDeque::new();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let mut first = retrieved(vec![incoming(&peer, "hash-n1", 2_000)], "cursor-n1");
        first.node_cursors = vec![("me/0/node".into(), "new-hash".into())];
        finish_sync(&mut app, &store, &identity.session_id, Ok(first), &mut downloads, Some(&committed));
        assert_eq!(committed.lock().unwrap()["me/0/node"], "old-hash", "failed sync keeps the start point");
        assert!(store.node_cursors().is_empty());

        store.connection.execute_batch("DROP TRIGGER fail;").unwrap();
        let mut retry = retrieved(vec![incoming(&peer, "hash-n1", 2_000)], "cursor-n1");
        retry.node_cursors = vec![("me/0/node".into(), "new-hash".into())];
        finish_sync(&mut app, &store, &identity.session_id, Ok(retry), &mut downloads, Some(&committed));
        assert_eq!(committed.lock().unwrap()["me/0/node"], "new-hash");
        assert_eq!(store.node_cursors()["me/0/node"], "new-hash");
    }

    #[test]
    fn a_failed_sync_that_only_found_a_group_leaves_no_trace() {
        let (_guard, identity, store) = test_store(0x63);
        let mut app = App::new(identity.session_id.clone());
        let mut downloads = std::collections::VecDeque::new();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER fail BEFORE INSERT ON contacts BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let group = "03".to_owned() + &"55".repeat(32);
        let mut result = retrieved(Vec::new(), "cursor-g");
        result.groups = vec![DiscoveredGroup { id: group.clone(), name: "New group".into(), can_write: true }];
        finish_sync(&mut app, &store, &identity.session_id, Ok(result), &mut downloads, None);
        assert!(app.status.contains("WILL RETRY"), "{}", app.status);
        assert!(app.conversations.iter().all(|c| c.id != group), "group rolled back in memory too");
    }

    #[test]
    fn same_millisecond_group_messages_are_kept_apart_and_old_databases_migrate() {
        let (_guard, identity, store) = test_store(0x44);
        let group = "03".to_owned() + &"77".repeat(32);
        let alice = group_message("05aa", "from alice");
        let mut bob = group_message("05bb", "from bob");
        store.save_message(&group, &alice).unwrap();
        store.save_message(&group, &bob).unwrap();
        bob.body = "bob edited".into();
        store.update_message(&group, &bob).unwrap();
        store.mark_message_read(&group, &alice).unwrap();
        let load = |store: &LocalStore| {
            let mut app = App::new(identity.session_id.clone());
            store.load(&mut app).unwrap();
            let index = app.conversations.iter().position(|c| c.id == group).unwrap();
            let mut bodies: Vec<(String, bool)> = app.conversations[index]
                .messages
                .iter()
                .map(|m| (m.body.clone(), m.is_read))
                .collect();
            bodies.sort();
            bodies
        };
        assert_eq!(
            load(&store),
            vec![("bob edited".into(), false), ("from alice".into(), true)]
        );
        store.delete_message(&group, &bob).unwrap();
        assert_eq!(load(&store), vec![("from alice".into(), true)]);

        // An old-format table (no sender column) is rebuilt with the author
        // read back from the encrypted rows.
        let body = store.encrypted_payload(&group_message("05cc", "old row")).unwrap();
        store
            .connection
            .execute_batch(
                "DROP TABLE messages;
                 CREATE TABLE messages (peer_id TEXT NOT NULL, timestamp_ms INTEGER NOT NULL,
                    outgoing INTEGER NOT NULL, body BLOB NOT NULL,
                    receipt_status INTEGER NOT NULL DEFAULT 0, is_read INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(peer_id, timestamp_ms, outgoing));",
            )
            .unwrap();
        store
            .connection
            .execute(
                "INSERT INTO messages(peer_id, timestamp_ms, outgoing, body) VALUES (?1, 5000, 0, ?2)",
                params![group, body],
            )
            .unwrap();
        store.add_sender_to_message_key().unwrap();
        let sender: String = store
            .connection
            .query_row("SELECT sender FROM messages", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sender, "05cc");
        store.save_message(&group, &group_message("05dd", "new row")).unwrap();
        assert_eq!(load(&store).len(), 2);
    }
}

#[cfg(test)]
mod delete_content_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn only_a_group_key_signature_authorizes_deleting_others() {
        let admin = SigningKey::from_bytes(&[9; 32]);
        let group = format!("03{}", hex::encode(admin.verifying_key().to_bytes()));
        let ids = vec!["05aa".to_owned(), "05bb".to_owned()];
        let hashes = vec!["h1".to_owned()];
        let signed = admin.sign(b"DELETE_CONTENT12305aa05bbh1").to_bytes();
        assert!(verify_delete_content_signature(&group, 123, &ids, &hashes, &signed));
        // Different timestamp, members, or a member's own key: rejected.
        assert!(!verify_delete_content_signature(&group, 124, &ids, &hashes, &signed));
        assert!(!verify_delete_content_signature(&group, 123, &ids[..1], &hashes, &signed));
        let member = SigningKey::from_bytes(&[3; 32]);
        let forged = member.sign(b"DELETE_CONTENT12305aa05bbh1").to_bytes();
        assert!(!verify_delete_content_signature(&group, 123, &ids, &hashes, &forged));
        assert!(!verify_delete_content_signature(&group, 123, &ids, &hashes, &[0; 10]));
    }

    fn message(sender: &str, timestamp: u64, hash: &str) -> Message {
        let mut message = Message::new("x".into(), timestamp, false);
        message.sender = Some(sender.into());
        message.server_hash = Some(hash.into());
        message
    }

    #[test]
    fn delete_rules_follow_the_official_clients() {
        let me = "05me";
        let ids = vec!["05bb".to_owned()];
        let hashes = vec!["h-old-bb".to_owned(), "h-cc".to_owned()];
        let old_bb = message("05bb", 100, "h-old-bb");
        let other_bb = message("05bb", 150, "h-other");
        let new_bb = message("05bb", 200, "h-new-bb");
        let cc = message("05cc", 100, "h-cc");
        // A member (no admin signature) deletes only their own, by hash.
        let member = DeleteContent { admin: false, author: "05bb", ids: &ids, hashes: &hashes, before_ms: 150 };
        assert!(member.matches(&old_bb, me));
        assert!(!member.matches(&other_bb, me), "not named by hash");
        assert!(!member.matches(&cc, me), "someone else's message");
        // An admin deletes the member's messages and hashed ones, up to the
        // command time only.
        let admin = DeleteContent { admin: true, author: "05ad", ids: &ids, hashes: &hashes, before_ms: 150 };
        assert!(admin.matches(&old_bb, me) && admin.matches(&other_bb, me) && admin.matches(&cc, me));
        assert!(!admin.matches(&new_bb, me), "sent after the command");
        let mut mine = Message::new("mine".into(), 100, true);
        mine.server_hash = Some("h-mine".into());
        assert!(!admin.matches(&mine, me));
        let admin_me = DeleteContent { admin: true, author: "05ad", ids: &[me.to_owned()], hashes: &[], before_ms: 150 };
        assert!(admin_me.matches(&mine, me));
    }
}

#[cfg(test)]
mod control_char_tests {
    use super::*;
    use ratatui::backend::TestBackend;

    #[test]
    fn control_characters_from_others_never_reach_the_terminal() {
        let mut app = App::new("05".to_owned() + &"11".repeat(32));
        let i = app.ensure_contact(&("05".to_owned() + &"22".repeat(32)));
        app.conversations[i].name = "evil\x1b]0;title\x07name".into();
        let mut message = Message::new("hi\x1b[2J\x1b]52;c;ZXZpbA==\x07there\r\x08x".into(), 1, false);
        message.quote = Some(QuoteRef { id: 0, author: "x".into(), text: "\x1b[31mred".into() });
        app.conversations[i].messages.push(message);
        app.conversations[i].refresh_preview();
        app.selected = i;
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &mut app)).unwrap();
        let control = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .filter(|cell| cell.symbol().chars().any(char::is_control))
            .count();
        assert_eq!(control, 0);
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;

    #[test]
    fn only_our_own_messages_follow_sync_target() {
        let me = "05".to_owned() + &"11".repeat(32);
        let peer = "05".to_owned() + &"22".repeat(32);
        let group = "03".to_owned() + &"33".repeat(32);
        let content = |target: &str| Content {
            data_message: Some(DataMessage {
                body: Some("hi".into()),
                timestamp: Some(1),
                sync_target: Some(target.into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Our sync copy of a group message goes to the group.
        let mine = parse_content(&me, "h".into(), me.clone(), me.clone(), 1, content(&group)).unwrap();
        assert_eq!(mine.contact_id, group);
        // Someone else cannot redirect their message into another chat.
        let theirs = parse_content(&me, "h".into(), peer.clone(), peer.clone(), 1, content(&group)).unwrap();
        assert_eq!(theirs.contact_id, peer);
        // Malformed targets are ignored.
        let bad = parse_content(&me, "h".into(), me.clone(), me.clone(), 1, content("03zz")).unwrap();
        assert_eq!(bad.contact_id, me);
        assert!(!is_chat_id("04".to_owned().as_str()));
    }
}

#[cfg(test)]
mod note_to_self_tests {
    use super::*;

    #[test]
    fn own_chat_is_note_to_self() {
        let me = "05".to_owned() + &"11".repeat(32);
        let peer = "05".to_owned() + &"22".repeat(32);
        let mut app = App::new(me.clone());
        let own = app.ensure_contact(&me);
        let other = app.ensure_contact(&peer);
        assert_eq!(app.conversations[own].title(&me), "Note to Self");
        assert_eq!(app.conversations[other].title(&me), short_id(&peer));
    }
}

#[cfg(test)]
mod delete_prompt_tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn screen(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn prompt_offers_everyone_only_for_own_messages() {
        let me = "05".to_owned() + &"11".repeat(32);
        let mut app = App::new(me);
        app.delete_prompt = Some(true);
        let own = screen(&mut app);
        assert!(own.contains("Delete for everyone"));
        assert!(own.contains("Delete on this device only"));
        app.delete_prompt = Some(false);
        let theirs = screen(&mut app);
        assert!(!theirs.contains("Delete for everyone"));
        assert!(theirs.contains("Delete on this device only"));
    }
}

