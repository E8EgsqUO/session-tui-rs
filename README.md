# Session TUI (Rust)

A terminal chat client for Session, implemented in Rust. It supports text conversations, groups, encrypted local history, and image, audio, and file attachments. It does not provide voice or video calls.

This repository includes the Session Rust core modules used by the client, so it can be built independently of the original `libsession-rust` checkout.

## Features

- Sign in with a 32-byte hex seed or a 13-word Session recovery phrase. The seed can be saved: with DPAPI on Windows, and on Linux/macOS in a passphrase-encrypted file (Argon2id + XChaCha20-Poly1305, mode 0600). `--forget-seed` removes it.
- Chat with contacts and groups (as admin or ordinary member); accept group invites with `/accept`. Messages are fetched automatically, or with `/rsync`. Groups can't be created or managed here yet; create them in the official app.
- Message requests: chats from people you haven't approved are listed separately, marked REQUEST. Until you `/accept` (or reply), they get no read or delivery receipts and their attachments aren't downloaded. `/decline` deletes the request.
- Chat management: `/delete` deletes all messages in a chat (the chat stays), `/remove` removes a contact or group from your account and deletes the chat (on your other devices too). Both ask for confirmation.
- Messages are sent in the background through a persistent outbox: a message is saved before the input is cleared, failed sends are retried automatically with backoff, and queued text messages, copies for your other devices and read receipts continue after a restart, subject to retry limits. Failed receipt tasks are eventually dropped; message tasks wait for `/retry` when their automatic budget is exhausted. `/retry` sends a failed message, or a parked device copy, right away. Attachment uploads in progress are not resumed after quitting.
- Send and receive text, images, audio and other files. Several files can go in one message (`/attach a.jpg b.jpg -- caption`), and albums are shown as one message.
- Send a screenshot or other image straight from the clipboard with `/paste [-- caption]`. The image is saved briefly to a private temporary file, which is deleted once the upload finishes. Clipboard access requires a local graphical session; in a typical SSH session the local desktop clipboard is unavailable.
- View images with `/view N` or a mouse click, and use ←/→ to step through the images in a message. Save attachments with `/save [N] [PATH]`.
- Emoji shortcodes such as `:joy:`, `:haha:` or `:+1:` are converted when sending.
- Replies (`/r1`–`/r5` for a message on screen, counted up from the lowest; or `/reply` on the selected one), unsending your own messages (`/u1`–`/u3` counted among your messages on screen; asks first), reactions (`/e1`–`/e5` the same way, `+`, or `/react [EMOJI]`), disappearing messages (`/disappear off | read 12h | send 1d`), typing indicators, received link previews, and notices for screenshots, missed calls and group changes.
- Delete or unsend messages. As in Session, a deleted message leaves a "This message was deleted" notice in its place ("…on this device" for a local delete), also when the other side deletes theirs; deleting the notice removes it. Read receipts are sent. This TUI does not send delivery receipts.
- Disappear-after-read messages are also shortened on the network when read, and a deadline set on another device is respected, as in the official apps (1:1 chats).
- Account data syncs with your other Session devices: profile name, contacts (approved and blocked), per-chat disappearing settings, read state, and joined groups.
- Local history is stored in an SQLCipher-encrypted database.
- Search the local history with `/search WORD` (this chat), `/search --all WORD` or `/search --chat ID|NAME WORD`, optionally limited with `--from YYYY-MM-DD` / `--to YYYY-MM-DD` (local dates, both inclusive). Matching ignores letter case with simple Unicode case folding (per-character lowercase, plus ß = ss and ς = σ; not full Unicode case folding). ↑/↓ select a result and Enter opens the chat at that message, briefly highlighted; `/search` alone reopens the last results. Disappeared and deleted messages are not found. The search runs over the decrypted history in memory, off the UI thread, and keeps the newest 500 hits.
- The transcript shows date lines (Today, Yesterday, or the date, in the local time zone) and an "Unread Messages" line before the first message that was unread when the chat was opened. The lines are display only. In the message list, End (or Ctrl+End anywhere) jumps to the newest message.
- Drafts: text you haven't sent is kept per chat. Switching chats brings back that chat's draft, and drafts survive a restart. They are stored encrypted in the local database (written after a short pause in typing, on switching chats and on quit) and removed once the message is queued or the chat is deleted. A command being typed (`/…`) is not saved as a draft.
- `/filter WORD` shows only chats whose name or ID contains WORD (any letter case); `/filter --unread` only chats with unread messages; `/filter` alone shows all again. The list header shows the filter and the count, and `/1`–`/9` and ←/→ follow the chats shown. `/pin` and `/unpin` keep the open chat at the top (marked `^`). Filter and pins are local to this device.
- `/unread` goes to the first unread message of the open chat (the "Unread Messages" line), and Alt+N to the next chat with unread messages (in list order, within the filter). `/goto YYYY-MM-DD` goes to the first message of that local date, if there is one. These only move the view.
- `/bookmark` / `/unbookmark` mark the selected message (★); `/bookmarks` lists them and Enter opens one. Only a reference is stored (chat, time, author), on this device; bookmarks of deleted or disappeared messages are dropped, never shown.
- `/media` lists the attachments of the open chat (name, type, size, sender, time): Enter opens the message, V views an image, S saves the file like `/save`. `/links` lists the http(s) links in the chat: Enter opens the message, C copies the link. Nothing is downloaded or opened to build the lists. Both show the newest 1000 entries.
- `/help` (or `/?`) shows all commands and keys. Tab on a partial command (`/se`) completes it, or the common part of several; Tab again cycles through them. Otherwise Tab moves focus as before.
- `/net` opens a network diagnostics page: connection state, onion paths (3 hops each, keys shortened to 4 characters), known service nodes and cached swarms, onion round-trip times, failures and round-trip success rate over the last 5 minutes (a reply came back through the path; it does not mean a message was stored or delivered), the last successful sync, outbox tasks waiting / retrying / failed, whether an HTTPS proxy is set (without credentials), and recent errors with keys and addresses masked. It only reads what the client already knows and sends no requests; R refreshes and Esc returns. A round trip is a whole onion request (all three hops, the destination and back); single-node latency is not measured.
- Use `https_proxy` or `HTTPS_PROXY` for HTTPS connections.
- Use `--debug` to write `session-tui-debug.log` in the current directory.
- Tab switches focus among chats, messages and the composer; use the arrow keys to navigate. `/1` to `/9` switch to the chat with that number in the chat list.
- Mouse: click a chat or image, scroll with the wheel, and drag the border between the chat list and the messages to resize (the width is remembered).
- Copying: double-click a message to copy its text, the input box to copy what you have typed, the chat title to copy the contact's Session ID, or the top bar to copy your own ID. On the new-account screen, press C or click to copy the recovery phrase. Copying uses OSC 52 (Windows Terminal and most terminals) and, on Linux, `wl-copy`, `xclip` or `xsel` when installed. Shift+drag still selects text in most terminals.
- Privacy: account/contact IDs in UI metadata are shortened (copy commands intentionally copy the full ID), and control characters in names, messages and file names are stripped so they can't inject terminal escape sequences.

Voice and video calls are not supported.

## Build

Prebuilt binaries for Linux x86_64, macOS ARM64 and Windows x86_64 are on the [Releases](https://github.com/E8EgsqUO/session-tui-rs/releases) page, with SHA-256 checksums in `SHA256SUMS.txt`.

To build it yourself you need Rust 1.93 or newer and `protoc`.

```sh
cargo build --locked --release --bin session-tui
```

Run the client with:

```sh
cargo run --release --bin session-tui
```

GitHub Actions checks formatting, Clippy correctness, all tests, and dependency advisories on pushes and pull requests, alongside binary builds. Dependency auditing also runs weekly. A `v*` tag publishes a release only after these checks and binary builds succeed.

## Implementation scope and checks

- Groups use Session closed-group messaging and account sync. Group creation, membership administration, and communities are not implemented in this TUI. Use an official client to manage groups.
- The TUI uses HTTPS to seed/guard nodes and onion requests to destinations. `src/network/transport/quic.rs` is a configuration stub; QUIC is not an active transport.
- Multi-device state and messages are reconciled by polling and persisted cursors. This is eventual synchronization, not an instantaneous push connection. After-read expiry reconciliation has unit coverage but still needs live cross-device validation.
- Attachment uploads in progress are not durable jobs and will not resume after exit; `/exit` warns before interrupting one. Cached `.blob` attachments remain encrypted until previewed in memory or exported by `/save`; exports are ordinary plaintext files.
- Debug logs omit message bodies and keys but include routing metadata and errors; review them before sharing.

Use Rust 1.93 with the `rustfmt` and `clippy` components, plus `protoc`:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D clippy::correctness
cargo test --locked --all-targets
cargo install cargo-audit --locked --version 0.22.2
cargo audit
```

Historical Clippy style warnings are still reported; correctness errors block CI. Security findings, protocol references, migration boundaries, and the incremental module plan are recorded in [the engineering audit](docs/ENGINEERING_AUDIT.md).

## License

GPL-3.0-only. See [LICENSE](LICENSE).
