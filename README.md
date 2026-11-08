# Session TUI (Rust)

A terminal chat client for Session, implemented in Rust. It supports text conversations, groups, encrypted local history, and image, audio, and file attachments. It does not provide voice or video calls.

This repository includes the Session Rust core modules used by the client, so it can be built independently of the original `libsession-rust` checkout.

## Features

- Sign in with a 32-byte hex seed or a 13-word Session recovery phrase. The seed can be saved: with DPAPI on Windows, and on Linux/macOS in a passphrase-encrypted file (Argon2id + XChaCha20-Poly1305, mode 0600). `--forget-seed` removes it.
- Chat with contacts and groups (as admin or ordinary member); accept group invites with `/accept`. Messages are fetched automatically, or with `/rsync`. Groups can't be created or managed here yet; create them in the official app.
- Message requests: chats from people you haven't approved are listed separately, marked REQUEST. Until you `/accept` (or reply), they get no read or delivery receipts and their attachments aren't downloaded. `/decline` deletes the request.
- Chat management: `/delete` deletes a chat and its messages (hidden on your other devices too; the contact stays), `/remove` removes a contact from your account and deletes the chat. Both ask for confirmation.
- Messages are sent in the background through a persistent outbox: a message is saved before the input is cleared, failed sends are retried automatically with backoff, and anything unsent (including copies for your other devices and read receipts) continues after a restart. `/retry` sends a failed message, or a parked device copy, right away. Attachment uploads in progress are not resumed after quitting.
- Send and receive text, images, audio and other files. Several files can go in one message (`/attach a.jpg b.jpg -- caption`), and albums are shown as one message.
- Send a screenshot or other image straight from the clipboard with `/paste [-- caption]`. The image is saved briefly to a private temporary file, which is deleted once the upload finishes. This doesn't work over SSH, where the local clipboard isn't reachable.
- View images with `/view N` or a mouse click, and use ←/→ to step through the images in a message. Save attachments with `/save [N] [PATH]`.
- Emoji shortcodes such as `:joy:`, `:haha:` or `:+1:` are converted when sending.
- Replies (`r` on a message), reactions (`+` or `/react EMOJI`), disappearing messages (`/disappear off | read 12h | send 1d`), typing indicators, link previews, and notices for screenshots, missed calls and group changes.
- Delete or unsend messages, with read receipts (delivery receipts are not sent, as in the official apps).
- Disappear-after-read messages are also shortened on the network when read, and a deadline set on another device is respected, as in the official apps (1:1 chats).
- Account data syncs with your other Session devices: profile name, contacts (approved and blocked), per-chat disappearing settings, read state, and joined groups.
- Local history is stored in an SQLCipher-encrypted database.
- Use `https_proxy` or `HTTPS_PROXY` for HTTPS connections.
- Use `--debug` to write `session-tui-debug.log` in the current directory.
- Tab switches focus among chats, messages and the composer; use the arrow keys to navigate. `/1` to `/9` switch to the chat with that number in the chat list.
- Mouse: click a chat or image, scroll with the wheel, and drag the border between the chat list and the messages to resize (the width is remembered).
- Copying: double-click a message to copy its text, the chat title to copy the contact's Session ID, or the top bar to copy your own ID. On the new-account screen, press C or click to copy the recovery phrase. Copying uses OSC 52 (Windows Terminal and most terminals) and, on Linux, `wl-copy`, `xclip` or `xsel` when installed. Shift+drag still selects text in most terminals.
- Privacy: full Session IDs aren't shown on screen (a shortened form is), and control characters in names, messages and file names are stripped so they can't inject terminal escape sequences.

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

GitHub Actions builds the binaries on every push and pull request. Pushing a `v*` tag also publishes them as a GitHub release.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
