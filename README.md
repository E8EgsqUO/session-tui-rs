# Session TUI (Rust)

A terminal chat client for Session, implemented in Rust. It supports text conversations, groups, encrypted local history, and image, audio, and file attachments. It does not provide voice or video calls.

This repository includes the Session Rust core modules used by the client, so it can be built independently of the original `libsession-rust` checkout.

## Features

- Sign in with a 32-byte hex seed or a 13-word Session recovery phrase. The seed can be saved: with DPAPI on Windows, and on Linux/macOS in a passphrase-encrypted file (Argon2id + XChaCha20-Poly1305, mode 0600). `--forget-seed` removes it.
- Chat with contacts and groups (as admin or ordinary member); accept group invites with `/accept`. Messages are fetched automatically, or with `/rsync`.
- Messages are sent in the background; failed ones can be resent with `/retry`.
- Send and receive text, images, audio and other files. Several files can go in one message (`/attach a.jpg b.jpg -- caption`), and albums are shown as one message.
- View images with `/view N` or a mouse click, and use ←/→ to step through the images in a message. Save attachments with `/save [N] [PATH]`.
- Replies (`r` on a message), reactions (`+` or `/react EMOJI`), disappearing messages (`/disappear off | read 12h | send 1d`), typing indicators, link previews, and notices for screenshots, missed calls and group changes.
- Delete or unsend messages, with read and delivery receipts.
- Account data syncs with your other Session devices: profile name, contacts (approved and blocked), per-chat disappearing settings, read state, and joined groups.
- Local history is stored in an SQLCipher-encrypted database.
- Use `https_proxy` or `HTTPS_PROXY` for HTTPS connections.
- Use `--debug` to write `session-tui-debug.log` in the current directory.
- Tab switches focus among chats, messages and the composer; use the arrow keys to navigate.

Voice and video calls are not supported.

## Build

Requirements: Rust 1.93 or newer and `protoc`.

```sh
cargo build --locked --release --bin session-tui
```

Run the client with:

```sh
cargo run --release --bin session-tui
```

GitHub Actions builds downloadable binaries for Linux x86_64, macOS ARM64, and Windows x86_64 on pushes and pull requests.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
