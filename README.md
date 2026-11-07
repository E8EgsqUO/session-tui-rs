# Session TUI (Rust)

A terminal chat client for Session, implemented in Rust. It supports text conversations, groups, encrypted local history, and image, audio, and file attachments. It does not provide voice or video calls.

This repository includes the Session Rust core modules used by the client, so it can be built independently of the original `libsession-rust` checkout.

## Features

- Sign in with a 32-byte hex seed or a 13-word Session recovery phrase.
- Chat with contacts and groups; poll for new messages automatically or run `/rsync`.
- Send and receive text, images, audio files, and other files.
- Preview received images and save attachments with `/save`.
- Delete or unsend supported messages.
- Store local history in an SQLCipher-encrypted database.
- Use `https_proxy` or `HTTPS_PROXY` for HTTPS connections.
- Use `--debug` to write `session-tui-debug.log` in the current directory.
- Switch focus among contacts, messages, and the composer with Tab; use arrow keys to navigate.

Delivery and read indicators depend on updates received from the Session network and the other device, so they may not appear immediately.

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
