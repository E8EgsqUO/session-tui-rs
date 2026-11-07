//! Generated protobuf bindings for Session protocol messages.
//!
//! Contains compiled protobuf types for message envelopes, content payloads,
//! and WebSocket protocol frames. Generated at build time from `.proto` files
//! in the `proto/` directory using `prost`.

/// Session message envelope, content, and typed message definitions.
pub mod session_protos {
    include!(concat!(env!("OUT_DIR"), "/session_protos.rs"));
}

/// WebSocket protocol request and response message definitions.
pub mod web_socket_protos {
    include!(concat!(env!("OUT_DIR"), "/web_socket_protos.rs"));
}
