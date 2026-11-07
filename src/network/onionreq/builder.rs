//! Onion request builder - constructs layered encrypted onion request payloads.
//!
//! Port of `session::onionreq::Builder` from the C++ code.
//!
//! Each layer wraps: `[4-byte LE size][encrypted_blob][routing_json]`
//!
//! The final payload structure going to the first hop is:
//! `[4-byte LE size][encrypted_blob][wrapper_json]`
//! where `wrapper_json` contains `{"ephemeral_key":"...", "enc_type":"..."}`

use crate::network::key_types::{
    Ed25519Pubkey, X25519Keypair, X25519Pubkey, compute_x25519_pubkey,
};
use crate::network::onionreq::hop_encryption::{EncryptType, HopEncryption};
use crate::network::service_node::ServiceNode;
use crate::network::types::NetworkDestination;

/// Error type for onion request builder operations.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Destination not set: {0}")]
    DestinationNotSet(String),
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Key error: {0}")]
    KeyError(#[from] crate::network::key_types::KeyError),
    #[error("Invalid destination: {0}")]
    InvalidDestination(String),
}

/// Extracts the X25519 pubkey for a given network destination.
pub fn pubkey_for_destination(
    destination: &NetworkDestination,
) -> Result<X25519Pubkey, BuilderError> {
    match destination {
        NetworkDestination::ServiceNode(sn) => {
            compute_x25519_pubkey(&sn.ed25519_pubkey).map_err(BuilderError::KeyError)
        }
        NetworkDestination::Server(sd) => Ok(sd.x25519_pubkey),
    }
}

/// Builder for constructing onion request payloads.
pub struct Builder {
    enc_type: EncryptType,
    is_v4_request: bool,
    hops: Vec<(Ed25519Pubkey, X25519Pubkey)>,
    endpoint: String,
    destination_x25519_pubkey: Option<X25519Pubkey>,

    // Snode destination
    ed25519_pubkey: Option<Ed25519Pubkey>,

    // Server destination
    host: Option<String>,
    protocol: Option<String>,
    method: Option<String>,
    port: Option<u16>,
    headers: Option<Vec<(String, String)>>,

    /// After `build()`, contains the final-hop X25519 keypair needed to decrypt the response.
    pub final_hop_x25519_keypair: Option<X25519Keypair>,
}

impl Builder {
    /// Creates a new empty builder with default settings.
    pub fn new() -> Self {
        Self {
            enc_type: EncryptType::XChaCha20,
            is_v4_request: false,
            hops: Vec::new(),
            endpoint: String::new(),
            destination_x25519_pubkey: None,
            ed25519_pubkey: None,
            host: None,
            protocol: None,
            method: None,
            port: None,
            headers: None,
            final_hop_x25519_keypair: None,
        }
    }

    /// Creates a builder pre-configured for a given destination, endpoint, and path nodes.
    pub fn make(
        destination: &NetworkDestination,
        endpoint: &str,
        nodes: &[ServiceNode],
        enc_type: EncryptType,
    ) -> Result<Self, BuilderError> {
        let mut builder = Self::new();
        builder.enc_type = enc_type;
        builder.endpoint = endpoint.to_string();
        builder.destination_x25519_pubkey = Some(pubkey_for_destination(destination)?);
        builder.is_v4_request =
            matches!(destination, NetworkDestination::Server(_));

        builder.set_destination(destination)?;
        for node in nodes {
            builder.add_hop_from_ed25519(&node.ed25519_pubkey)?;
        }

        Ok(builder)
    }

    /// Returns the current encryption type.
    pub fn enc_type(&self) -> EncryptType {
        self.enc_type
    }

    /// Sets the encryption type for hop encryption.
    pub fn set_enc_type(&mut self, enc_type: EncryptType) {
        self.enc_type = enc_type;
    }

    /// Returns `true` if this is a V4 (server-destined) request.
    pub fn is_v4_request(&self) -> bool {
        self.is_v4_request
    }

    /// Returns the destination's X25519 public key, if set.
    pub fn destination_x25519_public_key(&self) -> Option<&X25519Pubkey> {
        self.destination_x25519_pubkey.as_ref()
    }

    /// Sets the final destination for the onion request.
    pub fn set_destination(
        &mut self,
        destination: &NetworkDestination,
    ) -> Result<(), BuilderError> {
        self.ed25519_pubkey = None;

        match destination {
            NetworkDestination::ServiceNode(sn) => {
                self.is_v4_request = false;
                self.ed25519_pubkey = Some(sn.ed25519_pubkey);
                self.destination_x25519_pubkey =
                    Some(compute_x25519_pubkey(&sn.ed25519_pubkey)?);
            }
            NetworkDestination::Server(sd) => {
                self.is_v4_request = true;
                self.host = Some(sd.host.clone());
                self.method = Some(sd.method.clone());

                // Strip "://" from protocol if present
                let proto = if let Some(pos) = sd.protocol.find("://") {
                    sd.protocol[..pos].to_string()
                } else {
                    sd.protocol.clone()
                };
                self.protocol = Some(proto);
                self.port = sd.port;
                self.headers = sd.headers.clone();
                self.destination_x25519_pubkey = Some(sd.x25519_pubkey);
            }
        }
        Ok(())
    }

    /// Adds a hop by providing both ed25519 and x25519 pubkeys.
    pub fn add_hop(&mut self, ed25519_pk: Ed25519Pubkey, x25519_pk: X25519Pubkey) {
        self.hops.push((ed25519_pk, x25519_pk));
    }

    /// Adds a hop by computing X25519 from the Ed25519 key.
    pub fn add_hop_from_ed25519(
        &mut self,
        ed25519_pk: &Ed25519Pubkey,
    ) -> Result<(), BuilderError> {
        let x25519_pk = compute_x25519_pubkey(ed25519_pk)?;
        self.hops.push((*ed25519_pk, x25519_pk));
        Ok(())
    }

    /// Generates the inner payload for the final destination.
    pub fn generate_payload(&self, body: Option<&[u8]>) -> Vec<u8> {
        // If we don't have server request data, build snode-style payload
        if self.host.is_none() || self.protocol.is_none() || self.method.is_none() {
            let params: serde_json::Value = if let Some(b) = body {
                if b.is_empty() {
                    serde_json::json!({})
                } else {
                    serde_json::from_slice(b).unwrap_or(serde_json::json!({}))
                }
            } else {
                serde_json::json!({})
            };

            let wrapped = serde_json::json!({
                "method": self.endpoint,
                "params": params,
            });

            return wrapped.to_string().into_bytes();
        }

        // Server request (V4 style) using bencoded payload
        let mut headers_json = serde_json::Map::new();

        if let Some(ref hdrs) = self.headers {
            for (key, value) in hdrs {
                if key != "User-Agent" {
                    headers_json.insert(
                        key.clone(),
                        serde_json::Value::String(value.clone()),
                    );
                }
            }
        }

        if body.is_some() && !headers_json.contains_key("Content-Type") {
            headers_json.insert(
                "Content-Type".to_string(),
                serde_json::Value::String("application/json".to_string()),
            );
        }

        let mut final_endpoint = self.endpoint.clone();
        if !final_endpoint.is_empty() && !final_endpoint.starts_with('/') {
            final_endpoint = format!("/{}", final_endpoint);
        }

        let request_info = serde_json::json!({
            "method": self.method.as_deref().unwrap_or("GET"),
            "endpoint": final_endpoint,
            "headers": headers_json,
        });

        // Bencode as a list of strings
        let request_info_str = request_info.to_string();
        let mut parts: Vec<&[u8]> = vec![request_info_str.as_bytes()];

        if let Some(b) = body {
            if !b.is_empty() {
                parts.push(b);
            }
        }

        // Simple bencode list encoding
        let mut result = Vec::new();
        result.push(b'l');
        for part in &parts {
            result.extend_from_slice(format!("{}:", part.len()).as_bytes());
            result.extend_from_slice(part);
        }
        result.push(b'e');

        result
    }

    /// Generates the onion blob from an optional plaintext body.
    pub fn generate_onion_blob(
        &mut self,
        plaintext_body: Option<&[u8]>,
    ) -> Result<Vec<u8>, BuilderError> {
        let payload = self.generate_payload(plaintext_body);
        self.build(&payload)
    }

    /// Builds the final onion-encrypted payload from inner payload data.
    ///
    /// Returns the complete payload to be sent to the first hop in the path.
    pub fn build(&mut self, payload: &[u8]) -> Result<Vec<u8>, BuilderError> {
        let dest_x25519 = self.destination_x25519_pubkey.ok_or_else(|| {
            BuilderError::DestinationNotSet("No destination x25519 public key".into())
        })?;

        // Generate ephemeral keypair for the final hop
        let (mut eph_pk, mut eph_sk) = crate::network::key_types::x25519_keypair();

        let enc = HopEncryption::new(eph_sk.clone(), eph_pk, false);
        let final_route: serde_json::Value;
        let mut blob: Vec<u8>;

        // Encrypt the inner payload for the destination
        if self.host.is_some() && self.protocol.is_some() {
            // Server destination
            let port = self.port.unwrap_or_else(|| {
                if self.protocol.as_deref() == Some("https") {
                    443
                } else {
                    80
                }
            });

            final_route = serde_json::json!({
                "host": self.host.as_deref().unwrap_or(""),
                "target": "/oxen/v4/lsrpc",
                "method": "POST",
                "protocol": self.protocol.as_deref().unwrap_or(""),
                "port": port,
                "ephemeral_key": eph_pk.hex(),
                "enc_type": self.enc_type.as_str(),
            });

            blob = enc
                .encrypt(self.enc_type, payload, &dest_x25519)
                .map_err(|e| BuilderError::EncryptionFailed(e.to_string()))?;
        } else if let Some(ref ed_pk) = self.ed25519_pubkey {
            // Service node destination
            let control = serde_json::json!({"headers": ""});

            final_route = serde_json::json!({
                "destination": ed_pk.hex(),
                "ephemeral_key": eph_pk.hex(),
                "enc_type": self.enc_type.as_str(),
            });

            let control_str = control.to_string();
            let size_bytes = (payload.len() as u32).to_le_bytes();
            let mut data = Vec::with_capacity(4 + payload.len() + control_str.len());
            data.extend_from_slice(&size_bytes);
            data.extend_from_slice(payload);
            data.extend_from_slice(control_str.as_bytes());

            blob = enc
                .encrypt(self.enc_type, &data, &dest_x25519)
                .map_err(|e| BuilderError::EncryptionFailed(e.to_string()))?;
        } else {
            return Err(BuilderError::DestinationNotSet(
                "Missing ed25519 or server destination".into(),
            ));
        }

        // Save the final-hop keypair for response decryption
        self.final_hop_x25519_keypair = Some((eph_pk, eph_sk.clone()));

        // Now wrap for each intermediate hop (in reverse order)
        for (i, (_ed_pk, x25519_pk)) in self.hops.iter().rev().enumerate() {
            let routing: serde_json::Value = if i == 0 {
                // First reverse iteration = closest to destination = use final_route
                final_route.clone()
            } else {
                // Intermediate hop: forward to the next hop's ed25519 key
                let (next_ed, _) = &self.hops[self.hops.len() - i];
                serde_json::json!({
                    "destination": next_ed.hex(),
                    "ephemeral_key": eph_pk.hex(),
                    "enc_type": self.enc_type.as_str(),
                })
            };

            let routing_str = routing.to_string();
            let size_bytes = (blob.len() as u32).to_le_bytes();
            let mut data = Vec::with_capacity(4 + blob.len() + routing_str.len());
            data.extend_from_slice(&size_bytes);
            data.extend_from_slice(&blob);
            data.extend_from_slice(routing_str.as_bytes());

            // Generate new ephemeral keypair for this hop
            let (new_pk, new_sk) = crate::network::key_types::x25519_keypair();
            eph_pk = new_pk;
            eph_sk = new_sk;

            let hop_enc = HopEncryption::new(eph_sk.clone(), eph_pk, false);
            blob = hop_enc
                .encrypt(self.enc_type, &data, x25519_pk)
                .map_err(|e| BuilderError::EncryptionFailed(e.to_string()))?;
        }

        // Final wrapper for the first hop
        let wrapper = serde_json::json!({
            "ephemeral_key": eph_pk.hex(),
            "enc_type": self.enc_type.as_str(),
        });
        let wrapper_str = wrapper.to_string();

        let size_bytes = (blob.len() as u32).to_le_bytes();
        let mut result = Vec::with_capacity(4 + blob.len() + wrapper_str.len());
        result.extend_from_slice(&size_bytes);
        result.extend_from_slice(&blob);
        result.extend_from_slice(wrapper_str.as_bytes());

        Ok(result)
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::key_types::{Ed25519Pubkey, X25519Pubkey, x25519_keypair};
    use crate::network::swarm::INVALID_SWARM_ID;
    use crate::network::types::ServerDestination;

    fn make_test_node(suffix: u8) -> ServiceNode {
        // Generate a valid Ed25519 keypair so the pubkey is on the curve
        let seed = {
            let mut s = [0u8; 32];
            s[0] = suffix;
            s
        };
        let (pk, _sk) = crate::crypto::ed25519::ed25519_key_pair_from_seed(&seed).unwrap();
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey(pk),
            ip: [1, 2, 3, suffix],
            https_port: 443,
            omq_port: 22000,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        }
    }

    #[test]
    fn test_builder_snode_destination() {
        let dest_node = make_test_node(10);
        let path_nodes = vec![make_test_node(1), make_test_node(2), make_test_node(3)];

        let dest = NetworkDestination::ServiceNode(dest_node);
        let mut builder =
            Builder::make(&dest, "store", &path_nodes, EncryptType::XChaCha20).unwrap();

        let payload = b"test payload";
        let result = builder.build(payload);
        assert!(result.is_ok());

        let blob = result.unwrap();
        assert!(!blob.is_empty());

        // Should have saved the final hop keypair
        assert!(builder.final_hop_x25519_keypair.is_some());
    }

    #[test]
    fn test_builder_server_destination() {
        let (server_pk, _) = x25519_keypair();
        let dest = NetworkDestination::Server(ServerDestination {
            protocol: "https".into(),
            host: "example.com".into(),
            x25519_pubkey: server_pk,
            port: Some(443),
            headers: None,
            method: "POST".into(),
        });

        let path_nodes = vec![make_test_node(1), make_test_node(2), make_test_node(3)];
        let mut builder =
            Builder::make(&dest, "/api/v1/test", &path_nodes, EncryptType::XChaCha20).unwrap();

        let payload = b"{}";
        let result = builder.build(payload);
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_no_destination() {
        let mut builder = Builder::new();
        let result = builder.build(b"test");
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_payload_snode() {
        let mut builder = Builder::new();
        builder.endpoint = "store".to_string();

        let payload = builder.generate_payload(Some(b"{}"));
        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(parsed["method"], "store");
    }

    #[test]
    fn test_generate_payload_server() {
        let mut builder = Builder::new();
        builder.endpoint = "api/test".to_string();
        builder.host = Some("example.com".to_string());
        builder.protocol = Some("https".to_string());
        builder.method = Some("POST".to_string());
        builder.destination_x25519_pubkey = Some(X25519Pubkey([0u8; 32]));

        let payload = builder.generate_payload(Some(b"body data"));
        // Should be bencoded
        assert!(payload.starts_with(b"l"));
        assert!(payload.ends_with(b"e"));
    }

    #[test]
    fn test_pubkey_for_destination() {
        let (pk, _) = x25519_keypair();
        let dest = NetworkDestination::Server(ServerDestination {
            protocol: "https".into(),
            host: "example.com".into(),
            x25519_pubkey: pk,
            port: None,
            headers: None,
            method: "GET".into(),
        });

        let result = pubkey_for_destination(&dest).unwrap();
        assert_eq!(result, pk);
    }
}
