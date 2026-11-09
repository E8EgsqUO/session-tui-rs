use std::fmt;

use crate::network::key_types::{Ed25519Pubkey, KeyError, X25519Pubkey, compute_x25519_pubkey};
use crate::network::swarm::{INVALID_SWARM_ID, SwarmId};

/// A service node on the Session network.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServiceNode {
    pub ed25519_pubkey: Ed25519Pubkey,
    pub ip: [u8; 4],
    pub https_port: u16,
    pub omq_port: u16,
    pub storage_server_version: [u16; 3],
    pub swarm_id: SwarmId,
    pub requested_unlock_height: u64,
}

/// Error type for service node parsing/serialization.
#[derive(Debug, thiserror::Error)]
pub enum ServiceNodeError {
    #[error("Invalid service node serialization: {0}")]
    InvalidSerialization(String),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Invalid IP address: {0}")]
    InvalidIp(String),
    #[error("Invalid port: {0}")]
    InvalidPort(String),
    #[error("Invalid version: {0}")]
    InvalidVersion(String),
    #[error("JSON error: {0}")]
    Json(String),
    #[error("Invalid binary cache: {0}")]
    InvalidCache(String),
}

impl ServiceNode {
    /// Computes the X25519 public key from this node's Ed25519 pubkey.
    pub fn swarm_pubkey(&self) -> Result<X25519Pubkey, KeyError> {
        compute_x25519_pubkey(&self.ed25519_pubkey)
    }

    /// Returns the IP as a dotted-quad string.
    pub fn host(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            self.ip[0], self.ip[1], self.ip[2], self.ip[3]
        )
    }

    /// Returns `host:https_port` string.
    pub fn to_https_string(&self) -> String {
        format!("{}:{}", self.host(), self.https_port)
    }

    /// Returns `host:omq_port` string.
    pub fn to_omq_string(&self) -> String {
        format!("{}:{}", self.host(), self.omq_port)
    }

    /// Serializes this node to the pipe-delimited disk format:
    /// `{ed_pubkey_hex}|{ip}|{https_port}|{omq_port}|{major.minor.patch}|{swarm_id}\n`
    pub fn to_disk(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}.{}.{}|{}\n",
            self.ed25519_pubkey.hex(),
            self.host(),
            self.https_port,
            self.omq_port,
            self.storage_server_version[0],
            self.storage_server_version[1],
            self.storage_server_version[2],
            self.swarm_id,
        )
    }

    /// Parses a service node from the pipe-delimited disk format.
    pub fn from_disk(s: &str) -> Result<Self, ServiceNodeError> {
        let s = s.trim_end_matches('\n').trim_end_matches('\r');
        let parts: Vec<&str> = s.split('|').collect();
        if parts.len() != 6 {
            return Err(ServiceNodeError::InvalidSerialization(format!(
                "Expected 6 pipe-delimited fields, got {}",
                parts.len()
            )));
        }

        let ed25519_pubkey = Ed25519Pubkey::from_hex(parts[0])?;
        let ip = parse_ip(parts[1])?;

        let https_port: u16 = parts[2]
            .parse()
            .map_err(|_| ServiceNodeError::InvalidPort(parts[2].to_string()))?;
        let omq_port: u16 = parts[3]
            .parse()
            .map_err(|_| ServiceNodeError::InvalidPort(parts[3].to_string()))?;

        let version_parts: Vec<&str> = parts[4].split('.').collect();
        let mut version = [0u16; 3];
        for i in 0..3.min(version_parts.len()) {
            if let Ok(v) = version_parts[i].parse::<u16>() {
                version[i] = v;
            }
        }
        if version == [0, 0, 0] {
            return Err(ServiceNodeError::InvalidVersion(parts[4].to_string()));
        }

        let swarm_id: SwarmId = parts[5].parse().unwrap_or(INVALID_SWARM_ID);

        Ok(ServiceNode {
            ed25519_pubkey,
            ip,
            https_port,
            omq_port,
            storage_server_version: version,
            swarm_id,
            requested_unlock_height: 0,
        })
    }

    /// Parses a service node from JSON.
    pub fn from_json(json: &serde_json::Value) -> Result<Self, ServiceNodeError> {
        let pk_ed = json
            .get("pubkey_ed25519")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceNodeError::Json("missing pubkey_ed25519".into()))?;

        if pk_ed.len() != 64 {
            return Err(ServiceNodeError::Json(
                "pubkey_ed25519 is not a valid hex pubkey".into(),
            ));
        }

        let ed25519_pubkey = Ed25519Pubkey::from_hex(pk_ed)?;

        let mut storage_server_version = [0u16; 3];
        if let Some(ver) = json.get("storage_server_version") {
            if let Some(arr) = ver.as_array() {
                for (i, v) in arr.iter().enumerate().take(3) {
                    if let Some(n) = v.as_i64() {
                        storage_server_version[i] = n as u16;
                    }
                }
            } else if let Some(s) = ver.as_str() {
                for (i, part) in s.split('.').enumerate().take(3) {
                    if let Ok(v) = part.parse::<u16>() {
                        storage_server_version[i] = v;
                    }
                }
            }
        }

        let ip_str = json
            .get("public_ip")
            .or_else(|| json.get("ip"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ServiceNodeError::Json("missing ip/public_ip".into()))?;

        if ip_str == "0.0.0.0" {
            return Err(ServiceNodeError::InvalidIp("0.0.0.0".into()));
        }

        let ip = parse_ip(ip_str)?;

        let https_port: u16 = json
            .get("storage_https_port")
            .or_else(|| json.get("storage_port"))
            .or_else(|| json.get("port_https"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ServiceNodeError::Json("missing https port".into()))?
            as u16;

        let omq_port: u16 = json
            .get("storage_lmq_port")
            .or_else(|| json.get("port_omq"))
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ServiceNodeError::Json("missing omq port".into()))?
            as u16;

        if omq_port == 0 {
            return Err(ServiceNodeError::InvalidPort("omq port is 0".into()));
        }

        let mut swarm_id: SwarmId = INVALID_SWARM_ID;
        if let Some(sid) = json.get("swarm_id").and_then(|v| v.as_u64()) {
            swarm_id = sid;
        } else if let Some(s) = json.get("swarm").and_then(|v| v.as_str()) {
            if let Ok(v) = u64::from_str_radix(s, 16) {
                swarm_id = v;
            }
        }

        let requested_unlock_height = json
            .get("requested_unlock_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        Ok(ServiceNode {
            ed25519_pubkey,
            ip,
            https_port,
            omq_port,
            storage_server_version,
            swarm_id,
            requested_unlock_height,
        })
    }

    /// Parses binary snode cache data. Each snode is 51 bytes:
    /// pubkey(32) | swarm_id(8) | ip(4) | https_port(2) | omq_port(2) | version(3)
    pub fn process_snode_cache_bin(
        data: &[u8],
    ) -> Result<(Vec<ServiceNode>, usize), ServiceNodeError> {
        const SNODE_SIZE: usize = 51;

        if data.len() % SNODE_SIZE != 0 {
            return Err(ServiceNodeError::InvalidCache(format!(
                "Cache size {} is not a multiple of snode size {}",
                data.len(),
                SNODE_SIZE
            )));
        }

        let mut nodes = Vec::with_capacity(data.len() / SNODE_SIZE);
        let mut failed = 0usize;

        for chunk in data.chunks_exact(SNODE_SIZE) {
            let result = (|| -> Result<ServiceNode, ServiceNodeError> {
                let mut offset = 0;

                // Pubkey (32 bytes)
                let ed25519_pubkey = Ed25519Pubkey::from_bytes(&chunk[offset..offset + 32])?;
                offset += 32;

                // Swarm ID (8 bytes big-endian)
                let mut swarm_bytes = [0u8; 8];
                swarm_bytes.copy_from_slice(&chunk[offset..offset + 8]);
                let swarm_id = u64::from_be_bytes(swarm_bytes);
                offset += 8;

                // IP (4 bytes)
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&chunk[offset..offset + 4]);
                offset += 4;

                let ip_u32 = u32::from_be_bytes(ip);
                if ip_u32 == 0 {
                    return Err(ServiceNodeError::InvalidIp("0.0.0.0".into()));
                }

                // HTTPS port (2 bytes big-endian)
                let https_port = u16::from_be_bytes([chunk[offset], chunk[offset + 1]]);
                offset += 2;

                // OMQ port (2 bytes big-endian)
                let omq_port = u16::from_be_bytes([chunk[offset], chunk[offset + 1]]);
                offset += 2;

                if omq_port == 0 {
                    return Err(ServiceNodeError::InvalidPort("omq port is 0".into()));
                }

                // Version (3 bytes, one byte each)
                let version = [
                    chunk[offset] as u16,
                    chunk[offset + 1] as u16,
                    chunk[offset + 2] as u16,
                ];

                Ok(ServiceNode {
                    ed25519_pubkey,
                    ip,
                    https_port,
                    omq_port,
                    storage_server_version: version,
                    swarm_id,
                    requested_unlock_height: 0,
                })
            })();

            match result {
                Ok(node) => nodes.push(node),
                Err(_) => failed += 1,
            }
        }

        Ok((nodes, failed))
    }
}

impl fmt::Display for ServiceNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ed25519_pubkey.hex())
    }
}

impl fmt::Debug for ServiceNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceNode")
            .field("pubkey", &self.ed25519_pubkey.hex())
            .field("ip", &self.host())
            .field("https_port", &self.https_port)
            .field("omq_port", &self.omq_port)
            .field(
                "version",
                &format!(
                    "{}.{}.{}",
                    self.storage_server_version[0],
                    self.storage_server_version[1],
                    self.storage_server_version[2]
                ),
            )
            .field("swarm_id", &self.swarm_id)
            .finish()
    }
}

fn parse_ip(s: &str) -> Result<[u8; 4], ServiceNodeError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(ServiceNodeError::InvalidIp(s.to_string()));
    }
    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part
            .parse()
            .map_err(|_| ServiceNodeError::InvalidIp(s.to_string()))?;
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_node() -> ServiceNode {
        ServiceNode {
            ed25519_pubkey: Ed25519Pubkey::from_hex(
                "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
            )
            .unwrap(),
            ip: [95, 216, 33, 113],
            https_port: 22100,
            omq_port: 20200,
            storage_server_version: [2, 11, 0],
            swarm_id: INVALID_SWARM_ID,
            requested_unlock_height: 0,
        }
    }

    #[test]
    fn test_host() {
        let node = make_test_node();
        assert_eq!(node.host(), "95.216.33.113");
    }

    #[test]
    fn test_to_https_string() {
        let node = make_test_node();
        assert_eq!(node.to_https_string(), "95.216.33.113:22100");
    }

    #[test]
    fn test_disk_roundtrip() {
        let node = make_test_node();
        let disk = node.to_disk();
        let parsed = ServiceNode::from_disk(&disk).unwrap();
        assert_eq!(node.ed25519_pubkey, parsed.ed25519_pubkey);
        assert_eq!(node.ip, parsed.ip);
        assert_eq!(node.https_port, parsed.https_port);
        assert_eq!(node.omq_port, parsed.omq_port);
        assert_eq!(node.storage_server_version, parsed.storage_server_version);
    }

    #[test]
    fn test_from_disk_valid() {
        let line = "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef|95.216.33.113|22100|20200|2.11.0|18446744073709551615\n";
        let node = ServiceNode::from_disk(line).unwrap();
        assert_eq!(
            node.ed25519_pubkey.hex(),
            "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"
        );
        assert_eq!(node.ip, [95, 216, 33, 113]);
        assert_eq!(node.https_port, 22100);
        assert_eq!(node.omq_port, 20200);
        assert_eq!(node.storage_server_version, [2, 11, 0]);
    }

    #[test]
    fn test_from_disk_invalid_field_count() {
        assert!(ServiceNode::from_disk("a|b|c").is_err());
    }

    #[test]
    fn test_from_disk_invalid_version() {
        let line = "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef|1.2.3.4|443|22000|0.0.0|0";
        assert!(ServiceNode::from_disk(line).is_err());
    }

    #[test]
    fn test_display() {
        let node = make_test_node();
        let s = format!("{}", node);
        assert_eq!(
            s,
            "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef"
        );
    }

    #[test]
    fn test_from_json() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
                "pubkey_ed25519": "1f000f09a7b07828dcb72af7cd16857050c10c02bd58afb0e38111fb6cda1fef",
                "public_ip": "95.216.33.113",
                "storage_https_port": 22100,
                "storage_lmq_port": 20200,
                "storage_server_version": [2, 11, 0],
                "swarm_id": 12345
            }"#,
        )
        .unwrap();

        let node = ServiceNode::from_json(&json).unwrap();
        assert_eq!(node.https_port, 22100);
        assert_eq!(node.omq_port, 20200);
        assert_eq!(node.swarm_id, 12345);
        assert_eq!(node.storage_server_version, [2, 11, 0]);
    }
}
