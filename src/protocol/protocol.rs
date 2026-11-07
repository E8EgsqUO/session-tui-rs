//! Session protocol constants, Pro proof types, and protocol URL strings.
//!
//! Ported from `libsession-util/include/session/session_protocol.h`,
//! `libsession-util/include/session/session_protocol.hpp`, and
//! `libsession-util/src/session_protocol.cpp`.

use thiserror::Error;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of unicode codepoints that a standard message can use. If the
/// message exceeds this then the message must activate the higher character limit
/// feature provided by Session Pro which allows messages up to 10k characters.
pub const PRO_STANDARD_CHARACTER_LIMIT: usize = 2000;

/// Maximum number of unicode codepoints that a Session Pro entitled user can
/// send in a message.
pub const PRO_HIGHER_CHARACTER_LIMIT: usize = 10000;

/// Amount of conversations that a user without Session Pro can pin.
pub const PRO_STANDARD_PINNED_CONVERSATION_LIMIT: usize = 5;

/// Amount of bytes that a community or 1o1 message `Content` must be padded by
/// before wrapping in an envelope.
pub const COMMUNITY_OR_1O1_MSG_PADDING: usize = 160;

/// Padding terminating byte used when padding messages.
pub const PADDING_TERMINATING_BYTE: u8 = 0x80;

// ---------------------------------------------------------------------------
// Blake2b personalisation strings (must be exactly 16 bytes)
// ---------------------------------------------------------------------------

/// BLAKE2b personalisation for generating Session Pro proofs.
pub const GENERATE_PROOF_HASH_PERSONALISATION: &str = "ProGenerateProof";
/// BLAKE2b personalisation for building Session Pro proofs.
pub const BUILD_PROOF_HASH_PERSONALISATION: &str = "ProProof________";
/// BLAKE2b personalisation for adding Session Pro payment records.
pub const ADD_PRO_PAYMENT_HASH_PERSONALISATION: &str = "ProAddPayment___";
/// BLAKE2b personalisation for requesting Session Pro payment refunds.
pub const SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION: &str = "ProSetRefundReq_";
/// BLAKE2b personalisation for fetching Session Pro details.
pub const GET_PRO_DETAILS_HASH_PERSONALISATION: &str = "ProGetProDetReq_";

/// Internal Blake2b personalisation for the Session Pro backend proof hashing.
pub const PRO_BACKEND_BLAKE2B_PERSONALISATION: &str = "SeshProBackend__";

// ---------------------------------------------------------------------------
// Protocol URL strings
// ---------------------------------------------------------------------------

/// Bundle of hard-coded strings that an implementing application may use.
pub struct ProtocolStrings {
    pub build_variant_apk: &'static str,
    pub build_variant_fdroid: &'static str,
    pub build_variant_huawei: &'static str,
    pub build_variant_ipa: &'static str,
    pub url_donations: &'static str,
    pub url_donations_app: &'static str,
    pub url_download: &'static str,
    pub url_faq: &'static str,
    pub url_feedback: &'static str,
    pub url_network: &'static str,
    pub url_privacy_policy: &'static str,
    pub url_pro_access_not_found: &'static str,
    pub url_pro_faq: &'static str,
    pub url_pro_page: &'static str,
    pub url_pro_privacy_policy: &'static str,
    pub url_pro_roadmap: &'static str,
    pub url_pro_support: &'static str,
    pub url_pro_terms_of_service: &'static str,
    pub url_pro_upgrade: &'static str,
    pub url_staking: &'static str,
    pub url_support: &'static str,
    pub url_survey: &'static str,
    pub url_terms_of_service: &'static str,
    pub url_token: &'static str,
    pub url_translate: &'static str,
}

/// Global protocol strings matching the C++ `SESSION_PROTOCOL_STRINGS` constant.
pub static PROTOCOL_STRINGS: ProtocolStrings = ProtocolStrings {
    build_variant_apk: "APK",
    build_variant_fdroid: "F-Droid Store",
    build_variant_huawei: "Huawei App Gallery",
    build_variant_ipa: "IPA",
    url_donations: "https://getsession.org/donate",
    url_donations_app: "https://getsession.org/donate#app",
    url_download: "https://getsession.org/download",
    url_faq: "https://getsession.org/faq",
    url_feedback: "https://getsession.org/feedback",
    url_network: "https://docs.getsession.org/session-network",
    url_privacy_policy: "https://getsession.org/privacy-policy",
    url_pro_access_not_found:
        "https://sessionapp.zendesk.com/hc/sections/4416517450649-Support",
    url_pro_faq: "https://getsession.org/pro#faq",
    url_pro_page: "https://getsession.org/pro",
    url_pro_privacy_policy: "https://getsession.org/pro-privacy",
    url_pro_roadmap: "https://getsession.org/pro#roadmap",
    url_pro_support: "https://getsession.org/pro-support",
    url_pro_terms_of_service: "https://getsession.org/pro-terms",
    url_pro_upgrade: "https://getsession.org/pro#upgrade",
    url_staking: "https://docs.getsession.org/session-network/staking",
    url_support: "https://getsession.org/support",
    url_survey: "https://getsession.org/survey",
    url_terms_of_service: "https://getsession.org/terms-of-service",
    url_token: "https://token.getsession.org",
    url_translate: "https://getsession.org/translate",
};

// ---------------------------------------------------------------------------
// ProStatus
// ---------------------------------------------------------------------------

/// Status result from evaluating a Session Pro proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProStatus {
    /// Pro proof signature was not signed by the Pro backend key.
    InvalidProBackendSig = 1,
    /// Pro signature in the envelope was not signed by the rotating key.
    InvalidUserSig = 2,
    /// Proof is verified and has not expired.
    Valid = 3,
    /// Proof is verified but has expired.
    Expired = 4,
}

// ---------------------------------------------------------------------------
// ProProofVersion
// ---------------------------------------------------------------------------

/// Version tag for Pro proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProProofVersion {
    V0 = 0,
}

// ---------------------------------------------------------------------------
// ProProof
// ---------------------------------------------------------------------------

/// A Session Pro proof containing the fields needed to verify that a user is
/// entitled to Session Pro features.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProProof {
    /// Version of the proof set by the Session Pro Backend.
    pub version: u8,

    /// Hash of the generation index set by the Session Pro Backend.
    pub gen_index_hash: [u8; 32],

    /// The public key that the Session client registers their Session Pro
    /// entitlement under. Session clients must sign messages with this key
    /// alongside the sending of this proof for the network to authenticate
    /// their usage of the proof.
    pub rotating_pubkey: [u8; 32],

    /// Unix epoch timestamp (milliseconds) to which this proof's entitlement
    /// to Session Pro features is valid.
    pub expiry_unix_ts_ms: u64,

    /// Signature over the contents of the proof, signed by the Session Pro
    /// Backend key.
    pub sig: [u8; 64],
}

/// Errors that can occur during proof operations.
#[derive(Debug, Error)]
pub enum ProProofError {
    #[error("Invalid verify_pubkey: must be 32 byte Ed25519 public key (was: {0})")]
    InvalidPubkeySize(usize),

    #[error("Invalid signature: must be 64 bytes (was: {0})")]
    InvalidSignatureSize(usize),

    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::types::CryptoError),
}

impl ProProof {
    /// Create a 32-byte Blake2b hash from the proof. This hash is the payload
    /// that is signed in the proof.
    ///
    /// Matches the C++ `ProProof::hash()` and the backend hashing at:
    /// <https://github.com/Doy-lee/session-pro-backend/blob/9417e00adbff3bf608b7ae831f87045bdab06232/backend.py#L545-L558>
    pub fn hash(&self) -> [u8; 32] {
        proof_hash_internal(
            self.version,
            &self.gen_index_hash,
            &self.rotating_pubkey,
            self.expiry_unix_ts_ms,
        )
    }

    /// Verify that the proof's contents was not tampered with by hashing the
    /// proof and checking that the hash was signed by the secret key of the
    /// given Ed25519 public key.
    ///
    /// For Session Pro, we expect proofs to be signed by the Session Pro
    /// Backend public key.
    pub fn verify_signature(&self, verify_pubkey: &[u8]) -> Result<bool, ProProofError> {
        if verify_pubkey.len() != 32 {
            return Err(ProProofError::InvalidPubkeySize(verify_pubkey.len()));
        }
        let hash_to_sign = self.hash();
        let result = crate::crypto::ed25519::verify(&self.sig, verify_pubkey, &hash_to_sign)?;
        Ok(result)
    }

    /// Check if the `rotating_pubkey` in the proof was the signatory of the
    /// given message and signature.
    pub fn verify_message(&self, sig: &[u8], msg: &[u8]) -> Result<bool, ProProofError> {
        if sig.len() != 64 {
            return Err(ProProofError::InvalidSignatureSize(sig.len()));
        }
        let result = crate::crypto::ed25519::verify(sig, &self.rotating_pubkey, msg)?;
        Ok(result)
    }

    /// Check if the Pro proof is currently entitled to Pro given the
    /// `unix_ts_ms` with respect to the proof's `expiry_unix_ts_ms`.
    pub fn is_active(&self, unix_ts_ms: u64) -> bool {
        unix_ts_ms <= self.expiry_unix_ts_ms
    }

    /// Evaluate the status of the pro proof by checking it is signed by the
    /// `verify_pubkey`, it has not expired via `unix_ts_ms`, and optionally
    /// verify that the `signed_msg` was signed by the `rotating_pubkey`.
    ///
    /// Returns an error only if the key/signature sizes are wrong. Otherwise
    /// returns a [`ProStatus`] indicating validity.
    pub fn status(
        &self,
        verify_pubkey: &[u8],
        unix_ts_ms: u64,
        signed_msg: Option<ProSignedMessage<'_>>,
    ) -> Result<ProStatus, ProProofError> {
        // Verify the proof is signed by the Session Pro Backend key
        if !self.verify_signature(verify_pubkey)? {
            return Ok(ProStatus::InvalidProBackendSig);
        }

        // Check if the message was signed by the rotating key
        if let Some(sm) = signed_msg
            && !self.verify_message(sm.sig, sm.msg)? {
                return Ok(ProStatus::InvalidUserSig);
            }

        // Check if the proof has expired
        if !self.is_active(unix_ts_ms) {
            return Ok(ProStatus::Expired);
        }

        Ok(ProStatus::Valid)
    }
}

/// A signed message to verify against the rotating key in a proof.
#[derive(Debug, Clone, Copy)]
pub struct ProSignedMessage<'a> {
    pub sig: &'a [u8],
    pub msg: &'a [u8],
}

// ---------------------------------------------------------------------------
// ProProfileFeatures (bitset)
// ---------------------------------------------------------------------------

/// Profile feature flags. Each variant represents a bit position in the bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ProProfileFeature {
    ProBadge = 0,
    AnimatedAvatar = 1,
}

/// Number of defined profile features.
pub const PRO_PROFILE_FEATURES_COUNT: usize = 2;

/// A bitset for Session Pro profile features.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProProfileBitset {
    pub data: u64,
}

impl ProProfileBitset {
    /// Set a feature flag.
    pub fn set(&mut self, feature: ProProfileFeature) {
        self.data |= 1u64 << (feature as u64);
    }

    /// Unset a feature flag.
    pub fn unset(&mut self, feature: ProProfileFeature) {
        self.data &= !(1u64 << (feature as u64));
    }

    /// Check if a feature flag is set.
    pub fn is_set(&self, feature: ProProfileFeature) -> bool {
        (self.data & (1u64 << (feature as u64))) != 0
    }
}

// ---------------------------------------------------------------------------
// ProMessageFeatures (bitset)
// ---------------------------------------------------------------------------

/// Message feature flags. Each variant represents a bit position in the bitset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum ProMessageFeature {
    /// Message uses the 10k character limit.
    CharacterLimit10K = 0,
}

/// A bitset for Session Pro message features.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProMessageBitset {
    pub data: u64,
}

impl ProMessageBitset {
    /// Set a feature flag.
    pub fn set(&mut self, feature: ProMessageFeature) {
        self.data |= 1u64 << (feature as u64);
    }

    /// Unset a feature flag.
    pub fn unset(&mut self, feature: ProMessageFeature) {
        self.data &= !(1u64 << (feature as u64));
    }

    /// Check if a feature flag is set.
    pub fn is_set(&self, feature: ProMessageFeature) -> bool {
        (self.data & (1u64 << (feature as u64))) != 0
    }
}

// ---------------------------------------------------------------------------
// ProFeaturesForMsg
// ---------------------------------------------------------------------------

/// Status from evaluating a message for Pro features.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProFeaturesForMsgStatus {
    Success = 0,
    /// Message byte stream could not be decoded into valid UTF-8.
    UtfDecodingError = 1,
    /// Decoded string exceeded the maximum character limit allowed for Session Pro.
    ExceedsCharacterLimit = 2,
}

/// Result of evaluating a message for Session Pro features.
#[derive(Debug, Clone)]
pub struct ProFeaturesForMsg {
    pub status: ProFeaturesForMsgStatus,
    pub error: Option<String>,
    pub bitset: ProMessageBitset,
    pub codepoint_count: usize,
}

/// Determine the Pro features used in a given UTF-8 conversation message.
///
/// Counts the number of unicode codepoints and determines if the message
/// requires the higher character limit available in Session Pro.
pub fn pro_features_for_utf8(text: &str) -> ProFeaturesForMsg {
    let codepoint_count = text.chars().count();

    if codepoint_count > PRO_HIGHER_CHARACTER_LIMIT {
        return ProFeaturesForMsg {
            status: ProFeaturesForMsgStatus::ExceedsCharacterLimit,
            error: Some("Message exceeds the maximum character limit allowed".into()),
            bitset: ProMessageBitset::default(),
            codepoint_count,
        };
    }

    let mut bitset = ProMessageBitset::default();
    if codepoint_count > PRO_STANDARD_CHARACTER_LIMIT {
        bitset.set(ProMessageFeature::CharacterLimit10K);
    }

    ProFeaturesForMsg {
        status: ProFeaturesForMsgStatus::Success,
        error: None,
        bitset,
        codepoint_count,
    }
}

// ---------------------------------------------------------------------------
// DestinationType
// ---------------------------------------------------------------------------

/// The type of destination for an encoded message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DestinationType {
    SyncOr1o1 = 0,
    /// Both legacy and non-legacy groups. A non-legacy group is detected by
    /// the (0x03) prefix byte on the given `dest_group_pubkey`.
    Group = 1,
    CommunityInbox = 2,
    Community = 3,
}

// ---------------------------------------------------------------------------
// Envelope flags
// ---------------------------------------------------------------------------

/// Bitflags indicating which optional fields in an envelope have been populated.
pub mod envelope_flags {
    /// Envelope includes the source Session ID.
    pub const SOURCE: u32 = 1 << 0;
    /// Envelope includes the source device identifier.
    pub const SOURCE_DEVICE: u32 = 1 << 1;
    /// Envelope includes the server-assigned timestamp.
    pub const SERVER_TIMESTAMP: u32 = 1 << 2;
    /// Envelope includes a Session Pro signature.
    pub const PRO_SIG: u32 = 1 << 3;
    /// Envelope includes the client-assigned timestamp.
    pub const TIMESTAMP: u32 = 1 << 4;
}

// ---------------------------------------------------------------------------
// Message padding
// ---------------------------------------------------------------------------

/// Pad a message to the required alignment for 1o1/community messages (160 bytes)
/// including space for the padding-terminating byte.
pub fn pad_message(payload: &[u8]) -> Vec<u8> {
    let padded_content_size = payload.len() + 1; // +1 for the padding terminating byte
    let bytes_for_padding =
        COMMUNITY_OR_1O1_MSG_PADDING - (padded_content_size % COMMUNITY_OR_1O1_MSG_PADDING);
    let total_size = padded_content_size + bytes_for_padding;
    debug_assert!(total_size.is_multiple_of(COMMUNITY_OR_1O1_MSG_PADDING));

    let mut result = vec![0u8; total_size];
    result[..payload.len()].copy_from_slice(payload);
    result[payload.len()] = PADDING_TERMINATING_BYTE;
    result
}

/// Strip padding from a padded message, returning the unpadded content.
pub fn unpad_message(payload: &[u8]) -> &[u8] {
    let mut size = payload.len();
    while size > 0 {
        let ch = payload[size - 1];
        if ch != 0 && ch != PADDING_TERMINATING_BYTE {
            // Non-zero/non-padding byte: message is not padded (or padding already stripped)
            return payload;
        }
        size -= 1;
        if ch == PADDING_TERMINATING_BYTE {
            break;
        }
    }
    &payload[..size]
}

// ---------------------------------------------------------------------------
// Internal: proof hash
// ---------------------------------------------------------------------------

/// Compute the 32-byte Blake2b hash of a proof's fields using the
/// `ProProof________` personalisation. This matches the C++ `proof_hash_internal`.
fn proof_hash_internal(
    version: u8,
    gen_index_hash: &[u8; 32],
    rotating_pubkey: &[u8; 32],
    expiry_unix_ts_ms: u64,
) -> [u8; 32] {
    use blake2b_simd::Params;

    let mut params = Params::new();
    params.hash_length(32);

    // The personalisation must be exactly 16 bytes for Blake2b
    debug_assert!(BUILD_PROOF_HASH_PERSONALISATION.len() == 16);
    let mut personal = [0u8; 16];
    personal.copy_from_slice(BUILD_PROOF_HASH_PERSONALISATION.as_bytes());
    params.personal(&personal);

    let mut state = params.to_state();
    state.update(&[version]);
    state.update(gen_index_hash);
    state.update(rotating_pubkey);
    state.update(&expiry_unix_ts_ms.to_le_bytes());

    let hash = state.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

/// Initialise a Blake2b-32 hashing context with the given personalisation string.
/// The personalisation must be exactly 16 bytes.
pub fn make_blake2b32_hasher(personalisation: &str) -> blake2b_simd::State {
    debug_assert!(personalisation.len() == 16);
    let mut personal = [0u8; 16];
    let len = personalisation.len().min(16);
    personal[..len].copy_from_slice(&personalisation.as_bytes()[..len]);

    let mut params = blake2b_simd::Params::new();
    params.hash_length(32);
    params.personal(&personal);
    params.to_state()
}

// ---------------------------------------------------------------------------
// Group message size limits (from protocol constants used in groups)
// ---------------------------------------------------------------------------

/// Maximum size of a group message content before encryption.
/// Groups v2 messages are encrypted with 256-byte padding alignment.
pub const GROUP_MESSAGE_PADDING: usize = 256;

/// Session ID prefix byte for standard 1:1 accounts (`05`).
pub const SESSION_ID_PREFIX_STANDARD: u8 = 0x05;
/// Session ID prefix byte for v2 groups (`03`).
pub const SESSION_ID_PREFIX_GROUP: u8 = 0x03;

// ---------------------------------------------------------------------------
// UTF-16 pro features
// ---------------------------------------------------------------------------

/// Determine the Pro features used in a given UTF-16 conversation message.
///
/// Counts the number of unicode codepoints and determines if the message
/// requires the higher character limit available in Session Pro.
///
/// Matches the C++ `pro_features_for_utf16()` in `session_protocol.cpp`.
pub fn pro_features_for_utf16(utf16: &[u16]) -> ProFeaturesForMsg {
    // Decode the UTF-16 sequence and count codepoints. Invalid sequences
    // produce `REPLACEMENT_CHARACTER`, matching simdutf's "count" behavior.
    let decoded: Result<String, _> = char::decode_utf16(utf16.iter().copied())
        .map(|r| r.map(|c| c.to_string()))
        .collect::<Result<Vec<_>, _>>()
        .map(|v| v.concat());

    let (codepoint_count, decode_err) = match decoded {
        Ok(s) => (s.chars().count(), None),
        Err(e) => (0usize, Some(e.to_string())),
    };

    if let Some(err) = decode_err {
        return ProFeaturesForMsg {
            status: ProFeaturesForMsgStatus::UtfDecodingError,
            error: Some(err),
            bitset: ProMessageBitset::default(),
            codepoint_count: 0,
        };
    }

    if codepoint_count > PRO_HIGHER_CHARACTER_LIMIT {
        return ProFeaturesForMsg {
            status: ProFeaturesForMsgStatus::ExceedsCharacterLimit,
            error: Some("Message exceeds the maximum character limit allowed".into()),
            bitset: ProMessageBitset::default(),
            codepoint_count,
        };
    }

    let mut bitset = ProMessageBitset::default();
    if codepoint_count > PRO_STANDARD_CHARACTER_LIMIT {
        bitset.set(ProMessageFeature::CharacterLimit10K);
    }

    ProFeaturesForMsg {
        status: ProFeaturesForMsgStatus::Success,
        error: None,
        bitset,
        codepoint_count,
    }
}

// ---------------------------------------------------------------------------
// Destination
// ---------------------------------------------------------------------------

/// Configuration for `encode_for_destination`, specifying where a message is
/// going and providing the keys needed to encrypt for that destination.
///
/// Mirrors the C++ `session::Destination` struct.
#[derive(Debug, Clone)]
pub struct Destination {
    /// Type of destination.
    pub dest_type: Option<DestinationType>,

    /// Optional rotating Session Pro Ed25519 private key to sign the message
    /// with on behalf of the caller. Empty to opt out of Pro entitlement.
    /// Accepts a 32-byte seed or a 64-byte libsodium-style secret key.
    pub pro_rotating_ed25519_privkey: Vec<u8>,

    /// The timestamp to assign to the message envelope, in milliseconds.
    pub sent_timestamp_ms: u64,

    /// For `SyncOr1o1` / `CommunityInbox`: the recipient's Session public key
    /// (33 bytes, including 0x05 prefix).
    pub recipient_pubkey: [u8; 33],

    /// For `CommunityInbox`: the community inbox server's Ed25519 public key
    /// (32 bytes).
    pub community_inbox_server_pubkey: [u8; 32],

    /// For `Group`: the group public key (33 bytes, including 0x03 prefix).
    pub group_ed25519_pubkey: [u8; 33],

    /// For `Group`: the group's encryption key (32 or 64 bytes). Typically
    /// the latest key for the group.
    pub group_enc_key: Vec<u8>,
}

impl Default for Destination {
    fn default() -> Self {
        Self {
            dest_type: None,
            pro_rotating_ed25519_privkey: Vec::new(),
            sent_timestamp_ms: 0,
            recipient_pubkey: [0u8; 33],
            community_inbox_server_pubkey: [0u8; 32],
            group_ed25519_pubkey: [0u8; 33],
            group_enc_key: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Envelope / DecodedPro / DecodedEnvelope / DecodedCommunityMessage
// ---------------------------------------------------------------------------

/// A message envelope with metadata. Fields are only meaningful when the
/// corresponding bit in `flags` is set (see [`envelope_flags`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// Bitflags indicating which optional fields are populated.
    pub flags: u32,
    /// Client-assigned timestamp (milliseconds).
    pub timestamp: u64,
    /// Sender Session ID (33 bytes, including 0x05 prefix).
    pub source: [u8; 33],
    /// Sender device identifier.
    pub source_device: u32,
    /// Server-assigned timestamp.
    pub server_timestamp: u64,
    /// Signature by the sending client's rotating key.
    pub pro_sig: [u8; 64],
}

impl Default for Envelope {
    fn default() -> Self {
        Self {
            flags: 0,
            timestamp: 0,
            source: [0u8; 33],
            source_device: 0,
            server_timestamp: 0,
            pro_sig: [0u8; 64],
        }
    }
}

/// Pro proof data extracted from a decoded envelope.
#[derive(Debug, Clone)]
pub struct DecodedPro {
    /// Validity of the proof embedded in the envelope.
    pub status: ProStatus,
    /// Session Pro proof that was embedded. Always populated; check `status`
    /// before trusting its contents.
    pub proof: ProProof,
    /// Message feature bitset attached to this message.
    pub msg_bitset: ProMessageBitset,
    /// Profile feature bitset attached to this message.
    pub profile_bitset: ProProfileBitset,
}

/// Result of `decode_envelope`: a parsed envelope with its decrypted content
/// and sender information.
#[derive(Debug, Clone)]
pub struct DecodedEnvelope {
    /// The envelope parsed from the payload.
    pub envelope: Envelope,
    /// Decrypted content with padding stripped (ready to parse as protobuf
    /// `Content`).
    pub content_plaintext: Vec<u8>,
    /// Sender's Ed25519 public key extracted from the encrypted content.
    /// Zero for groups v2 envelopes (only x25519 is known in that case).
    pub sender_ed25519_pubkey: [u8; 32],
    /// Sender's X25519 public key (always populated on success).
    pub sender_x25519_pubkey: [u8; 32],
    /// Set if the envelope included Pro metadata.
    pub pro: Option<DecodedPro>,
}

/// Result of `decode_for_community`.
#[derive(Debug, Clone)]
pub struct DecodedCommunityMessage {
    /// Envelope if the payload was originally an envelope blob.
    pub envelope: Option<Envelope>,
    /// Protobuf-encoded `Content` bytes with padding stripped.
    pub content_plaintext: Vec<u8>,
    /// Pro signature if one was present in the payload.
    pub pro_sig: Option<[u8; 64]>,
    /// Set if the payload included Pro metadata.
    pub pro: Option<DecodedPro>,
}

/// Keys for decrypting an envelope.
///
/// Either provide `group_ed25519_pubkey` for encrypted groups v2 envelopes,
/// or `decrypt_keys` for unencrypted envelopes whose content is encrypted
/// (1:1 / legacy groups).
#[derive(Debug, Clone, Default)]
pub struct DecodeEnvelopeKey<'a> {
    /// For groups v2: the group public key.
    pub group_ed25519_pubkey: Option<&'a [u8]>,
    /// For 1:1 / legacy groups: one or more Ed25519 secret keys to attempt
    /// decryption with. Accepts 32-byte seeds or 64-byte libsodium secret keys.
    pub decrypt_keys: &'a [&'a [u8]],
}

// ---------------------------------------------------------------------------
// Encode/decode errors
// ---------------------------------------------------------------------------

/// Errors that can occur during high-level envelope encode/decode.
#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("Missing destination type")]
    MissingDestinationType,
    #[error("Invalid recipient pubkey: expected 33 bytes (0x05 prefix)")]
    InvalidRecipientPubkey,
    #[error("Invalid group pubkey: expected 33 bytes (0x03 prefix)")]
    InvalidGroupPubkey,
    #[error("Invalid group encryption key: expected 32 or 64 bytes")]
    InvalidGroupEncKey,
    #[error("Encrypting for a legacy group (0x05 prefix) is not supported")]
    LegacyGroupUnsupported,
    #[error("Invalid Session Pro rotating ed25519 privkey: expected 32 or 64 bytes")]
    InvalidProKeySize,
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::crypto::types::CryptoError),
    #[error("Ed25519 error: {0}")]
    Ed25519(String),
    #[error("Protobuf encode error: {0}")]
    ProtobufEncode(String),
    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(String),
    #[error("Decryption failed after trying {0} key(s)")]
    DecryptionFailed(usize),
    #[error("Envelope missing required content field")]
    MissingContent,
    #[error("Malformed envelope: {0}")]
    MalformedEnvelope(String),
    #[error("Malformed content: {0}")]
    MalformedContent(String),
    #[error("Malformed Pro proof: {0}")]
    MalformedProProof(String),
}

// ---------------------------------------------------------------------------
// Helpers for encoding/decoding
// ---------------------------------------------------------------------------

/// Normalise an Ed25519 private key to a 64-byte libsodium-style secret key.
/// Accepts a 32-byte seed or a 64-byte secret key.
fn expand_ed25519_sk(key: &[u8]) -> Result<[u8; 64], EnvelopeError> {
    match key.len() {
        32 => {
            let (_, sk) = crate::crypto::ed25519::ed25519_key_pair_from_seed(key)?;
            Ok(sk)
        }
        64 => {
            let mut out = [0u8; 64];
            out.copy_from_slice(key);
            Ok(out)
        }
        _ => Err(EnvelopeError::InvalidProKeySize),
    }
}

/// Sign a detached Ed25519 signature using a 64-byte libsodium-style key.
fn detached_sign(sk_64: &[u8; 64], msg: &[u8]) -> Result<[u8; 64], EnvelopeError> {
    use ed25519_dalek::{Signer, SigningKey};
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&sk_64[..32]);
    let signing_key = SigningKey::from_bytes(&seed);
    let sig = signing_key.sign(msg);
    Ok(sig.to_bytes())
}

/// Generate a throw-away Ed25519 signature over `msg`. Used to fill the
/// envelope's `pro_sig` when the sender is not using Session Pro — this makes
/// Pro and non-Pro messages indistinguishable on the wire.
fn throwaway_sign(msg: &[u8]) -> [u8; 64] {
    use ed25519_dalek::{Signer, SigningKey};
    use rand::RngExt;
    let seed: [u8; 32] = rand::rng().random();
    let sk = SigningKey::from_bytes(&seed);
    sk.sign(msg).to_bytes()
}

// ---------------------------------------------------------------------------
// encode_for_destination
// ---------------------------------------------------------------------------

/// Low-level: encode a plaintext `Content` message for a destination.
///
/// Builds the envelope/websocket wrapping and encryption appropriate for
/// `dest.dest_type`. This is the foundation used by the higher-level helpers
/// (`encode_for_1o1`, `encode_for_group`, `encode_for_community`,
/// `encode_for_community_inbox`).
///
/// Port of C++ `encode_for_destination()` in `session_protocol.cpp`.
pub fn encode_for_destination(
    plaintext: &[u8],
    ed25519_privkey: &[u8],
    dest: &Destination,
) -> Result<Vec<u8>, EnvelopeError> {
    use prost::Message as _;
    use crate::proto::session_protos::{envelope, Content, Envelope as PbEnvelope};
    use crate::proto::web_socket_protos::{
        web_socket_message, WebSocketMessage as PbWsMsg, WebSocketRequestMessage as PbWsReq,
    };

    let dest_type = dest
        .dest_type
        .ok_or(EnvelopeError::MissingDestinationType)?;

    // Normalise the pro rotating key if provided.
    let pro_rotating_sk: Option<[u8; 64]> = if !dest.pro_rotating_ed25519_privkey.is_empty() {
        Some(expand_ed25519_sk(&dest.pro_rotating_ed25519_privkey)?)
    } else {
        None
    };

    match dest_type {
        DestinationType::SyncOr1o1 | DestinationType::Group => {
            let is_group = matches!(dest_type, DestinationType::Group);
            let is_1o1 = !is_group;

            // Validate keys
            if is_1o1 && dest.recipient_pubkey[0] != SESSION_ID_PREFIX_STANDARD {
                return Err(EnvelopeError::InvalidRecipientPubkey);
            }
            if is_group {
                if dest.group_ed25519_pubkey[0] == SESSION_ID_PREFIX_STANDARD {
                    return Err(EnvelopeError::LegacyGroupUnsupported);
                }
                if dest.group_ed25519_pubkey[0] != SESSION_ID_PREFIX_GROUP {
                    return Err(EnvelopeError::InvalidGroupPubkey);
                }
                if dest.group_enc_key.len() != 32 && dest.group_enc_key.len() != 64 {
                    return Err(EnvelopeError::InvalidGroupEncKey);
                }
            }

            // For 1:1, pad and encrypt the content before wrapping in the envelope.
            // For group, the envelope is encrypted wholesale below.
            let envelope_content: Vec<u8> = if is_1o1 {
                let padded = pad_message(plaintext);
                crate::crypto::session_encrypt::encrypt_for_recipient(
                    ed25519_privkey,
                    &dest.recipient_pubkey,
                    &padded,
                )?
            } else {
                plaintext.to_vec()
            };

            // Pro signature: sign the envelope content with the rotating key if
            // given; otherwise use a throw-away signature so pro/non-pro
            // messages are indistinguishable on the wire.
            let pro_sig = match pro_rotating_sk {
                Some(sk) => detached_sign(&sk, &envelope_content)?,
                None => throwaway_sign(&envelope_content),
            };

            // Build the Envelope protobuf.
            let pb_envelope = PbEnvelope {
                r#type: if is_1o1 {
                    envelope::Type::SessionMessage as i32
                } else {
                    envelope::Type::ClosedGroupMessage as i32
                },
                source: None,
                source_device: Some(1),
                timestamp: dest.sent_timestamp_ms,
                content: Some(envelope_content),
                server_timestamp: None,
                pro_sig: Some(pro_sig.to_vec()),
            };

            let envelope_bytes = pb_envelope.encode_to_vec();

            if is_group {
                // Encrypt the whole envelope using the group key.
                let group_pubkey_32 = &dest.group_ed25519_pubkey[1..];
                let ciphertext = crate::crypto::session_encrypt::encrypt_for_group(
                    ed25519_privkey,
                    group_pubkey_32,
                    &dest.group_enc_key,
                    &envelope_bytes,
                    /* compress */ true,
                    /* padding */ 256,
                )?;
                Ok(ciphertext)
            } else {
                // 1:1 wraps the envelope in a WebSocket REQUEST.
                let ws_req = PbWsReq {
                    verb: Some(String::new()),
                    path: Some(String::new()),
                    body: Some(envelope_bytes),
                    headers: Vec::new(),
                    request_id: Some(0),
                };
                let ws_msg = PbWsMsg {
                    r#type: Some(web_socket_message::Type::Request as i32),
                    request: Some(ws_req),
                    response: None,
                };
                Ok(ws_msg.encode_to_vec())
            }
        }

        DestinationType::Community | DestinationType::CommunityInbox => {
            let is_inbox = matches!(dest_type, DestinationType::CommunityInbox);

            let content_bytes: Vec<u8> = if let Some(sk) = pro_rotating_sk.as_ref() {
                // Parse the content, sign the padded content, embed the sig
                // in the content's community-only pro signature field, then
                // re-pad for transmission.
                let mut content = Content::decode(plaintext)
                    .map_err(|e| EnvelopeError::MalformedContent(e.to_string()))?;

                if content.pro_sig_for_community_message_only.is_some() {
                    return Err(EnvelopeError::MalformedContent(
                        "Pro signature for community message must not be pre-set".into(),
                    ));
                }

                let padded_once = pad_message(plaintext);
                let pro_sig = detached_sign(sk, &padded_once)?;

                content.pro_sig_for_community_message_only = Some(pro_sig.to_vec());
                let reserialised = content.encode_to_vec();
                pad_message(&reserialised)
            } else {
                pad_message(plaintext)
            };

            if is_inbox {
                // Community inbox: blinded encrypt to recipient.
                let ciphertext = crate::crypto::session_encrypt::encrypt_for_blinded_recipient(
                    ed25519_privkey,
                    &dest.community_inbox_server_pubkey,
                    &dest.recipient_pubkey,
                    &content_bytes,
                )?;
                Ok(ciphertext)
            } else {
                // Community posting: the padded content is sent unencrypted.
                Ok(content_bytes)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// encode_for_1o1 / group / community / community_inbox (high-level wrappers)
// ---------------------------------------------------------------------------

/// Encode a plaintext `Content` message for a 1:1 (or sync) conversation.
///
/// Wraps the plaintext in a `WebSocket(Envelope(encrypted(padded(Content))))`.
/// The result is ready to store on the recipient's swarm.
///
/// Port of C++ `encode_for_1o1()`.
pub fn encode_for_1o1(
    plaintext: &[u8],
    ed25519_privkey: &[u8],
    sent_timestamp_ms: u64,
    recipient_pubkey: &[u8; 33],
    pro_rotating_ed25519_privkey: Option<&[u8]>,
) -> Result<Vec<u8>, EnvelopeError> {
    let dest = Destination {
        dest_type: Some(DestinationType::SyncOr1o1),
        pro_rotating_ed25519_privkey: pro_rotating_ed25519_privkey
            .map(|s| s.to_vec())
            .unwrap_or_default(),
        sent_timestamp_ms,
        recipient_pubkey: *recipient_pubkey,
        ..Default::default()
    };
    encode_for_destination(plaintext, ed25519_privkey, &dest)
}

/// Encode a plaintext `Content` message for a community inbox.
///
/// Port of C++ `encode_for_community_inbox()`.
pub fn encode_for_community_inbox(
    plaintext: &[u8],
    ed25519_privkey: &[u8],
    sent_timestamp_ms: u64,
    recipient_pubkey: &[u8; 33],
    community_server_pubkey: &[u8; 32],
    pro_rotating_ed25519_privkey: Option<&[u8]>,
) -> Result<Vec<u8>, EnvelopeError> {
    let dest = Destination {
        dest_type: Some(DestinationType::CommunityInbox),
        pro_rotating_ed25519_privkey: pro_rotating_ed25519_privkey
            .map(|s| s.to_vec())
            .unwrap_or_default(),
        sent_timestamp_ms,
        recipient_pubkey: *recipient_pubkey,
        community_inbox_server_pubkey: *community_server_pubkey,
        ..Default::default()
    };
    encode_for_destination(plaintext, ed25519_privkey, &dest)
}

/// Encode a plaintext `Content` message for posting to a community.
///
/// If `pro_rotating_ed25519_privkey` is provided, the community-only Pro
/// signature is embedded in the content.
///
/// Port of C++ `encode_for_community()`.
pub fn encode_for_community(
    plaintext: &[u8],
    pro_rotating_ed25519_privkey: Option<&[u8]>,
) -> Result<Vec<u8>, EnvelopeError> {
    let dest = Destination {
        dest_type: Some(DestinationType::Community),
        pro_rotating_ed25519_privkey: pro_rotating_ed25519_privkey
            .map(|s| s.to_vec())
            .unwrap_or_default(),
        ..Default::default()
    };
    // `ed25519_privkey` is unused for plain Community (no encryption); pass empty.
    encode_for_destination(plaintext, &[], &dest)
}

/// Encode a plaintext `Content` message for a v2 group.
///
/// Only v2 groups (0x03 prefix) are supported. Passing a 0x05-prefixed
/// (legacy) group key returns `EnvelopeError::LegacyGroupUnsupported`.
///
/// Port of C++ `encode_for_group()`.
pub fn encode_for_group(
    plaintext: &[u8],
    ed25519_privkey: &[u8],
    sent_timestamp_ms: u64,
    group_ed25519_pubkey: &[u8; 33],
    group_enc_key: &[u8],
    pro_rotating_ed25519_privkey: Option<&[u8]>,
) -> Result<Vec<u8>, EnvelopeError> {
    let dest = Destination {
        dest_type: Some(DestinationType::Group),
        pro_rotating_ed25519_privkey: pro_rotating_ed25519_privkey
            .map(|s| s.to_vec())
            .unwrap_or_default(),
        sent_timestamp_ms,
        group_ed25519_pubkey: *group_ed25519_pubkey,
        group_enc_key: group_enc_key.to_vec(),
        ..Default::default()
    };
    encode_for_destination(plaintext, ed25519_privkey, &dest)
}

// ---------------------------------------------------------------------------
// decode_envelope
// ---------------------------------------------------------------------------

/// Decode (and decrypt if necessary) an incoming message envelope.
///
/// Handles both:
/// - 1:1 / legacy group messages: payload is a `WebSocketMessage` wrapping an
///   `Envelope` with encrypted content.
/// - Groups v2 messages: payload is an encrypted blob; use
///   `keys.group_ed25519_pubkey` and `keys.decrypt_keys` (group encryption
///   keys) to decrypt into a plaintext `Envelope`.
///
/// Port of C++ `decode_envelope()`.
pub fn decode_envelope(
    keys: &DecodeEnvelopeKey<'_>,
    envelope_payload: &[u8],
    pro_backend_pubkey: &[u8; 32],
) -> Result<DecodedEnvelope, EnvelopeError> {
    use prost::Message as _;
    use crate::proto::session_protos::{Content, Envelope as PbEnvelope};
    use crate::proto::web_socket_protos::WebSocketMessage as PbWsMsg;

    let mut result_envelope = Envelope::default();
    let mut sender_ed25519_pubkey = [0u8; 32];
    let mut sender_x25519_pubkey = [0u8; 32];
    let content_plaintext_vec: Vec<u8>;

    // Parse the envelope plaintext — either by decrypting a groups v2 blob, or
    // by unwrapping a WebSocketRequestMessage.
    let pb_envelope: PbEnvelope = if let Some(group_pubkey) = keys.group_ed25519_pubkey {
        let decrypt = crate::crypto::session_encrypt::decrypt_group_message(
            keys.decrypt_keys,
            group_pubkey,
            envelope_payload,
        )?;

        // Expected: "05" + 64 hex chars = 66 chars
        if decrypt.session_id.len() != 66 || !decrypt.session_id.starts_with("05") {
            return Err(EnvelopeError::MalformedEnvelope(format!(
                "Invalid sender session ID extracted from group envelope: {}",
                decrypt.session_id
            )));
        }

        let sender_x_bytes = hex::decode(&decrypt.session_id[2..]).map_err(|e| {
            EnvelopeError::MalformedEnvelope(format!("Invalid sender session ID hex: {e}"))
        })?;
        if sender_x_bytes.len() != 32 {
            return Err(EnvelopeError::MalformedEnvelope(
                "Sender x25519 pubkey has wrong length".into(),
            ));
        }
        sender_x25519_pubkey.copy_from_slice(&sender_x_bytes);

        PbEnvelope::decode(decrypt.data.as_slice())
            .map_err(|e| EnvelopeError::ProtobufDecode(e.to_string()))?
    } else {
        // 1:1 / legacy group — wrapped in a WebSocketMessage.
        let ws = PbWsMsg::decode(envelope_payload)
            .map_err(|e| EnvelopeError::ProtobufDecode(e.to_string()))?;
        let request = ws
            .request
            .ok_or_else(|| EnvelopeError::MalformedEnvelope("missing WS request".into()))?;
        let body = request
            .body
            .ok_or_else(|| EnvelopeError::MalformedEnvelope("missing WS request body".into()))?;

        PbEnvelope::decode(body.as_slice())
            .map_err(|e| EnvelopeError::ProtobufDecode(e.to_string()))?
    };

    // Timestamp
    result_envelope.timestamp = pb_envelope.timestamp;
    result_envelope.flags |= envelope_flags::TIMESTAMP;

    // Source (optional, accepts 0 or 64 hex chars for backwards compat)
    if let Some(source) = pb_envelope.source.as_ref() {
        if !source.is_empty() {
            if source.len() != 64 {
                return Err(EnvelopeError::MalformedEnvelope(format!(
                    "Envelope source has unexpected size: {}b",
                    source.len()
                )));
            }
            let src_bytes = hex::decode(source).map_err(|e| {
                EnvelopeError::MalformedEnvelope(format!("Invalid source hex: {e}"))
            })?;
            if src_bytes.len() == 32 {
                result_envelope.source[0] = SESSION_ID_PREFIX_STANDARD;
                result_envelope.source[1..].copy_from_slice(&src_bytes);
                result_envelope.flags |= envelope_flags::SOURCE;
            }
        }
    }

    if let Some(sd) = pb_envelope.source_device {
        result_envelope.source_device = sd;
        result_envelope.flags |= envelope_flags::SOURCE_DEVICE;
    }

    if let Some(st) = pb_envelope.server_timestamp {
        result_envelope.server_timestamp = st;
        result_envelope.flags |= envelope_flags::SERVER_TIMESTAMP;
    }

    // Content
    let content = pb_envelope
        .content
        .as_ref()
        .ok_or(EnvelopeError::MissingContent)?;

    if keys.group_ed25519_pubkey.is_some() {
        // Groups v2: envelope was encrypted, content is plaintext.
        content_plaintext_vec = content.clone();
    } else {
        // 1:1 / legacy: content is encrypted with recipient's ed25519 key.
        let mut success = false;
        let mut plaintext = Vec::new();
        let mut sender_pk = Vec::new();
        let mut last_err: Option<EnvelopeError> = None;
        for sk in keys.decrypt_keys {
            match crate::crypto::session_encrypt::decrypt_incoming(sk, content) {
                Ok((pt, spk)) => {
                    plaintext = pt;
                    sender_pk = spk;
                    success = true;
                    break;
                }
                Err(e) => last_err = Some(e.into()),
            }
        }
        if !success {
            return Err(last_err
                .unwrap_or(EnvelopeError::DecryptionFailed(keys.decrypt_keys.len())));
        }

        // Strip padding
        let unpadded = unpad_message(&plaintext);
        content_plaintext_vec = unpadded.to_vec();

        if sender_pk.len() != 32 {
            return Err(EnvelopeError::MalformedEnvelope(
                "sender ed25519 pubkey has wrong length".into(),
            ));
        }
        sender_ed25519_pubkey.copy_from_slice(&sender_pk);
        sender_x25519_pubkey =
            crate::crypto::curve25519::to_curve25519_pubkey(&sender_ed25519_pubkey)?;
    }

    // Parse the Content protobuf to extract Pro metadata (if present).
    let pb_content = Content::decode(content_plaintext_vec.as_slice())
        .map_err(|e| EnvelopeError::ProtobufDecode(e.to_string()))?;

    // Copy pro_sig if present (accept missing for backwards compat with older clients).
    let mut pro_out: Option<DecodedPro> = None;
    if let Some(ps) = pb_envelope.pro_sig.as_ref() {
        if ps.len() != 64 {
            return Err(EnvelopeError::MalformedEnvelope(
                "pro signature has wrong size".into(),
            ));
        }
        result_envelope.pro_sig.copy_from_slice(ps);

        if let Some(pro_msg) = pb_content.pro_message.as_ref() {
            let sig_timestamp = pb_content.sig_timestamp.ok_or_else(|| {
                EnvelopeError::MalformedContent(
                    "Content missing sigTimestamp; Pro proof expiry is unverifiable".into(),
                )
            })?;

            result_envelope.flags |= envelope_flags::PRO_SIG;

            let proto_proof = pro_msg
                .proof
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("pro_message missing proof".into()))?;

            let version = proto_proof
                .version
                .ok_or_else(|| EnvelopeError::MalformedProProof("proof missing version".into()))?;
            if version != ProProofVersion::V0 as u32 {
                return Err(EnvelopeError::MalformedProProof(format!(
                    "unexpected proof version {version}"
                )));
            }

            let gen_index_hash_bytes = proto_proof
                .gen_index_hash
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing genIndexHash".into()))?;
            if gen_index_hash_bytes.len() != 32 {
                return Err(EnvelopeError::MalformedProProof(
                    "genIndexHash wrong size".into(),
                ));
            }

            let rotating_pk_bytes = proto_proof
                .rotating_public_key
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing rotatingPublicKey".into()))?;
            if rotating_pk_bytes.len() != 32 {
                return Err(EnvelopeError::MalformedProProof(
                    "rotatingPublicKey wrong size".into(),
                ));
            }

            let expiry = proto_proof
                .expiry_unix_ts
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing expiryUnixTs".into()))?;

            let sig_bytes = proto_proof
                .sig
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing sig".into()))?;
            if sig_bytes.len() != 64 {
                return Err(EnvelopeError::MalformedProProof("sig wrong size".into()));
            }

            let mut proof = ProProof {
                version: version as u8,
                gen_index_hash: [0u8; 32],
                rotating_pubkey: [0u8; 32],
                expiry_unix_ts_ms: expiry,
                sig: [0u8; 64],
            };
            proof.gen_index_hash.copy_from_slice(gen_index_hash_bytes);
            proof.rotating_pubkey.copy_from_slice(rotating_pk_bytes);
            proof.sig.copy_from_slice(sig_bytes);

            let msg_bitset = ProMessageBitset {
                data: pro_msg.msg_bitset.unwrap_or(0),
            };
            let profile_bitset = ProProfileBitset {
                data: pro_msg.profile_bitset.unwrap_or(0),
            };

            let signed_msg = ProSignedMessage {
                sig: ps,
                msg: content,
            };
            let status = proof
                .status(pro_backend_pubkey, sig_timestamp, Some(signed_msg))
                .map_err(|e| EnvelopeError::Ed25519(e.to_string()))?;

            pro_out = Some(DecodedPro {
                status,
                proof,
                msg_bitset,
                profile_bitset,
            });
        }
    }

    Ok(DecodedEnvelope {
        envelope: result_envelope,
        content_plaintext: content_plaintext_vec,
        sender_ed25519_pubkey,
        sender_x25519_pubkey,
        pro: pro_out,
    })
}

// ---------------------------------------------------------------------------
// decode_for_community
// ---------------------------------------------------------------------------

/// Decode a community message payload (may be a plain `Content`, a `Content`
/// with an embedded community pro signature, or an `Envelope`).
///
/// Port of C++ `decode_for_community()`.
pub fn decode_for_community(
    content_or_envelope_payload: &[u8],
    unix_ts_ms: u64,
    pro_backend_pubkey: &[u8; 32],
) -> Result<DecodedCommunityMessage, EnvelopeError> {
    use prost::Message as _;
    use crate::proto::session_protos::{Content, Envelope as PbEnvelope};

    let mut result = DecodedCommunityMessage {
        envelope: None,
        content_plaintext: Vec::new(),
        pro_sig: None,
        pro: None,
    };

    // Try to parse as envelope first.
    let mut pro_sig_from_envelope: Option<Vec<u8>> = None;
    let parsed_envelope = PbEnvelope::decode(content_or_envelope_payload)
        .ok()
        .filter(|e| e.content.is_some());
    if let Some(pb_envelope) = parsed_envelope {
        let mut envelope = Envelope::default();

        if let Some(source) = pb_envelope.source.as_ref()
            && !source.is_empty()
        {
            if source.len() != 64 {
                return Err(EnvelopeError::MalformedEnvelope(format!(
                    "source has unexpected size: {}b",
                    source.len()
                )));
            }
            let src_bytes = hex::decode(source).map_err(|e| {
                EnvelopeError::MalformedEnvelope(format!("Invalid source hex: {e}"))
            })?;
            if src_bytes.len() == 32 {
                envelope.source[0] = SESSION_ID_PREFIX_STANDARD;
                envelope.source[1..].copy_from_slice(&src_bytes);
                envelope.flags |= envelope_flags::SOURCE;
            }
        }

        envelope.timestamp = pb_envelope.timestamp;
        envelope.flags |= envelope_flags::TIMESTAMP;

        if let Some(sd) = pb_envelope.source_device {
            envelope.source_device = sd;
            envelope.flags |= envelope_flags::SOURCE_DEVICE;
        }

        if let Some(st) = pb_envelope.server_timestamp {
            envelope.server_timestamp = st;
            envelope.flags |= envelope_flags::SERVER_TIMESTAMP;
        }

        if let Some(ps) = pb_envelope.pro_sig.as_ref() {
            envelope.flags |= envelope_flags::PRO_SIG;
            pro_sig_from_envelope = Some(ps.clone());
        }

        // content is the padded protobuf-encoded Content blob
        if let Some(content) = pb_envelope.content {
            result.content_plaintext = content;
        }

        result.envelope = Some(envelope);
    } else {
        // Treat payload as padded Content directly
        result.content_plaintext = content_or_envelope_payload.to_vec();
    }

    // Parse content (unpad then decode)
    let unpadded = unpad_message(&result.content_plaintext);
    let pb_content = Content::decode(unpadded)
        .map_err(|e| EnvelopeError::ProtobufDecode(e.to_string()))?;

    // Resolve which pro signature to use
    let mut effective_pro_sig: Option<Vec<u8>> = pro_sig_from_envelope.clone();
    if let Some(content_sig) = pb_content.pro_sig_for_community_message_only.as_ref() {
        if effective_pro_sig.is_some() {
            return Err(EnvelopeError::MalformedContent(
                "Envelope and content both provided a pro signature".into(),
            ));
        }
        effective_pro_sig = Some(content_sig.clone());
    }

    if let Some(ps) = effective_pro_sig.as_ref() {
        if ps.len() != 64 {
            return Err(EnvelopeError::MalformedEnvelope(
                "pro signature wrong size".into(),
            ));
        }

        let mut pro_sig_arr = [0u8; 64];
        pro_sig_arr.copy_from_slice(ps);
        result.pro_sig = Some(pro_sig_arr);

        if let Some(env) = result.envelope.as_mut() {
            env.pro_sig.copy_from_slice(ps);
        }

        if let Some(pro_msg) = pb_content.pro_message.as_ref() {
            let proto_proof = pro_msg
                .proof
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("pro_message missing proof".into()))?;

            let version = proto_proof
                .version
                .ok_or_else(|| EnvelopeError::MalformedProProof("proof missing version".into()))?;
            if version != ProProofVersion::V0 as u32 {
                return Err(EnvelopeError::MalformedProProof(format!(
                    "unexpected proof version {version}"
                )));
            }
            let gen_index_hash_bytes = proto_proof
                .gen_index_hash
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing genIndexHash".into()))?;
            let rotating_pk_bytes = proto_proof
                .rotating_public_key
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing rotatingPublicKey".into()))?;
            let expiry = proto_proof
                .expiry_unix_ts
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing expiryUnixTs".into()))?;
            let sig_bytes = proto_proof
                .sig
                .as_ref()
                .ok_or_else(|| EnvelopeError::MalformedProProof("missing sig".into()))?;

            if gen_index_hash_bytes.len() != 32
                || rotating_pk_bytes.len() != 32
                || sig_bytes.len() != 64
            {
                return Err(EnvelopeError::MalformedProProof("field wrong size".into()));
            }

            let mut proof = ProProof {
                version: version as u8,
                gen_index_hash: [0u8; 32],
                rotating_pubkey: [0u8; 32],
                expiry_unix_ts_ms: expiry,
                sig: [0u8; 64],
            };
            proof.gen_index_hash.copy_from_slice(gen_index_hash_bytes);
            proof.rotating_pubkey.copy_from_slice(rotating_pk_bytes);
            proof.sig.copy_from_slice(sig_bytes);

            let msg_bitset = ProMessageBitset {
                data: pro_msg.msg_bitset.unwrap_or(0),
            };
            let profile_bitset = ProProfileBitset {
                data: pro_msg.profile_bitset.unwrap_or(0),
            };

            // If the payload was a `Content` with the community-only pro
            // signature field set, we have to verify against the padded
            // `Content` with that field cleared (matching how the sender
            // signed it before inserting the field).
            let status = if result.envelope.is_some() {
                proof
                    .status(
                        pro_backend_pubkey,
                        unix_ts_ms,
                        Some(ProSignedMessage {
                            sig: ps,
                            msg: &result.content_plaintext,
                        }),
                    )
                    .map_err(|e| EnvelopeError::Ed25519(e.to_string()))?
            } else {
                // Remove signature, reserialise + pad, then verify.
                let mut content_without_sig = pb_content.clone();
                content_without_sig.pro_sig_for_community_message_only = None;
                let serialised = content_without_sig.encode_to_vec();
                let padded = pad_message(&serialised);
                proof
                    .status(
                        pro_backend_pubkey,
                        unix_ts_ms,
                        Some(ProSignedMessage {
                            sig: ps,
                            msg: &padded,
                        }),
                    )
                    .map_err(|e| EnvelopeError::Ed25519(e.to_string()))?
            };

            result.pro = Some(DecodedPro {
                status,
                proof,
                msg_bitset,
                profile_bitset,
            });
        }
    }

    // Strip padding from returned content.
    result.content_plaintext = unpadded.to_vec();
    Ok(result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_1o1_roundtrip() {
        use prost::Message as _;
        use crate::crypto::{curve25519, ed25519};
        use crate::proto::session_protos::{Content, DataMessage};

        // Sender and recipient keypairs
        let (_sender_ed_pk, sender_ed_sk) = ed25519::ed25519_key_pair();
        let (recipient_ed_pk, recipient_ed_sk) = ed25519::ed25519_key_pair();

        // Recipient's Session ID is "05" + x25519(recipient_ed_pk)
        let recipient_x = curve25519::to_curve25519_pubkey(&recipient_ed_pk).unwrap();
        let mut recipient_session_id = [0u8; 33];
        recipient_session_id[0] = SESSION_ID_PREFIX_STANDARD;
        recipient_session_id[1..].copy_from_slice(&recipient_x);

        // Build a simple Content with a DataMessage
        let body_text = "hello alpin!".to_string();
        let ts_ms: u64 = 1_700_000_000_000;
        let content = Content {
            data_message: Some(DataMessage {
                body: Some(body_text.clone()),
                timestamp: Some(ts_ms),
                ..Default::default()
            }),
            sig_timestamp: Some(ts_ms),
            ..Default::default()
        };
        let plaintext = content.encode_to_vec();

        // Encode for 1o1
        let wire = encode_for_1o1(
            &plaintext,
            &sender_ed_sk,
            ts_ms,
            &recipient_session_id,
            None,
        )
        .expect("encode_for_1o1 should succeed");
        assert!(!wire.is_empty());

        // Decode as recipient
        let keys = DecodeEnvelopeKey {
            group_ed25519_pubkey: None,
            decrypt_keys: &[&recipient_ed_sk],
        };
        let pro_backend_pk = [0u8; 32]; // not used since message has no Pro
        let decoded = decode_envelope(&keys, &wire, &pro_backend_pk)
            .expect("decode_envelope should succeed");

        // Envelope timestamp and flags
        assert_eq!(decoded.envelope.timestamp, ts_ms);
        assert!(decoded.envelope.flags & envelope_flags::TIMESTAMP != 0);

        // Content round-trips
        let parsed_content = Content::decode(decoded.content_plaintext.as_slice())
            .expect("content should parse");
        let dm = parsed_content.data_message.expect("data_message present");
        assert_eq!(dm.body.as_deref(), Some(body_text.as_str()));

        // No Pro metadata
        assert!(decoded.pro.is_none());
    }

    #[test]
    fn test_encode_decode_for_community_roundtrip() {
        use prost::Message as _;
        use crate::proto::session_protos::{Content, DataMessage};

        let content = Content {
            data_message: Some(DataMessage {
                body: Some("hi community".into()),
                timestamp: Some(1),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plaintext = content.encode_to_vec();

        let wire = encode_for_community(&plaintext, None).expect("encode ok");

        let pro_backend_pk = [0u8; 32];
        let decoded = decode_for_community(&wire, 0, &pro_backend_pk).expect("decode ok");

        let parsed = Content::decode(decoded.content_plaintext.as_slice()).expect("parse");
        assert_eq!(
            parsed.data_message.and_then(|d| d.body).as_deref(),
            Some("hi community")
        );
        assert!(decoded.pro.is_none());
        assert!(decoded.pro_sig.is_none());
    }

    #[test]
    fn test_pro_features_for_utf16_short() {
        let text: Vec<u16> = "hello".encode_utf16().collect();
        let result = pro_features_for_utf16(&text);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert_eq!(result.codepoint_count, 5);
        assert_eq!(result.bitset.data, 0);
    }

    #[test]
    fn test_constants() {
        assert_eq!(PRO_STANDARD_CHARACTER_LIMIT, 2000);
        assert_eq!(PRO_HIGHER_CHARACTER_LIMIT, 10000);
        assert_eq!(PRO_STANDARD_PINNED_CONVERSATION_LIMIT, 5);
        assert_eq!(COMMUNITY_OR_1O1_MSG_PADDING, 160);
    }

    #[test]
    fn test_personalisation_lengths() {
        assert_eq!(GENERATE_PROOF_HASH_PERSONALISATION.len(), 16);
        assert_eq!(BUILD_PROOF_HASH_PERSONALISATION.len(), 16);
        assert_eq!(ADD_PRO_PAYMENT_HASH_PERSONALISATION.len(), 16);
        assert_eq!(SET_PAYMENT_REFUND_REQUESTED_HASH_PERSONALISATION.len(), 16);
        assert_eq!(GET_PRO_DETAILS_HASH_PERSONALISATION.len(), 16);
    }

    #[test]
    fn test_protocol_strings() {
        assert_eq!(PROTOCOL_STRINGS.build_variant_apk, "APK");
        assert_eq!(PROTOCOL_STRINGS.build_variant_fdroid, "F-Droid Store");
        assert_eq!(PROTOCOL_STRINGS.build_variant_huawei, "Huawei App Gallery");
        assert_eq!(PROTOCOL_STRINGS.build_variant_ipa, "IPA");
        assert_eq!(
            PROTOCOL_STRINGS.url_donations,
            "https://getsession.org/donate"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_donations_app,
            "https://getsession.org/donate#app"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_download,
            "https://getsession.org/download"
        );
        assert_eq!(PROTOCOL_STRINGS.url_faq, "https://getsession.org/faq");
        assert_eq!(
            PROTOCOL_STRINGS.url_feedback,
            "https://getsession.org/feedback"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_network,
            "https://docs.getsession.org/session-network"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_privacy_policy,
            "https://getsession.org/privacy-policy"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_access_not_found,
            "https://sessionapp.zendesk.com/hc/sections/4416517450649-Support"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_faq,
            "https://getsession.org/pro#faq"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_page,
            "https://getsession.org/pro"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_privacy_policy,
            "https://getsession.org/pro-privacy"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_roadmap,
            "https://getsession.org/pro#roadmap"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_support,
            "https://getsession.org/pro-support"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_terms_of_service,
            "https://getsession.org/pro-terms"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_pro_upgrade,
            "https://getsession.org/pro#upgrade"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_staking,
            "https://docs.getsession.org/session-network/staking"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_support,
            "https://getsession.org/support"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_survey,
            "https://getsession.org/survey"
        );
        assert_eq!(
            PROTOCOL_STRINGS.url_terms_of_service,
            "https://getsession.org/terms-of-service"
        );
        assert_eq!(PROTOCOL_STRINGS.url_token, "https://token.getsession.org");
        assert_eq!(
            PROTOCOL_STRINGS.url_translate,
            "https://getsession.org/translate"
        );
    }

    #[test]
    fn test_pro_status_values() {
        assert_eq!(ProStatus::InvalidProBackendSig as u8, 1);
        assert_eq!(ProStatus::InvalidUserSig as u8, 2);
        assert_eq!(ProStatus::Valid as u8, 3);
        assert_eq!(ProStatus::Expired as u8, 4);
    }

    #[test]
    fn test_pro_profile_bitset() {
        let mut bitset = ProProfileBitset::default();
        assert!(!bitset.is_set(ProProfileFeature::ProBadge));
        assert!(!bitset.is_set(ProProfileFeature::AnimatedAvatar));

        bitset.set(ProProfileFeature::ProBadge);
        assert!(bitset.is_set(ProProfileFeature::ProBadge));
        assert!(!bitset.is_set(ProProfileFeature::AnimatedAvatar));
        assert_eq!(bitset.data, 1);

        bitset.set(ProProfileFeature::AnimatedAvatar);
        assert!(bitset.is_set(ProProfileFeature::ProBadge));
        assert!(bitset.is_set(ProProfileFeature::AnimatedAvatar));
        assert_eq!(bitset.data, 3);

        bitset.unset(ProProfileFeature::ProBadge);
        assert!(!bitset.is_set(ProProfileFeature::ProBadge));
        assert!(bitset.is_set(ProProfileFeature::AnimatedAvatar));
        assert_eq!(bitset.data, 2);
    }

    #[test]
    fn test_pro_message_bitset() {
        let mut bitset = ProMessageBitset::default();
        assert!(!bitset.is_set(ProMessageFeature::CharacterLimit10K));

        bitset.set(ProMessageFeature::CharacterLimit10K);
        assert!(bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(bitset.data, 1);

        bitset.unset(ProMessageFeature::CharacterLimit10K);
        assert!(!bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(bitset.data, 0);
    }

    #[test]
    fn test_pro_features_for_utf8_short_message() {
        let msg = "Hello, world!";
        let result = pro_features_for_utf8(msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert!(result.error.is_none());
        assert!(!result.bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(result.codepoint_count, 13);
    }

    #[test]
    fn test_pro_features_for_utf8_at_standard_limit() {
        let msg: String = "a".repeat(PRO_STANDARD_CHARACTER_LIMIT);
        let result = pro_features_for_utf8(&msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert!(!result.bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(result.codepoint_count, PRO_STANDARD_CHARACTER_LIMIT);
    }

    #[test]
    fn test_pro_features_for_utf8_above_standard_limit() {
        let msg: String = "a".repeat(PRO_STANDARD_CHARACTER_LIMIT + 1);
        let result = pro_features_for_utf8(&msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert!(result.bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(result.codepoint_count, PRO_STANDARD_CHARACTER_LIMIT + 1);
    }

    #[test]
    fn test_pro_features_for_utf8_at_pro_limit() {
        let msg: String = "a".repeat(PRO_HIGHER_CHARACTER_LIMIT);
        let result = pro_features_for_utf8(&msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert!(result.bitset.is_set(ProMessageFeature::CharacterLimit10K));
        assert_eq!(result.codepoint_count, PRO_HIGHER_CHARACTER_LIMIT);
    }

    #[test]
    fn test_pro_features_for_utf8_above_pro_limit() {
        let msg: String = "a".repeat(PRO_HIGHER_CHARACTER_LIMIT + 1);
        let result = pro_features_for_utf8(&msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::ExceedsCharacterLimit);
        assert!(result.error.is_some());
    }

    #[test]
    fn test_pro_features_for_utf8_multibyte() {
        // Each emoji is 1 codepoint but multiple bytes
        let msg = "\u{1F600}\u{1F601}\u{1F602}"; // 3 emoji
        let result = pro_features_for_utf8(msg);
        assert_eq!(result.status, ProFeaturesForMsgStatus::Success);
        assert_eq!(result.codepoint_count, 3);
    }

    #[test]
    fn test_pad_message_alignment() {
        let payload = b"hello";
        let padded = pad_message(payload);
        assert_eq!(padded.len() % COMMUNITY_OR_1O1_MSG_PADDING, 0);
        assert!(padded.len() >= payload.len() + 1);
        assert_eq!(&padded[..payload.len()], payload);
        assert_eq!(padded[payload.len()], PADDING_TERMINATING_BYTE);
        // Rest should be zero
        for &b in &padded[payload.len() + 1..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_pad_message_exact_boundary() {
        // Payload that is exactly PADDING-1 bytes (content + padding byte = PADDING, but the
        // C++ algorithm always adds at least PADDING additional zero bytes after the terminator
        // when the content+terminator falls exactly on a boundary)
        let payload = vec![0xAA; COMMUNITY_OR_1O1_MSG_PADDING - 1];
        let padded = pad_message(&payload);
        assert_eq!(padded.len() % COMMUNITY_OR_1O1_MSG_PADDING, 0);
        assert_eq!(padded.len(), COMMUNITY_OR_1O1_MSG_PADDING * 2);
    }

    #[test]
    fn test_unpad_message() {
        let original = b"hello world";
        let padded = pad_message(original);
        let unpadded = unpad_message(&padded);
        assert_eq!(unpadded, original);
    }

    #[test]
    fn test_unpad_message_empty() {
        let unpadded = unpad_message(&[]);
        assert_eq!(unpadded, &[] as &[u8]);
    }

    #[test]
    fn test_proof_hash_deterministic() {
        let proof = ProProof {
            version: 0,
            gen_index_hash: [1u8; 32],
            rotating_pubkey: [2u8; 32],
            expiry_unix_ts_ms: 1000000,
            sig: [0u8; 64],
        };
        let h1 = proof.hash();
        let h2 = proof.hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_proof_hash_different_inputs() {
        let proof1 = ProProof {
            version: 0,
            gen_index_hash: [1u8; 32],
            rotating_pubkey: [2u8; 32],
            expiry_unix_ts_ms: 1000000,
            sig: [0u8; 64],
        };
        let proof2 = ProProof {
            version: 1,
            gen_index_hash: [1u8; 32],
            rotating_pubkey: [2u8; 32],
            expiry_unix_ts_ms: 1000000,
            sig: [0u8; 64],
        };
        assert_ne!(proof1.hash(), proof2.hash());
    }

    #[test]
    fn test_proof_is_active() {
        let proof = ProProof {
            version: 0,
            gen_index_hash: [0u8; 32],
            rotating_pubkey: [0u8; 32],
            expiry_unix_ts_ms: 5000,
            sig: [0u8; 64],
        };
        assert!(proof.is_active(4999));
        assert!(proof.is_active(5000));
        assert!(!proof.is_active(5001));
    }

    #[test]
    fn test_proof_verify_signature_invalid_pubkey_size() {
        let proof = ProProof {
            version: 0,
            gen_index_hash: [0u8; 32],
            rotating_pubkey: [0u8; 32],
            expiry_unix_ts_ms: 5000,
            sig: [0u8; 64],
        };
        let bad_key = [0u8; 16];
        let result = proof.verify_signature(&bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_verify_message_invalid_sig_size() {
        let proof = ProProof {
            version: 0,
            gen_index_hash: [0u8; 32],
            rotating_pubkey: [0u8; 32],
            expiry_unix_ts_ms: 5000,
            sig: [0u8; 64],
        };
        let bad_sig = [0u8; 32];
        let result = proof.verify_message(&bad_sig, b"hello");
        assert!(result.is_err());
    }

    #[test]
    fn test_proof_sign_and_verify() {
        // Generate a keypair for the "backend"
        let (backend_pk, backend_sk) = crate::crypto::ed25519::ed25519_key_pair();

        // Generate a keypair for the rotating key
        let (rotating_pk, rotating_sk) = crate::crypto::ed25519::ed25519_key_pair();

        // Build a proof
        let mut proof = ProProof {
            version: 0,
            gen_index_hash: [0xAA; 32],
            rotating_pubkey: rotating_pk,
            expiry_unix_ts_ms: u64::MAX, // never expires for this test
            sig: [0u8; 64],
        };

        // Sign the proof hash with the backend key
        let hash = proof.hash();
        let sig = crate::crypto::ed25519::sign(&backend_sk, &hash).unwrap();
        proof.sig = sig;

        // Verify the proof signature
        assert!(proof.verify_signature(&backend_pk).unwrap());

        // Verify with wrong key should fail
        let (wrong_pk, _) = crate::crypto::ed25519::ed25519_key_pair();
        assert!(!proof.verify_signature(&wrong_pk).unwrap());

        // Verify a message signed by the rotating key
        let msg = b"test message";
        let msg_sig = crate::crypto::ed25519::sign(&rotating_sk, msg).unwrap();
        assert!(proof.verify_message(&msg_sig, msg).unwrap());

        // Full status check
        let status = proof.status(&backend_pk, 0, None).unwrap();
        assert_eq!(status, ProStatus::Valid);

        // Status with signed message
        let status = proof
            .status(
                &backend_pk,
                0,
                Some(ProSignedMessage {
                    sig: &msg_sig,
                    msg,
                }),
            )
            .unwrap();
        assert_eq!(status, ProStatus::Valid);
    }

    #[test]
    fn test_proof_status_expired() {
        let (backend_pk, backend_sk) = crate::crypto::ed25519::ed25519_key_pair();

        let mut proof = ProProof {
            version: 0,
            gen_index_hash: [0xBB; 32],
            rotating_pubkey: [0u8; 32],
            expiry_unix_ts_ms: 1000,
            sig: [0u8; 64],
        };

        let hash = proof.hash();
        proof.sig = crate::crypto::ed25519::sign(&backend_sk, &hash).unwrap();

        // Check at a time after expiry
        let status = proof.status(&backend_pk, 1001, None).unwrap();
        assert_eq!(status, ProStatus::Expired);
    }

    #[test]
    fn test_destination_type_values() {
        assert_eq!(DestinationType::SyncOr1o1 as u8, 0);
        assert_eq!(DestinationType::Group as u8, 1);
        assert_eq!(DestinationType::CommunityInbox as u8, 2);
        assert_eq!(DestinationType::Community as u8, 3);
    }

    #[test]
    fn test_envelope_flags() {
        assert_eq!(envelope_flags::SOURCE, 1);
        assert_eq!(envelope_flags::SOURCE_DEVICE, 2);
        assert_eq!(envelope_flags::SERVER_TIMESTAMP, 4);
        assert_eq!(envelope_flags::PRO_SIG, 8);
        assert_eq!(envelope_flags::TIMESTAMP, 16);
    }

    #[test]
    fn test_make_blake2b32_hasher() {
        let mut hasher = make_blake2b32_hasher(BUILD_PROOF_HASH_PERSONALISATION);
        hasher.update(b"test data");
        let result = hasher.finalize();
        assert_eq!(result.as_bytes().len(), 32);
    }
}
