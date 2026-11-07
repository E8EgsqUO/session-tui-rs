//! Group Members config type.
//!
//! Port of `libsession-util/include/session/config/groups/members.hpp` and
//! `src/config/groups/members.cpp`.
//!
//! Config keys:
//!   m - dict of members; each key is the session ID (33 bytes binary),
//!       each value is a dict containing:
//!     n - member name (always set, possibly empty)
//!     p - member profile pic URL
//!     q - member profile pic key (32 bytes)
//!     I - invite status (1=sent, 2=failed, 3=not_sent, omitted=accepted)
//!     s - supplement flag (1 if invite included supplemental keys)
//!     A - admin flag (1 if admin)
//!     P - promotion status (1=sent, 2=failed, 3=not_sent, omitted=not promoting)
//!     t - profile_updated timestamp (seconds)

use std::collections::BTreeMap;

use crate::config::config_base::field_helpers::*;
use crate::config::config_base::ConfigType;
use crate::config::config_message::{ConfigData, ConfigValue};
use crate::config::namespaces::Namespace;
use crate::config::profile_pic::ProfilePic;

/// Status constants for invite/promotion.
pub const STATUS_SENT: i32 = 1;
pub const STATUS_FAILED: i32 = 2;
pub const STATUS_NOT_SENT: i32 = 3;

/// Removal status constants.
pub const REMOVED_MEMBER: i32 = 1;
pub const REMOVED_MEMBER_AND_MESSAGES: i32 = 2;

/// Maximum member name length in bytes.
pub const MAX_NAME_LENGTH: usize = 100;

/// Status enum consolidating invite/promotion/removal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    InviteUnknown,
    InviteNotSent,
    InviteSending,
    InviteFailed,
    InviteSent,
    InviteAccepted,
    PromotionUnknown,
    PromotionNotSent,
    PromotionSending,
    PromotionFailed,
    PromotionSent,
    PromotionAccepted,
    RemovedUnknown,
    Removed,
    RemovedIncludingMessages,
}

/// A single group member.
#[derive(Debug, Clone)]
pub struct Member {
    /// The member's session ID in hex (66 chars).
    pub session_id: String,
    /// The member's display name.
    pub name: String,
    /// The member's profile picture.
    pub profile_pic: ProfilePic,
    /// Unix timestamp (seconds) when the profile was last updated.
    pub profile_updated: i64,
    /// Whether this member is an admin.
    pub admin: bool,
    /// Whether the invite included supplemental keys.
    pub supplement: bool,
    /// Invite status (0 = accepted/no invite, STATUS_SENT/FAILED/NOT_SENT).
    pub invite_status: i32,
    /// Promotion status (0 = not promoting, STATUS_SENT/FAILED/NOT_SENT).
    pub promotion_status: i32,
}

impl Member {
    /// Creates a new Member with the given session ID.
    pub fn new(session_id: &str) -> Self {
        Member {
            session_id: session_id.to_string(),
            name: String::new(),
            profile_pic: ProfilePic::default(),
            profile_updated: 0,
            admin: false,
            supplement: false,
            invite_status: STATUS_NOT_SENT,
            promotion_status: 0,
        }
    }

    /// Marks the invite as sent.
    pub fn set_invite_sent(&mut self) {
        self.invite_status = STATUS_SENT;
    }

    /// Resets the invite status to not sent.
    pub fn set_invite_not_sent(&mut self) {
        self.invite_status = STATUS_NOT_SENT;
    }

    /// Marks the invite as failed.
    pub fn set_invite_failed(&mut self) {
        self.invite_status = STATUS_FAILED;
    }

    /// Marks the invite as accepted (clears invite and supplement flags).
    pub fn set_invite_accepted(&mut self) {
        self.invite_status = 0;
        self.supplement = false;
    }

    /// Whether the invite is pending (any non-zero invite_status).
    pub fn invite_pending(&self) -> bool {
        self.invite_status != 0
    }

    /// Marks this member for promotion to admin.
    pub fn set_promoted(&mut self) {
        self.admin = true;
        self.invite_status = 0;
        self.promotion_status = STATUS_NOT_SENT;
    }

    /// Marks promotion message as sent.
    pub fn set_promotion_sent(&mut self) {
        self.admin = true;
        self.invite_status = 0;
        self.promotion_status = STATUS_SENT;
    }

    /// Marks promotion as failed.
    pub fn set_promotion_failed(&mut self) {
        self.admin = true;
        self.invite_status = 0;
        self.promotion_status = STATUS_FAILED;
    }

    /// Marks promotion as accepted.
    pub fn set_promotion_accepted(&mut self) {
        self.admin = true;
        self.invite_status = 0;
        self.promotion_status = 0;
    }

    /// Whether a promotion is pending.
    pub fn promotion_pending(&self) -> bool {
        self.promotion_status != 0
    }

    /// Returns the consolidated status.
    pub fn status(&self) -> MemberStatus {
        if self.promotion_status != 0 {
            match self.promotion_status {
                STATUS_NOT_SENT => MemberStatus::PromotionNotSent,
                STATUS_SENT => MemberStatus::PromotionSent,
                STATUS_FAILED => MemberStatus::PromotionFailed,
                _ => MemberStatus::PromotionUnknown,
            }
        } else if self.admin {
            MemberStatus::PromotionAccepted
        } else if self.invite_status != 0 {
            match self.invite_status {
                STATUS_NOT_SENT => MemberStatus::InviteNotSent,
                STATUS_SENT => MemberStatus::InviteSent,
                STATUS_FAILED => MemberStatus::InviteFailed,
                _ => MemberStatus::InviteUnknown,
            }
        } else {
            MemberStatus::InviteAccepted
        }
    }

    fn load_from_dict(&mut self, dict: &ConfigData) {
        self.name = get_string(dict, b"n").unwrap_or_default();

        self.profile_pic = ProfilePic::default();
        if let Some(url) = get_string(dict, b"p") {
            self.profile_pic.url = url;
        }
        if let Some(key) = get_bytes(dict, b"q")
            && key.len() == 32 {
                self.profile_pic.key = key;
            }

        self.profile_updated = get_int_or_zero(dict, b"t");
        self.admin = get_int_or_zero(dict, b"A") != 0;
        self.supplement = get_int_or_zero(dict, b"s") != 0;
        self.invite_status = get_int_or_zero(dict, b"I") as i32;
        self.promotion_status = get_int_or_zero(dict, b"P") as i32;
    }

    fn store_to_dict(&self) -> ConfigData {
        let mut dict = ConfigData::new();

        // Name is always stored (even if empty) to keep the dict alive
        set_str_always(&mut dict, b"n", &self.name);

        if !self.profile_pic.url.is_empty() && self.profile_pic.key.len() == 32 {
            set_nonempty_str(&mut dict, b"p", &self.profile_pic.url);
            set_nonempty_bytes(&mut dict, b"q", &self.profile_pic.key);
        }

        set_positive_int(&mut dict, b"t", self.profile_updated);
        set_flag(&mut dict, b"A", self.admin);

        // Invite status (omit if 0, which means accepted)
        if self.invite_status != 0 && !self.admin {
            dict.insert(
                b"I".to_vec(),
                ConfigValue::Integer(self.invite_status as i64),
            );
            set_flag(&mut dict, b"s", self.supplement);
        }

        // Promotion status (omit if 0)
        if self.promotion_status != 0 {
            dict.insert(
                b"P".to_vec(),
                ConfigValue::Integer(self.promotion_status as i64),
            );
        }

        dict
    }
}

/// The GroupMembers config type.
#[derive(Debug, Clone, Default)]
pub struct GroupMembers {
    members: BTreeMap<String, Member>,
}

impl GroupMembers {
    /// Gets a member by session ID.
    pub fn get(&self, session_id: &str) -> Option<&Member> {
        self.members.get(session_id)
    }

    /// Gets a mutable member by session ID.
    pub fn get_mut(&mut self, session_id: &str) -> Option<&mut Member> {
        self.members.get_mut(session_id)
    }

    /// Gets a member or constructs a new one.
    pub fn get_or_construct(&self, session_id: &str) -> Member {
        self.members
            .get(session_id)
            .cloned()
            .unwrap_or_else(|| Member::new(session_id))
    }

    /// Sets (inserts or updates) a member.
    pub fn set(&mut self, member: Member) {
        self.members
            .insert(member.session_id.clone(), member);
    }

    /// Removes a member. Returns true if found.
    pub fn erase(&mut self, session_id: &str) -> bool {
        self.members.remove(session_id).is_some()
    }

    /// Returns the number of members.
    pub fn size(&self) -> usize {
        self.members.len()
    }

    /// Returns true if there are no members.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Iterates over all members.
    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    /// Returns all member session IDs.
    pub fn session_ids(&self) -> Vec<&str> {
        self.members.keys().map(|s| s.as_str()).collect()
    }
}

impl ConfigType for GroupMembers {
    fn namespace() -> Namespace {
        Namespace::GroupMembers
    }

    fn encryption_domain() -> &'static str {
        "groups::Members"
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        self.members.clear();

        if let Some(ConfigValue::Dict(members_dict)) = data.get(b"m".as_ref()) {
            for (key, value) in members_dict {
                if let ConfigValue::Dict(member_dict) = value {
                    let session_id = hex::encode(key);
                    let mut member = Member::new(&session_id);
                    member.load_from_dict(member_dict);
                    self.members.insert(session_id, member);
                }
            }
        }
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        if self.members.is_empty() {
            data.remove(b"m".as_ref());
            return;
        }

        let mut members_dict = ConfigData::new();
        for (session_id, member) in &self.members {
            if let Ok(key_bytes) = hex::decode(session_id) {
                members_dict.insert(key_bytes, ConfigValue::Dict(member.store_to_dict()));
            }
        }
        data.insert(b"m".to_vec(), ConfigValue::Dict(members_dict));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_member() {
        let m = Member::new("05abcdef");
        assert_eq!(m.session_id, "05abcdef");
        assert!(!m.admin);
        assert!(m.invite_pending());
        assert!(!m.promotion_pending());
    }

    #[test]
    fn test_member_invite_lifecycle() {
        let mut m = Member::new("05abcdef");
        assert_eq!(m.status(), MemberStatus::InviteNotSent);

        m.set_invite_sent();
        assert_eq!(m.status(), MemberStatus::InviteSent);

        m.set_invite_accepted();
        assert_eq!(m.status(), MemberStatus::InviteAccepted);
        assert!(!m.invite_pending());
    }

    #[test]
    fn test_member_promotion_lifecycle() {
        let mut m = Member::new("05abcdef");
        m.set_invite_accepted();

        m.set_promoted();
        assert!(m.admin);
        assert_eq!(m.status(), MemberStatus::PromotionNotSent);

        m.set_promotion_sent();
        assert_eq!(m.status(), MemberStatus::PromotionSent);

        m.set_promotion_accepted();
        assert_eq!(m.status(), MemberStatus::PromotionAccepted);
        assert!(!m.promotion_pending());
    }

    #[test]
    fn test_members_crud() {
        let mut members = GroupMembers::default();
        assert!(members.is_empty());

        let mut m = Member::new("05aabb");
        m.name = "Alice".to_string();
        m.set_invite_accepted();
        members.set(m);

        assert_eq!(members.size(), 1);
        assert_eq!(members.get("05aabb").unwrap().name, "Alice");

        members.erase("05aabb");
        assert!(members.is_empty());
    }

    #[test]
    fn test_roundtrip() {
        let mut members = GroupMembers::default();

        let mut m1 = Member::new("050000000000000000000000000000000000000000000000000000000000000000");
        m1.name = "Alice".to_string();
        m1.admin = true;
        m1.set_invite_accepted();
        m1.set_promotion_accepted();
        members.set(m1);

        let mut m2 = Member::new("050000000000000000000000000000000000000000000000000000000000000001");
        m2.name = "Bob".to_string();
        m2.set_invite_sent();
        m2.supplement = true;
        members.set(m2);

        let mut data = ConfigData::new();
        members.store_to_data(&mut data);

        let mut loaded = GroupMembers::default();
        loaded.load_from_data(&data);

        assert_eq!(loaded.size(), 2);

        let alice = loaded.get("050000000000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(alice.name, "Alice");
        assert!(alice.admin);
        assert!(!alice.invite_pending());

        let bob = loaded.get("050000000000000000000000000000000000000000000000000000000000000001").unwrap();
        assert_eq!(bob.name, "Bob");
        assert!(!bob.admin);
        assert_eq!(bob.invite_status, STATUS_SENT);
        assert!(bob.supplement);
    }
}
