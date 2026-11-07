/// Namespace identifiers for Session config and message storage.
///
/// Mirrors the C enum `NAMESPACE` from `namespaces.h`.
#[repr(i16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Namespace {
    /// Messages sent to an updated group which should be able to be retrieved by revoked
    /// members are stored in this namespace.
    RevokedRetrievableGroupMessages = -11,

    /// Messages sent to one-to-one conversations are stored in this namespace.
    Default = 0,

    /// User profile config.
    UserProfile = 2,

    /// Contacts config.
    Contacts = 3,

    /// Volatile conversation info config.
    ConvoInfoVolatile = 4,

    /// User groups config.
    UserGroups = 5,

    /// Messages sent to a group.
    GroupMessages = 11,

    /// Groups config namespace for shared config of the group itself (keys).
    GroupKeys = 12,

    /// Groups config namespace for shared config of the group itself (info).
    GroupInfo = 13,

    /// Groups config namespace for shared config of the group itself (members).
    GroupMembers = 14,

    /// The local config should never be pushed but this gives a nice identifier for each
    /// config type.
    Local = 9999,
}

impl Namespace {
    /// Returns the raw i16 value of this namespace.
    pub fn raw(self) -> i16 {
        self as i16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_values() {
        assert_eq!(Namespace::RevokedRetrievableGroupMessages as i16, -11);
        assert_eq!(Namespace::Default as i16, 0);
        assert_eq!(Namespace::UserProfile as i16, 2);
        assert_eq!(Namespace::Contacts as i16, 3);
        assert_eq!(Namespace::ConvoInfoVolatile as i16, 4);
        assert_eq!(Namespace::UserGroups as i16, 5);
        assert_eq!(Namespace::GroupMessages as i16, 11);
        assert_eq!(Namespace::GroupKeys as i16, 12);
        assert_eq!(Namespace::GroupInfo as i16, 13);
        assert_eq!(Namespace::GroupMembers as i16, 14);
        assert_eq!(Namespace::Local as i16, 9999);
    }

    #[test]
    fn test_namespace_equality() {
        assert_eq!(Namespace::Default, Namespace::Default);
        assert_ne!(Namespace::Default, Namespace::UserProfile);
    }

    #[test]
    fn test_namespace_raw() {
        assert_eq!(Namespace::GroupKeys.raw(), 12);
        assert_eq!(Namespace::RevokedRetrievableGroupMessages.raw(), -11);
    }
}
