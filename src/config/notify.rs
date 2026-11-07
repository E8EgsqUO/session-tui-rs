//! Notification settings for Session configs.
//!
//! Port of `libsession-util/include/session/config/notify.hpp`.

/// Notification mode for a conversation or group.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotifyMode {
    /// Use the default notification setting.
    #[default]
    Default = 0,
    /// Notify for all messages.
    All = 1,
    /// Notifications are disabled.
    Disabled = 2,
    /// Notify only for mentions (groups only; for DMs this becomes `All`).
    MentionsOnly = 3,
}

impl NotifyMode {
    /// Creates a `NotifyMode` from a raw `i32` value.
    ///
    /// Returns `Default` for unrecognized values.
    pub fn from_raw(val: i32) -> Self {
        match val {
            0 => NotifyMode::Default,
            1 => NotifyMode::All,
            2 => NotifyMode::Disabled,
            3 => NotifyMode::MentionsOnly,
            _ => NotifyMode::Default,
        }
    }
}

/// What content to include in notifications.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotifyContent {
    /// Use the default content setting.
    #[default]
    Default = 0,
    /// Show sender name and message preview.
    NameAndPreview = 1,
    /// Show sender name but no message preview.
    NameNoPreview = 2,
    /// Show neither sender name nor message preview.
    NoNameNoPreview = 3,
}

impl NotifyContent {
    /// Creates a `NotifyContent` from a raw `i32` value.
    ///
    /// Returns `Default` for unrecognized values.
    pub fn from_raw(val: i32) -> Self {
        match val {
            0 => NotifyContent::Default,
            1 => NotifyContent::NameAndPreview,
            2 => NotifyContent::NameNoPreview,
            3 => NotifyContent::NoNameNoPreview,
            _ => NotifyContent::Default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_notify_mode_repr() {
        assert_eq!(NotifyMode::Default as i32, 0);
        assert_eq!(NotifyMode::All as i32, 1);
        assert_eq!(NotifyMode::Disabled as i32, 2);
        assert_eq!(NotifyMode::MentionsOnly as i32, 3);
    }

    #[test]
    fn test_notify_mode_from_raw() {
        assert_eq!(NotifyMode::from_raw(0), NotifyMode::Default);
        assert_eq!(NotifyMode::from_raw(1), NotifyMode::All);
        assert_eq!(NotifyMode::from_raw(2), NotifyMode::Disabled);
        assert_eq!(NotifyMode::from_raw(3), NotifyMode::MentionsOnly);
        assert_eq!(NotifyMode::from_raw(99), NotifyMode::Default);
        assert_eq!(NotifyMode::from_raw(-1), NotifyMode::Default);
    }

    #[test]
    fn test_notify_content_repr() {
        assert_eq!(NotifyContent::Default as i32, 0);
        assert_eq!(NotifyContent::NameAndPreview as i32, 1);
        assert_eq!(NotifyContent::NameNoPreview as i32, 2);
        assert_eq!(NotifyContent::NoNameNoPreview as i32, 3);
    }

    #[test]
    fn test_notify_content_from_raw() {
        assert_eq!(NotifyContent::from_raw(0), NotifyContent::Default);
        assert_eq!(NotifyContent::from_raw(1), NotifyContent::NameAndPreview);
        assert_eq!(NotifyContent::from_raw(2), NotifyContent::NameNoPreview);
        assert_eq!(NotifyContent::from_raw(3), NotifyContent::NoNameNoPreview);
        assert_eq!(NotifyContent::from_raw(42), NotifyContent::Default);
    }

    #[test]
    fn test_notify_mode_default() {
        let mode: NotifyMode = Default::default();
        assert_eq!(mode, NotifyMode::Default);
    }

    #[test]
    fn test_notify_content_default() {
        let content: NotifyContent = Default::default();
        assert_eq!(content, NotifyContent::Default);
    }
}
