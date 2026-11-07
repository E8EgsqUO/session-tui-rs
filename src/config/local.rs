//! Local config type.
//!
//! Port of `libsession-util/include/session/config/local.hpp` and `src/config/local.cpp`.
//!
//! Local-only settings that are never pushed to the swarm. Includes notification content,
//! notification sound, theme, primary color, and arbitrary boolean settings.
//!
//! Config keys:
//!   notify_content - notification content type (int)
//!   notify_sound   - iOS notification sound (int64)
//!   theme          - UI theme (int)
//!   theme_primary_color - UI primary color (int)
//!   settings       - dict of boolean settings (key -> int 0/1)

use std::collections::BTreeMap;

use crate::config::config_base::field_helpers::*;
use crate::config::config_base::ConfigType;
use crate::config::config_message::{ConfigData, ConfigValue};
use crate::config::namespaces::Namespace;
use crate::config::notify::NotifyContent;

/// UI theme options.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Theme {
    #[default]
    Default = 0,
    ClassicDark = 1,
    ClassicLight = 2,
    OceanDark = 3,
    OceanLight = 4,
}

impl Theme {
    /// Creates a Theme from a raw i32 value.
    pub fn from_raw(val: i32) -> Self {
        match val {
            1 => Theme::ClassicDark,
            2 => Theme::ClassicLight,
            3 => Theme::OceanDark,
            4 => Theme::OceanLight,
            _ => Theme::Default,
        }
    }
}

/// UI primary color options.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ThemePrimaryColor {
    #[default]
    Default = 0,
    Green = 1,
    Blue = 2,
    Yellow = 3,
    Pink = 4,
    Purple = 5,
    Orange = 6,
    Red = 7,
}

impl ThemePrimaryColor {
    /// Creates a ThemePrimaryColor from a raw i32 value.
    pub fn from_raw(val: i32) -> Self {
        match val {
            1 => ThemePrimaryColor::Green,
            2 => ThemePrimaryColor::Blue,
            3 => ThemePrimaryColor::Yellow,
            4 => ThemePrimaryColor::Pink,
            5 => ThemePrimaryColor::Purple,
            6 => ThemePrimaryColor::Orange,
            7 => ThemePrimaryColor::Red,
            _ => ThemePrimaryColor::Default,
        }
    }
}

/// Local config type -- never pushed to the swarm.
#[derive(Debug, Clone, Default)]
pub struct Local {
    /// What content to show in notifications.
    pub notification_content: NotifyContent,
    /// iOS notification sound ID.
    pub ios_notification_sound: i64,
    /// UI theme.
    pub theme: Theme,
    /// UI primary color.
    pub theme_primary_color: ThemePrimaryColor,
    /// Arbitrary boolean settings (key -> value).
    pub settings: BTreeMap<String, bool>,
}

impl Local {
    /// Gets a setting by key. Returns None if not set.
    pub fn get_setting(&self, key: &str) -> Option<bool> {
        self.settings.get(key).copied()
    }

    /// Sets a setting. Pass None to remove it.
    pub fn set_setting(&mut self, key: &str, value: Option<bool>) {
        match value {
            Some(v) => {
                self.settings.insert(key.to_string(), v);
            }
            None => {
                self.settings.remove(key);
            }
        }
    }

    /// Returns the number of settings.
    pub fn size_settings(&self) -> usize {
        self.settings.len()
    }
}

impl ConfigType for Local {
    fn namespace() -> Namespace {
        // Local configs should never be pushed, but we need a namespace for identification.
        // The C++ code uses UserProfile namespace as fallback.
        Namespace::Local
    }

    fn encryption_domain() -> &'static str {
        "Local"
    }

    fn is_readonly() -> bool {
        // Local configs should never be pushed to the swarm
        true
    }

    fn load_from_data(&mut self, data: &ConfigData) {
        let nc = get_int_or_zero(data, b"notify_content") as i32;
        self.notification_content = NotifyContent::from_raw(nc);

        self.ios_notification_sound = get_int_or_zero(data, b"notify_sound");

        let theme_val = get_int_or_zero(data, b"theme") as i32;
        self.theme = Theme::from_raw(theme_val);

        let color_val = get_int_or_zero(data, b"theme_primary_color") as i32;
        self.theme_primary_color = ThemePrimaryColor::from_raw(color_val);

        // Settings
        self.settings.clear();
        if let Some(ConfigValue::Dict(settings_dict)) = data.get(b"settings".as_ref()) {
            for (key, value) in settings_dict {
                if let ConfigValue::Integer(v) = value
                    && let Ok(key_str) = String::from_utf8(key.clone()) {
                        self.settings.insert(key_str, *v != 0);
                    }
            }
        }
    }

    fn store_to_data(&self, data: &mut ConfigData) {
        set_positive_int(data, b"notify_content", self.notification_content as i32 as i64);
        set_positive_int(data, b"notify_sound", self.ios_notification_sound);
        set_positive_int(data, b"theme", self.theme as i32 as i64);
        set_positive_int(
            data,
            b"theme_primary_color",
            self.theme_primary_color as i32 as i64,
        );

        if self.settings.is_empty() {
            data.remove(b"settings".as_ref());
        } else {
            let mut settings_dict = ConfigData::new();
            for (key, value) in &self.settings {
                if *value {
                    settings_dict.insert(
                        key.as_bytes().to_vec(),
                        ConfigValue::Integer(1),
                    );
                }
                // false values are stored as flag=1 (presence) in C++ via set_flag,
                // but for settings we store 0/1 explicitly
            }
            data.insert(b"settings".to_vec(), ConfigValue::Dict(settings_dict));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::config_base::ConfigBase;

    #[test]
    fn test_default_local() {
        let local = Local::default();
        assert_eq!(local.theme, Theme::Default);
        assert_eq!(local.theme_primary_color, ThemePrimaryColor::Default);
        assert_eq!(local.notification_content, NotifyContent::Default);
        assert_eq!(local.ios_notification_sound, 0);
        assert!(local.settings.is_empty());
    }

    #[test]
    fn test_theme_from_raw() {
        assert_eq!(Theme::from_raw(0), Theme::Default);
        assert_eq!(Theme::from_raw(1), Theme::ClassicDark);
        assert_eq!(Theme::from_raw(4), Theme::OceanLight);
        assert_eq!(Theme::from_raw(99), Theme::Default);
    }

    #[test]
    fn test_primary_color_from_raw() {
        assert_eq!(ThemePrimaryColor::from_raw(0), ThemePrimaryColor::Default);
        assert_eq!(ThemePrimaryColor::from_raw(1), ThemePrimaryColor::Green);
        assert_eq!(ThemePrimaryColor::from_raw(7), ThemePrimaryColor::Red);
        assert_eq!(ThemePrimaryColor::from_raw(99), ThemePrimaryColor::Default);
    }

    #[test]
    fn test_settings() {
        let mut local = Local::default();
        assert!(local.get_setting("test_key").is_none());

        local.set_setting("test_key", Some(true));
        assert_eq!(local.get_setting("test_key"), Some(true));

        local.set_setting("test_key", None);
        assert!(local.get_setting("test_key").is_none());
    }

    #[test]
    fn test_roundtrip() {
        let mut local = Local::default();
        local.theme = Theme::OceanDark;
        local.theme_primary_color = ThemePrimaryColor::Purple;
        local.notification_content = NotifyContent::NameAndPreview;
        local.ios_notification_sound = 42;
        local.set_setting("call_notifications", Some(true));
        local.set_setting("typing_indicators", Some(true));

        let mut data = ConfigData::new();
        local.store_to_data(&mut data);

        let mut loaded = Local::default();
        loaded.load_from_data(&data);

        assert_eq!(loaded.theme, Theme::OceanDark);
        assert_eq!(loaded.theme_primary_color, ThemePrimaryColor::Purple);
        assert_eq!(loaded.notification_content, NotifyContent::NameAndPreview);
        assert_eq!(loaded.ios_notification_sound, 42);
        assert_eq!(loaded.get_setting("call_notifications"), Some(true));
        assert_eq!(loaded.get_setting("typing_indicators"), Some(true));
    }

    #[test]
    fn test_local_never_pushes() {
        let seed = hex_literal::hex!(
            "0123456789abcdef0123456789abcdef00000000000000000000000000000000"
        );
        let mut base: ConfigBase<Local> = ConfigBase::new(&seed, None).unwrap();
        base.get_mut().theme = Theme::ClassicDark;
        // Even after mutation, needs_push should be false for local configs
        assert!(!base.needs_push());
    }
}
