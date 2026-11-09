//! Chat list: `/filter`, pinned chats first, and moving between the chats
//! that are shown. Filtering only changes what the list shows; chats keep
//! receiving, syncing and counting unread messages.

use super::{App, Conversation};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChatFilter {
    /// Name or Session/group ID contains this (any letter case).
    Text(String),
    /// Chats with unread messages.
    Unread,
}

impl ChatFilter {
    pub fn parse(args: &str) -> Option<Self> {
        match args.trim() {
            "" => None,
            "--unread" => Some(Self::Unread),
            text => Some(Self::Text(text.to_owned())),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Text(text) => format!("“{text}”"),
            Self::Unread => "unread".into(),
        }
    }

    pub fn matches(&self, title: &str, id: &str, unread: usize) -> bool {
        match self {
            Self::Unread => unread > 0,
            Self::Text(text) => {
                let wanted = text.to_lowercase();
                title.to_lowercase().contains(&wanted) || id.contains(&wanted)
            }
        }
    }
}

/// Sort key: pinned chats, then ordinary ones, then message requests; each
/// group newest first. (Requests stay last unless pinned.)
pub fn sort_key(pinned: bool, request: bool, last_activity: u64) -> (u8, std::cmp::Reverse<u64>) {
    let group = if pinned {
        0
    } else if request {
        2
    } else {
        1
    };
    (group, std::cmp::Reverse(last_activity))
}

fn shown(app: &App, conversation: &Conversation) -> bool {
    app.chat_filter.as_ref().is_none_or(|filter| {
        filter.matches(
            conversation.title(&app.local_id),
            &conversation.id,
            conversation.unread(),
        )
    })
}

/// Indices of the chats shown in the list, in list order.
pub(super) fn visible(app: &App) -> Vec<usize> {
    (0..app.conversations.len())
        .filter(|&index| shown(app, &app.conversations[index]))
        .collect()
}

/// Move `delta` places in the shown list (from the open chat, or from the
/// list's start when the open chat is filtered out).
pub(super) fn step(app: &mut App, delta: isize) {
    let list = visible(app);
    if list.is_empty() {
        return;
    }
    let position = match list.iter().position(|&i| i == app.selected) {
        Some(position) => (position as isize + delta).clamp(0, list.len() as isize - 1),
        None => 0,
    };
    app.selected = list[position as usize];
}

/// The `n`th shown chat (1-based), as `/1`–`/9` number them.
pub(super) fn nth(app: &App, number: usize) -> Option<usize> {
    visible(app).get(number.checked_sub(1)?).copied()
}

/// Next shown chat after the open one (wrapping) with unread messages.
pub fn next_unread(
    order: &[usize],
    current: usize,
    unread: impl Fn(usize) -> bool,
) -> Option<usize> {
    let start = order
        .iter()
        .position(|&i| i == current)
        .map_or(0, |p| p + 1);
    (0..order.len())
        .map(|offset| order[(start + offset) % order.len()])
        .find(|&index| index != current && unread(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_parsing_and_matching() {
        assert_eq!(ChatFilter::parse("  "), None);
        assert_eq!(ChatFilter::parse("--unread"), Some(ChatFilter::Unread));
        let filter = ChatFilter::parse("ALI").unwrap();
        assert!(filter.matches("Alice", "05aa", 0));
        assert!(!filter.matches("Bob", "05aa", 3));
        let filter = ChatFilter::parse("开发").unwrap();
        assert!(filter.matches("后端开发群", "03ff", 0));
        assert!(ChatFilter::parse("05ab").unwrap().matches("x", "05abcd", 0));
        assert!(ChatFilter::Unread.matches("x", "05", 2));
        assert!(!ChatFilter::Unread.matches("x", "05", 0));
    }

    #[test]
    fn pinned_first_then_chats_then_requests() {
        let mut chats = [
            ("old pinned", true, false, 1),
            ("new chat", false, false, 9),
            ("request", false, true, 10),
            ("new pinned", true, false, 5),
            ("old chat", false, false, 2),
        ];
        chats.sort_by_key(|(_, pinned, request, at)| sort_key(*pinned, *request, *at));
        let names: Vec<&str> = chats.iter().map(|c| c.0).collect();
        assert_eq!(
            names,
            [
                "new pinned",
                "old pinned",
                "new chat",
                "old chat",
                "request"
            ]
        );
    }

    #[test]
    fn next_unread_wraps_and_skips() {
        let order = [4, 1, 3, 0];
        let unread = |i: usize| i == 4 || i == 0;
        assert_eq!(next_unread(&order, 1, unread), Some(0));
        assert_eq!(next_unread(&order, 0, unread), Some(4));
        // The open chat itself doesn't count; nothing else unread.
        assert_eq!(next_unread(&order, 4, |i| i == 4), None);
        assert_eq!(next_unread(&[], 0, unread), None);
        // Open chat filtered out: start from the top.
        assert_eq!(next_unread(&order, 7, unread), Some(4));
    }
}
