//! Help page content and slash-command completion, from one table: the
//! commands Tab completes are exactly those named in [`HELP`], and a test
//! checks them against the commands the input handler dispatches.

/// (section, [(keys or command, description)]).
pub const HELP: &[(&str, &[(&str, &str)])] = &[
    (
        "Navigation",
        &[
            ("Tab / Shift+Tab", "Move focus: chats → messages → composer"),
            ("← / →", "Previous / next chat (when the composer is empty)"),
            ("↑ / ↓", "Move in the focused list"),
            ("Alt+N", "Next chat with unread messages (within /filter)"),
            (
                "End · Ctrl+End",
                "Jump to the newest message (message list)",
            ),
            (
                "Mouse",
                "Click a chat, message or image; wheel moves the selection",
            ),
            ("/help · /? · Esc", "Open / close this help (↑/↓ scroll)"),
            ("/exit · Ctrl+C", "Quit"),
        ],
    ),
    (
        "Composer",
        &[
            ("Enter", "Send"),
            ("Shift+Enter · Alt+Enter · Ctrl+J", "New line"),
            (
                "Tab on a partial command",
                "Complete a command; Tab again cycles through matches",
            ),
            (
                "← → ↑ ↓ Home End",
                "Move the cursor (Ctrl+A / Ctrl+E: line start / end)",
            ),
            ("Backspace · Delete", "Delete before / after the cursor"),
            ("Ctrl+W · Ctrl+U", "Delete previous word · clear everything"),
            ("Paste", "Inserted at the cursor, line breaks kept"),
            ("Double-click", "Copy what you have typed"),
            (
                ":joy: :heart: :+1:",
                "Emoji shortcodes (/emoji lists them; Win+. on Windows)",
            ),
            (
                "Drafts",
                "Unsent text is kept per chat, also after a restart",
            ),
        ],
    ),
    (
        "Messages (focus the message list)",
        &[
            ("r", "Reply to the selected message (Esc cancels)"),
            ("e  then 1-6", "Reaction bar: 😂 🥰 😢 😡 😮 😈"),
            ("+", "React 👍"),
            (
                "/react EMOJI",
                "React with any emoji or :shortcode: (again removes it)",
            ),
            (
                "Delete",
                "Delete: 1 on this device only · 2 for everyone (your messages)",
            ),
            ("/retry", "Resend the selected failed message"),
            (
                "/bookmark · /unbookmark",
                "Bookmark the selected message (★)",
            ),
            ("/bookmarks", "List bookmarks; Enter opens the message"),
            ("/unread", "Go to the first unread message of this chat"),
            (
                "/goto YYYY-MM-DD",
                "Go to the first message of that local date",
            ),
            ("✓ / ✓✓ / teal ✓✓", "Sent / delivered / read"),
        ],
    ),
    (
        "Search and lists",
        &[
            (
                "/search [--all | --chat ID|NAME] WORD",
                "Search messages (--from/--to YYYY-MM-DD); Enter opens one",
            ),
            (
                "/media",
                "Attachments of this chat · Enter open · V view · S save",
            ),
            ("/links", "Links in this chat · Enter open · C copy"),
        ],
    ),
    (
        "Attachments",
        &[
            (
                "/attach P1 [P2…] [-- caption]",
                "Send files as one message (max 32; quote paths with spaces)",
            ),
            (
                "/view [N]",
                "Open image N of the selected message; ←/→ next/previous",
            ),
            (
                "/paste [-- caption]",
                "Send the image on the clipboard (e.g. a screenshot)",
            ),
            (
                "/save [N] [PATH]",
                "Save attachment N, or all, to PATH or the current folder",
            ),
        ],
    ),
    (
        "Chats and groups",
        &[
            ("Ctrl+N", "Start a chat with a Session ID"),
            (
                "/1 … /9",
                "Switch to chat N (the number shown in the chat list)",
            ),
            (
                "/filter WORD · --unread",
                "Show only matching chats; /filter alone shows all",
            ),
            (
                "/pin · /unpin",
                "Keep this chat at the top (this device only)",
            ),
            (
                "/disappear off | read 12h | send 1d",
                "Disappearing messages for this 1:1 chat",
            ),
            (
                "/accept",
                "Accept a message request, or join the group you were invited to",
            ),
            ("/decline", "Decline a message request (deletes it)"),
            (
                "/delete",
                "Delete this chat and its messages (the contact stays)",
            ),
            (
                "/remove",
                "Remove this contact from your account and delete the chat",
            ),
            (
                "/block · /unblock",
                "Block / unblock this 1:1 contact on all your devices",
            ),
            ("/rsync", "Fetch messages now (also automatic)"),
            (
                "/net",
                "Network diagnostics (paths, nodes, outbox; R refresh)",
            ),
        ],
    ),
    (
        "Settings",
        &[
            (
                "/name [NAME]",
                "Show / set your display name (synced to your other devices)",
            ),
            (
                "/bell on|off",
                "Terminal bell for new messages (title shows unread count)",
            ),
            ("/emoji", "List emoji shortcodes"),
            ("--debug", "Start with a debug log (session-tui-debug.log)"),
            ("--forget-seed", "Start and delete the saved seed"),
        ],
    ),
];

/// Every slash command named in [`HELP`] (not `/1`…`/9`), sorted.
pub fn commands() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = HELP
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .flat_map(|(keys, _)| keys.split_whitespace())
        .filter(|word| {
            word.starts_with('/')
                && word.len() > 1
                && !word[1..].starts_with(|c: char| c.is_ascii_digit())
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Tab completion state: the matches of the typed prefix and which one is
/// shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completion {
    pub matches: Vec<&'static str>,
    pub index: Option<usize>,
}

/// What Tab does with `input`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Not a command being typed: Tab moves focus as before.
    NotCommand,
    /// Nothing matches; the input stays.
    NoMatch,
    /// Replace the input with this.
    Complete(String),
}

/// Complete the command in `input` (a `/word` with nothing after it). The
/// first Tab completes a unique match, or the longest common prefix of
/// several; further Tabs cycle through them.
pub fn complete(input: &str, state: &mut Option<Completion>) -> Tab {
    if !input.starts_with('/') || input.contains(char::is_whitespace) {
        *state = None;
        return Tab::NotCommand;
    }
    // Tab again (any other key resets `state`): next match.
    if let Some(current) = state.as_mut()
        && current.matches.len() > 1
    {
        let len = current.matches.len();
        let mut next = current.index.map_or(0, |i| (i + 1) % len);
        if current.matches[next] == input {
            next = (next + 1) % len;
        }
        current.index = Some(next);
        return Tab::Complete(current.matches[next].to_owned());
    }
    let matches: Vec<&'static str> = commands()
        .into_iter()
        .filter(|command| command.starts_with(input))
        .collect();
    match matches.len() {
        0 => {
            *state = None;
            Tab::NoMatch
        }
        1 => {
            *state = None;
            Tab::Complete(format!("{} ", matches[0]))
        }
        _ => {
            let prefix = common_prefix(&matches);
            *state = Some(Completion {
                matches,
                index: None,
            });
            if prefix.len() > input.len() {
                Tab::Complete(prefix)
            } else {
                // Already at the common part: show the first match.
                let current = state.as_mut().expect("just set");
                current.index = Some(0);
                Tab::Complete(current.matches[0].to_owned())
            }
        }
    }
}

fn common_prefix(words: &[&str]) -> String {
    let first = words[0];
    let mut end = first.len();
    for word in &words[1..] {
        end = end.min(
            first
                .char_indices()
                .zip(word.chars())
                .find(|((_, a), b)| a != b)
                .map_or(end.min(word.len()), |((i, _), _)| i),
        );
    }
    first[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_multiple_and_no_match() {
        let mut state = None;
        assert_eq!(
            complete("/se", &mut state),
            Tab::Complete("/search ".into())
        );
        assert_eq!(
            complete("/fi", &mut state),
            Tab::Complete("/filter ".into())
        );
        assert_eq!(complete("/zz", &mut state), Tab::NoMatch);
        assert_eq!(state, None);
        // /bo → /bookmark, /bookmarks: common prefix first, then cycling.
        assert_eq!(
            complete("/bo", &mut state),
            Tab::Complete("/bookmark".into())
        );
        assert_eq!(
            complete("/bookmark", &mut state),
            Tab::Complete("/bookmarks".into())
        );
        assert_eq!(
            complete("/bookmarks", &mut state),
            Tab::Complete("/bookmark".into())
        );
        assert_eq!(
            complete("/bookmark", &mut state),
            Tab::Complete("/bookmarks".into())
        );
        // /un…: several, already at the common prefix.
        let mut state = None;
        let first = complete("/un", &mut state);
        assert!(matches!(first, Tab::Complete(ref c) if c.starts_with("/un")));
        let second = complete(
            match &first {
                Tab::Complete(c) => c,
                _ => unreachable!(),
            },
            &mut state,
        );
        assert_ne!(first, second);
    }

    #[test]
    fn plain_text_and_arguments_are_not_completed() {
        let mut state = None;
        assert_eq!(complete("hello", &mut state), Tab::NotCommand);
        assert_eq!(complete("", &mut state), Tab::NotCommand);
        assert_eq!(complete("/search fo", &mut state), Tab::NotCommand);
    }

    #[test]
    fn help_and_dispatch_name_the_same_commands() {
        let source = include_str!("session_tui.rs");
        let listed = commands();
        // Every command in the help is handled by the input handler.
        for command in &listed {
            assert!(
                source.contains(&format!("\"{command}\"")),
                "{command} is in the help but not handled"
            );
        }
        // Every command the handler matches is in the help.
        let mut handled = Vec::new();
        for line in source.lines() {
            let line = line.trim_start();
            if !line.starts_with("\"/")
                || !(line.contains("=>") || line.ends_with(" if") || line.contains(" if "))
            {
                continue;
            }
            for part in line.split('|') {
                let part = part.trim();
                if let Some(rest) = part.strip_prefix('"')
                    && let Some(end) = rest.find('"')
                {
                    handled.push(&rest[..end]);
                }
            }
        }
        handled.retain(|c| c.starts_with('/') && c.len() > 1);
        assert!(handled.len() > 20);
        for command in handled {
            assert!(
                listed.contains(&command),
                "{command} is handled but not in the help"
            );
        }
        // The two special cases handled before the command match.
        assert!(listed.contains(&"/paste") && listed.contains(&"/decline"));
    }
}
