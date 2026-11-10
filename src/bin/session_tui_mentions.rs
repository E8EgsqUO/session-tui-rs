//! Group mentions. On the wire a mention is `@` followed by the member's
//! Session ID (66 hex characters), as in the official clients; here it is
//! typed and shown as `@Name`.

use std::borrow::Cow;

/// Length of a Session ID in hex.
const ID_LEN: usize = 66;

fn is_session_id(text: &str) -> bool {
    text.len() == ID_LEN && text.starts_with("05") && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Show `@<session id>` as `@<name>`.
pub fn display<'a>(body: &'a str, name_of: impl Fn(&str) -> String) -> Cow<'a, str> {
    if !body.contains("@05") {
        return Cow::Borrowed(body);
    }
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find("@05") {
        out.push_str(&rest[..=at]);
        let after = &rest[at + 1..];
        match after.get(..ID_LEN).filter(|id| is_session_id(id)) {
            Some(id) => {
                out.push_str(&name_of(id));
                rest = &after[ID_LEN..];
            }
            None => rest = after,
        }
    }
    out.push_str(rest);
    Cow::Owned(out)
}

/// Turn typed `@Name` into `@<session id>` for the group's members
/// (`(name, id)`). The longest matching name wins, and a name must end at a
/// word boundary, so `@Ann` does not match inside `@Anna`.
pub fn expand(body: &str, members: &[(String, String)]) -> String {
    if !body.contains('@') || members.is_empty() {
        return body.to_owned();
    }
    let mut names: Vec<&(String, String)> = members.iter().filter(|(n, _)| !n.is_empty()).collect();
    names.sort_by_key(|(name, _)| std::cmp::Reverse(name.len()));
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some(at) = rest.find('@') {
        out.push_str(&rest[..=at]);
        let after = &rest[at + 1..];
        let hit = names.iter().find(|(name, _)| {
            after.starts_with(name.as_str())
                && !after[name.len()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphanumeric)
        });
        match hit {
            Some((name, id)) => {
                out.push_str(id);
                rest = &after[name.len()..];
            }
            None => rest = after,
        }
    }
    out.push_str(rest);
    out
}

/// Tab on `@prefix` right before the cursor: the new input and cursor, and
/// the names that matched (several: completed to their common prefix).
pub fn complete(
    input: &str,
    cursor: usize,
    names: &[String],
) -> Option<(String, usize, Vec<String>)> {
    let before = input.get(..cursor)?;
    let at = before.rfind('@')?;
    let typed = &before[at + 1..];
    if typed.contains(char::is_whitespace)
        || before[..at]
            .chars()
            .next_back()
            .is_some_and(|c| !c.is_whitespace())
    {
        return None;
    }
    let lower = typed.to_lowercase();
    let mut matches: Vec<String> = names
        .iter()
        .filter(|name| !name.is_empty() && name.to_lowercase().starts_with(&lower))
        .cloned()
        .collect();
    matches.sort();
    matches.dedup();
    let replacement = match matches.as_slice() {
        [] => return None,
        [only] => format!("{only} "),
        many => {
            let first = &many[0];
            let common = first
                .char_indices()
                .map(|(i, c)| i + c.len_utf8())
                .take_while(|end| many.iter().all(|m| m.starts_with(&first[..*end])))
                .last()
                .unwrap_or(0);
            first[..common].to_owned()
        }
    };
    let new_input = format!("{}{replacement}{}", &input[..=at], &input[cursor..]);
    Some((new_input, at + 1 + replacement.len(), matches))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(byte: &str) -> String {
        format!("05{}", byte.repeat(32))
    }

    #[test]
    fn mentions_round_trip_between_names_and_ids() {
        let members = vec![
            ("Ann".to_owned(), id("aa")),
            ("Anna Lee".to_owned(), id("bb")),
        ];
        let wire = expand("hi @Anna Lee, @Ann! not @Annabel or a@b", &members);
        assert_eq!(
            wire,
            format!("hi @{}, @{}! not @Annabel or a@b", id("bb"), id("aa"))
        );
        let shown = display(&wire, |i| {
            if i == id("aa") {
                "Ann".into()
            } else {
                "Anna Lee".into()
            }
        });
        assert_eq!(shown, "hi @Anna Lee, @Ann! not @Annabel or a@b");
        // Not a full Session ID: left alone, and multi-byte text is safe.
        assert_eq!(display("@05abc é@05", |_| "x".into()), "@05abc é@05");
        assert_eq!(expand("é@é", &members), "é@é");
    }

    #[test]
    fn tab_completes_a_member_name() {
        let names = vec!["Anna".to_owned(), "Andy".to_owned(), "Bob".to_owned()];
        assert_eq!(
            complete("hey @b", 6, &names),
            Some(("hey @Bob ".into(), 9, vec!["Bob".into()]))
        );
        let (input, cursor, matches) = complete("@a tail", 2, &names).unwrap();
        assert_eq!((input.as_str(), cursor, matches.len()), ("@An tail", 3, 2));
        assert_eq!(complete("mail@a", 6, &names), None);
        assert_eq!(complete("@zed", 4, &names), None);
    }
}
