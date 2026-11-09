//! Multi-line composer editing: a text buffer with a byte-offset cursor,
//! plus soft-wrapping into terminal rows for display.

use unicode_width::UnicodeWidthChar;

/// Clamp `cursor` into `text` and onto a char boundary.
pub fn clamp(text: &str, cursor: usize) -> usize {
    let mut cursor = cursor.min(text.len());
    while !text.is_char_boundary(cursor) {
        cursor -= 1;
    }
    cursor
}

pub fn insert(text: &mut String, cursor: &mut usize, insert: &str) {
    *cursor = clamp(text, *cursor);
    text.insert_str(*cursor, insert);
    *cursor += insert.len();
}

fn prev_boundary(text: &str, cursor: usize) -> Option<usize> {
    text[..cursor]
        .char_indices()
        .next_back()
        .map(|(index, _)| index)
}

fn next_boundary(text: &str, cursor: usize) -> Option<usize> {
    text[cursor..].chars().next().map(|c| cursor + c.len_utf8())
}

pub fn backspace(text: &mut String, cursor: &mut usize) {
    *cursor = clamp(text, *cursor);
    if let Some(previous) = prev_boundary(text, *cursor) {
        text.replace_range(previous..*cursor, "");
        *cursor = previous;
    }
}

pub fn delete(text: &mut String, cursor: &mut usize) {
    *cursor = clamp(text, *cursor);
    if let Some(next) = next_boundary(text, *cursor) {
        text.replace_range(*cursor..next, "");
    }
}

/// Delete the word before the cursor (Ctrl+W).
pub fn delete_word(text: &mut String, cursor: &mut usize) {
    *cursor = clamp(text, *cursor);
    let before = &text[..*cursor];
    let trimmed = before.trim_end_matches([' ', '\t']);
    let start = trimmed
        .rfind(|c: char| c.is_whitespace())
        .map(|index| index + trimmed[index..].chars().next().map_or(1, char::len_utf8))
        .unwrap_or(0);
    text.replace_range(start..*cursor, "");
    *cursor = start;
}

pub fn left(text: &str, cursor: &mut usize) {
    *cursor = prev_boundary(text, clamp(text, *cursor)).unwrap_or(0);
}

pub fn right(text: &str, cursor: &mut usize) {
    let current = clamp(text, *cursor);
    *cursor = next_boundary(text, current).unwrap_or(current);
}

fn line_start(text: &str, cursor: usize) -> usize {
    text[..cursor].rfind('\n').map_or(0, |index| index + 1)
}

fn line_end(text: &str, cursor: usize) -> usize {
    text[cursor..]
        .find('\n')
        .map_or(text.len(), |index| cursor + index)
}

pub fn home(text: &str, cursor: &mut usize) {
    *cursor = line_start(text, clamp(text, *cursor));
}

pub fn end(text: &str, cursor: &mut usize) {
    *cursor = line_end(text, clamp(text, *cursor));
}

/// Move to the previous (`up`) or next logical line, keeping the column in
/// characters. Returns false when there is no such line.
pub fn vertical(text: &str, cursor: &mut usize, up: bool) -> bool {
    let current = clamp(text, *cursor);
    let start = line_start(text, current);
    let column = text[start..current].chars().count();
    let target_start = if up {
        if start == 0 {
            return false;
        }
        line_start(text, start - 1)
    } else {
        let end = line_end(text, current);
        if end == text.len() {
            return false;
        }
        end + 1
    };
    let target_end = line_end(text, target_start);
    *cursor = text[target_start..target_end]
        .char_indices()
        .nth(column)
        .map_or(target_end, |(index, _)| target_start + index);
    true
}

/// Soft-wrap `text` into rows of at most `width` columns. Returns the rows
/// and the (row, column) of `cursor`.
pub fn wrap(text: &str, cursor: usize, width: usize) -> (Vec<String>, (usize, usize)) {
    let width = width.max(2);
    let cursor = clamp(text, cursor);
    let mut rows = vec![String::new()];
    let mut column = 0;
    let mut position = (0, 0);
    for (index, c) in text.char_indices() {
        if index == cursor {
            position = (rows.len() - 1, column);
        }
        if c == '\n' {
            rows.push(String::new());
            column = 0;
            continue;
        }
        let w = c.width().unwrap_or(0);
        if column + w > width {
            rows.push(String::new());
            column = 0;
            if index == cursor {
                position = (rows.len() - 1, 0);
            }
        }
        rows.last_mut().expect("at least one row").push(c);
        column += w;
    }
    if cursor == text.len() {
        if column >= width {
            rows.push(String::new());
            column = 0;
        }
        position = (rows.len() - 1, column);
    }
    (rows, position)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_handles_multibyte_text() {
        let mut text = String::new();
        let mut cursor = 0;
        insert(&mut text, &mut cursor, "你好");
        left(&text, &mut cursor);
        insert(&mut text, &mut cursor, "a");
        assert_eq!(text, "你a好");
        backspace(&mut text, &mut cursor);
        assert_eq!((text.as_str(), cursor), ("你好", 3));
        delete(&mut text, &mut cursor);
        assert_eq!(text, "你");
        right(&text, &mut cursor);
        right(&text, &mut cursor);
        assert_eq!(cursor, text.len());
    }

    #[test]
    fn vertical_moves_keep_the_column() {
        let text = "abcd\nxy\n12345";
        let mut cursor = 3; // after "abc"
        assert!(vertical(text, &mut cursor, false));
        assert_eq!(cursor, 7); // end of "xy"
        assert!(vertical(text, &mut cursor, false));
        assert_eq!(cursor, 10); // "12|345"
        assert!(!vertical(text, &mut cursor, false));
        assert!(vertical(text, &mut cursor, true));
        home(text, &mut cursor);
        assert_eq!(cursor, 5);
        end(text, &mut cursor);
        assert_eq!(cursor, 7);
    }

    #[test]
    fn delete_word_removes_previous_word() {
        let mut text = "hello big world".to_owned();
        let mut cursor = text.len();
        delete_word(&mut text, &mut cursor);
        assert_eq!(text, "hello big ");
        delete_word(&mut text, &mut cursor);
        assert_eq!(text, "hello ");
    }

    #[test]
    fn wrap_tracks_cursor_with_wide_chars_and_newlines() {
        let (rows, position) = wrap("ab\n你好世界", 9, 4);
        assert_eq!(rows, vec!["ab", "你好", "世界"]);
        assert_eq!(position, (2, 0)); // cursor before 世 → start of row 2
        let (rows, position) = wrap("abcd", 4, 4);
        assert_eq!(rows, vec!["abcd", ""]);
        assert_eq!(position, (1, 0));
        let (_, position) = wrap("", 0, 4);
        assert_eq!(position, (0, 0));
    }
}
