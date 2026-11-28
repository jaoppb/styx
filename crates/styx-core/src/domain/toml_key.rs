//! TOML key formatting for configuration error messages that name a table to edit.

use std::fmt::Write as _;

/// Formats `name` as a TOML key: as written when it is a bare key (`[A-Za-z0-9_-]+`),
/// otherwise as a basic string with quotes, backslashes and control characters escaped,
/// so an error message can show a table header the reader can paste into the file.
#[must_use]
pub fn format_toml_key(name: &str) -> String {
    if !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return name.to_owned();
    }
    let mut quoted = String::with_capacity(name.len().saturating_add(2));
    quoted.push('"');
    for character in name.chars() {
        match character {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '\u{08}' => quoted.push_str("\\b"),
            '\t' => quoted.push_str("\\t"),
            '\n' => quoted.push_str("\\n"),
            '\u{0C}' => quoted.push_str("\\f"),
            '\r' => quoted.push_str("\\r"),
            other if other.is_ascii_control() => {
                let _ = write!(quoted, "\\u{:04X}", u32::from(other));
            }
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_keys_are_left_as_written() {
        assert_eq!(format_toml_key("recursor-v4_1"), "recursor-v4_1");
    }

    #[test]
    fn other_keys_are_quoted_and_escaped() {
        assert_eq!(format_toml_key("rec.v4"), r#""rec.v4""#);
        assert_eq!(format_toml_key(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(format_toml_key("tab\there"), r#""tab\there""#);
        assert_eq!(format_toml_key("\u{1}"), r#""\u0001""#);
        assert_eq!(format_toml_key(""), r#""""#);
    }

    #[test]
    fn control_characters_take_their_short_escape_or_a_unicode_escape() {
        assert_eq!(format_toml_key("a\nb"), r#""a\nb""#);
        assert_eq!(format_toml_key("\r"), r#""\r""#);
        assert_eq!(format_toml_key("\u{08}"), r#""\b""#);
        assert_eq!(format_toml_key("\u{0C}"), r#""\f""#);
        assert_eq!(format_toml_key("\u{7f}"), r#""\u007F""#);
    }

    #[test]
    fn spaces_and_non_ascii_names_are_quoted_but_not_escaped() {
        assert_eq!(format_toml_key("rec v4"), r#""rec v4""#);
        assert_eq!(format_toml_key("é"), r#""é""#);
    }
}
