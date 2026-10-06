//! Name arithmetic the descent needs and `styx-proto` does not provide.

use styx_proto::{Label, Name, MAX_LABEL_LEN, MAX_NAME_LEN};

/// The ancestor of `name` with exactly `labels` non-root labels, or `name` itself
/// when it has no more than that.
#[must_use]
pub fn ancestor_with_labels(name: &Name, labels: usize) -> Name {
    let mut current = name.clone();
    while current.label_count() > labels {
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }
    current
}

/// DNAME substitution (RFC 6672 §2.2): `name`, which lies strictly below `owner`,
/// with `owner` replaced by `target`. `None` when `name` is not strictly below
/// `owner` or the result would exceed the 255-octet name limit.
#[must_use]
pub fn substitute_suffix(name: &Name, owner: &Name, target: &Name) -> Option<Name> {
    if name.eq_ignore_case(owner) || !name.is_subdomain_of(owner) {
        return None;
    }
    let keep = name.label_count().checked_sub(owner.label_count())?;
    let mut labels: Vec<Label> = name
        .labels()
        .take(keep)
        .map(|label| label.to_owned_label())
        .collect();
    labels.extend(target.labels().map(|label| label.to_owned_label()));
    Name::new(labels).ok()
}

/// Parses an uncompressed wire-format name occupying exactly `octets`, as in DNAME
/// RDATA (RFC 6672 §2.1: the target is never compressed).
///
/// The octets are hostile input, so every offset is bounds-checked and anything
/// unexpected — a compression pointer, an over-long label, trailing bytes, a name
/// over 255 octets, a missing terminator — yields `None` rather than a guess.
#[must_use]
pub fn parse_uncompressed_name(octets: &[u8]) -> Option<Name> {
    if octets.len() > MAX_NAME_LEN {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = 0usize;
    loop {
        let length = usize::from(*octets.get(offset)?);
        let start = offset.checked_add(1)?;
        if length == 0 {
            return (start == octets.len()).then(|| Name::new(labels).ok())?;
        }
        if length > MAX_LABEL_LEN {
            return None;
        }
        let end = start.checked_add(length)?;
        labels.push(Label::new(octets.get(start..end)?.to_vec()).ok()?);
        offset = end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn ancestors_are_cut_from_the_left() {
        let full = name("a.b.example.com.");
        assert_eq!(ancestor_with_labels(&full, 0), Name::root());
        assert_eq!(ancestor_with_labels(&full, 1), name("com."));
        assert_eq!(ancestor_with_labels(&full, 3), name("b.example.com."));
        assert_eq!(ancestor_with_labels(&full, 9), full);
    }

    #[test]
    fn dname_substitution_swaps_the_suffix() {
        let rewritten = substitute_suffix(
            &name("www.old.example."),
            &name("old.example."),
            &name("new.example.net."),
        );
        assert_eq!(rewritten, Some(name("www.new.example.net.")));
        assert_eq!(
            substitute_suffix(&name("old.example."), &name("old.example."), &name("x.")),
            None
        );
    }

    #[test]
    fn wire_names_parse_strictly() {
        assert_eq!(
            parse_uncompressed_name(&[3, b'w', b'w', b'w', 0]),
            Some(name("www."))
        );
        assert_eq!(parse_uncompressed_name(&[0]), Some(Name::root()));
        assert_eq!(parse_uncompressed_name(&[0xC0, 0x0C]), None, "pointer");
        assert_eq!(parse_uncompressed_name(&[3, b'a', b'b']), None, "short");
        assert_eq!(parse_uncompressed_name(&[1, b'a', 0, 9]), None, "trailing");
        assert_eq!(parse_uncompressed_name(&[1, b'a']), None, "unterminated");
        assert_eq!(parse_uncompressed_name(&[]), None);
    }
}
