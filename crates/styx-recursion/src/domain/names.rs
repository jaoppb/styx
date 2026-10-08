//! Name arithmetic the descent needs and `styx-proto` does not provide.

use styx_proto::Name;

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
}
