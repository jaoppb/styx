//! Name arithmetic beyond the wire codec: DNAME substitution and strict parsing of
//! an uncompressed wire name, shared by the recursor and the cache's bailiwick rules.

use super::{Label, Name, MAX_LABEL_LEN, MAX_NAME_LEN};

impl Name {
    /// DNAME substitution (RFC 6672 §2.2): this name, which lies strictly below
    /// `owner`, with `owner` replaced by `target`. `None` when this name is not
    /// strictly below `owner` or the result would exceed the 255-octet limit.
    #[must_use]
    pub fn substitute_suffix(&self, owner: &Self, target: &Self) -> Option<Self> {
        if self.eq_ignore_case(owner) || !self.is_subdomain_of(owner) {
            return None;
        }
        let keep = self.label_count().checked_sub(owner.label_count())?;
        let mut labels: Vec<Label> = self
            .labels()
            .take(keep)
            .map(|label| label.to_owned_label())
            .collect();
        labels.extend(target.labels().map(|label| label.to_owned_label()));
        Self::new(labels).ok()
    }

    /// The ancestor of this name, or the name itself, that keeps only its rightmost
    /// `label_count` labels: `ancestor(1)` of `www.example.com.` is `com.`, and
    /// `ancestor(0)` is the root. `None` when `label_count` exceeds this name's.
    #[must_use]
    pub fn ancestor(&self, label_count: usize) -> Option<Self> {
        let skip = self.label_count().checked_sub(label_count)?;
        let start = match self.label_offsets().nth(skip) {
            Some(offset) => offset,
            None => self.wire.len().checked_sub(1)?,
        };
        Some(Self {
            wire: Box::from(self.wire.get(start..)?),
        })
    }

    /// Parses an uncompressed wire-format name occupying exactly `octets`, as in
    /// DNAME RDATA (RFC 6672 §2.1: the target is never compressed).
    ///
    /// The octets are hostile input, so every offset is bounds-checked and anything
    /// unexpected — a compression pointer, an over-long label, trailing bytes, a
    /// name over 255 octets, a missing terminator — yields `None` rather than a
    /// guess.
    #[must_use]
    pub fn from_uncompressed_wire(octets: &[u8]) -> Option<Self> {
        if octets.len() > MAX_NAME_LEN {
            return None;
        }
        let mut labels = Vec::new();
        let mut offset = 0usize;
        loop {
            let length = usize::from(*octets.get(offset)?);
            let start = offset.checked_add(1)?;
            if length == 0 {
                return (start == octets.len()).then(|| Self::new(labels).ok())?;
            }
            if length > MAX_LABEL_LEN {
                return None;
            }
            let end = start.checked_add(length)?;
            labels.push(Label::new(octets.get(start..end)?.to_vec()).ok()?);
            offset = end;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn dname_substitution_swaps_the_suffix() {
        let rewritten = name("www.old.example.")
            .substitute_suffix(&name("old.example."), &name("new.example.net."));
        assert_eq!(rewritten, Some(name("www.new.example.net.")));
        assert_eq!(
            name("old.example.").substitute_suffix(&name("old.example."), &name("x.")),
            None
        );
    }

    #[test]
    fn ancestor_keeps_the_rightmost_labels() {
        let www = name("www.Example.com.");
        assert_eq!(www.ancestor(3), Some(www.clone()));
        assert_eq!(www.ancestor(2), Some(name("example.com.")));
        assert_eq!(www.ancestor(1), Some(name("com.")));
        assert_eq!(www.ancestor(0), Some(Name::root()));
        assert_eq!(www.ancestor(4), None);
        assert_eq!(Name::root().ancestor(0), Some(Name::root()));
    }

    #[test]
    fn wire_names_parse_strictly() {
        assert_eq!(
            Name::from_uncompressed_wire(&[3, b'w', b'w', b'w', 0]),
            Some(name("www."))
        );
        assert_eq!(Name::from_uncompressed_wire(&[0]), Some(Name::root()));
        assert_eq!(Name::from_uncompressed_wire(&[0xC0, 0x0C]), None, "pointer");
        assert_eq!(
            Name::from_uncompressed_wire(&[3, b'a', b'b']),
            None,
            "short"
        );
        assert_eq!(
            Name::from_uncompressed_wire(&[1, b'a', 0, 9]),
            None,
            "trailing"
        );
        assert_eq!(
            Name::from_uncompressed_wire(&[1, b'a']),
            None,
            "unterminated"
        );
        assert_eq!(Name::from_uncompressed_wire(&[]), None);
    }
}
