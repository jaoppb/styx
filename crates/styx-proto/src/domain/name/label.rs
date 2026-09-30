//! DNS label representation and iteration.

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::domain::error::NameError;
use crate::domain::name::MAX_LABEL_LEN;

/// An individual DNS label with validated length (1..=63 octets).
#[derive(Clone, Eq)]
pub struct Label {
    pub(crate) octets: Vec<u8>,
}

impl Label {
    /// Creates a new label from octets.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::EmptyLabel`] if empty, or [`NameError::LabelTooLong`]
    /// if length exceeds 63 octets.
    pub fn new(octets: Vec<u8>) -> Result<Self, NameError> {
        if octets.is_empty() {
            return Err(NameError::EmptyLabel);
        }
        if octets.len() > MAX_LABEL_LEN {
            return Err(NameError::LabelTooLong(octets.len()));
        }
        Ok(Self { octets })
    }

    /// Returns a slice of the label's raw octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.octets
    }

    /// Returns the length of the label in octets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.octets.len()
    }

    /// Returns whether the label has zero length (always false for valid labels).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// Returns an ASCII-lowercased copy of this label.
    #[must_use]
    pub fn as_lowercase(&self) -> Self {
        Self {
            octets: self.octets.iter().map(u8::to_ascii_lowercase).collect(),
        }
    }

    /// Compares two labels case-insensitively using ASCII rules.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        self.octets.eq_ignore_ascii_case(&other.octets)
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_case(other)
    }
}

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in &self.octets {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label(\"{self}\")")
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_escaped_octets(&self.octets, f)
    }
}

/// A borrowed view of a DNS label within a domain name's wire buffer.
#[derive(Clone, Copy, Eq)]
pub struct LabelRef<'a> {
    pub(crate) octets: &'a [u8],
}

impl<'a> LabelRef<'a> {
    /// Creates a new `LabelRef` wrapping a validated slice of octets (1..=63).
    #[must_use]
    pub const fn new(octets: &'a [u8]) -> Self {
        Self { octets }
    }

    /// Returns a slice of the label's raw octets.
    #[must_use]
    pub const fn as_bytes(&self) -> &'a [u8] {
        self.octets
    }

    /// Returns the length of the label in octets.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.octets.len()
    }

    /// Returns whether the label has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }

    /// Compares two labels case-insensitively using ASCII rules.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        self.octets.eq_ignore_ascii_case(other.octets)
    }

    /// Converts this borrowed label to an owned [`Label`].
    #[must_use]
    pub fn to_owned_label(&self) -> Label {
        Label {
            octets: self.octets.to_vec(),
        }
    }
}

impl PartialEq for LabelRef<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_case(other)
    }
}

impl PartialEq<Label> for LabelRef<'_> {
    fn eq(&self, other: &Label) -> bool {
        self.octets.eq_ignore_ascii_case(&other.octets)
    }
}

impl PartialEq<LabelRef<'_>> for Label {
    fn eq(&self, other: &LabelRef<'_>) -> bool {
        self.octets.eq_ignore_ascii_case(other.octets)
    }
}

impl Hash for LabelRef<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.octets {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl fmt::Debug for LabelRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LabelRef(\"{self}\")")
    }
}

impl fmt::Display for LabelRef<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_escaped_octets(self.octets, f)
    }
}

/// An iterator yielding byte offsets of each label in a domain name's wire representation.
pub struct LabelOffsets<'a> {
    pub(crate) wire: &'a [u8],
    pub(crate) offset: usize,
}

impl<'a> Iterator for LabelOffsets<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        let &len = self.wire.get(self.offset)?;
        if len == 0 {
            return None;
        }
        let current = self.offset;
        let next = self.offset.checked_add(1)?.checked_add(usize::from(len))?;
        if next > self.wire.len() {
            return None;
        }
        self.offset = next;
        Some(current)
    }
}

/// An iterator over the labels of a domain name.
pub struct LabelIter<'a> {
    wire: &'a [u8],
    offsets: [u8; 128],
    start: usize,
    end: usize,
}

impl<'a> LabelIter<'a> {
    /// Creates a new `LabelIter` over a domain name wire buffer.
    #[must_use]
    pub fn new(wire: &'a [u8]) -> Self {
        let mut offsets = [0u8; 128];
        let mut count = 0usize;
        let mut offset = 0usize;
        while let Some(&len) = wire.get(offset) {
            if len == 0 {
                break;
            }
            record_label_offset(&mut offsets, &mut count, offset);
            let next = match offset
                .checked_add(1)
                .and_then(|o| o.checked_add(usize::from(len)))
            {
                Some(n) => n,
                None => break,
            };
            if next > wire.len() {
                break;
            }
            offset = next;
        }
        Self {
            wire,
            offsets,
            start: 0,
            end: count,
        }
    }
}

fn record_label_offset(offsets: &mut [u8; 128], count: &mut usize, offset: usize) {
    let Ok(off_u8) = u8::try_from(offset) else {
        return;
    };
    let Some(slot) = offsets.get_mut(*count) else {
        return;
    };
    *slot = off_u8;
    *count = count.saturating_add(1);
}

impl<'a> Iterator for LabelIter<'a> {
    type Item = LabelRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }
        let &off = self.offsets.get(self.start)?;
        self.start = self.start.saturating_add(1);
        let offset = usize::from(off);
        let &len = self.wire.get(offset)?;
        let start = offset.checked_add(1)?;
        let end = start.checked_add(usize::from(len))?;
        let bytes = self.wire.get(start..end)?;
        Some(LabelRef { octets: bytes })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.end.saturating_sub(self.start);
        (rem, Some(rem))
    }
}

impl<'a> DoubleEndedIterator for LabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start >= self.end {
            return None;
        }
        self.end = self.end.saturating_sub(1);
        let &off = self.offsets.get(self.end)?;
        let offset = usize::from(off);
        let &len = self.wire.get(offset)?;
        let start = offset.checked_add(1)?;
        let end = start.checked_add(usize::from(len))?;
        let bytes = self.wire.get(start..end)?;
        Some(LabelRef { octets: bytes })
    }
}

impl<'a> ExactSizeIterator for LabelIter<'a> {}

pub(crate) fn format_escaped_octets(octets: &[u8], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for &b in octets {
        if b == b'.' || b == b'\\' || b == b' ' {
            write!(f, "\\{}", b as char)?;
        } else if b.is_ascii_graphic() {
            write!(f, "{}", b as char)?;
        } else {
            write!(f, "\\{b:03}")?;
        }
    }
    Ok(())
}
