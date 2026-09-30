//! Domain name representation and invariants.
//!
//! Enforces RFC 1035 ceilings at construction:
//! - Labels are at most 63 octets.
//! - Names are at most 255 octets in wire format.
//!
//! In accordance with RFC 1035 §2.3.3 and Phase 4/Phase 6 requirements, [`Name`]
//! preserves original case but compares and hashes case-insensitively.

mod label;

pub use label::{Label, LabelIter, LabelOffsets, LabelRef};

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::domain::error::NameError;

/// Maximum length of an RFC 1035 label in octets.
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum length of an RFC 1035 domain name in wire format in octets.
pub const MAX_NAME_LEN: usize = 255;

/// A validated DNS domain name stored in RFC 1035 wire format.
#[derive(Clone, Eq)]
pub struct Name {
    wire: Box<[u8]>,
}

impl Name {
    /// Returns the root domain name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self {
            wire: Box::new([0]),
        }
    }

    /// Constructs a `Name` from a validated wire buffer.
    #[must_use]
    pub const fn from_wire(wire: Box<[u8]>) -> Self {
        Self { wire }
    }

    /// Creates a name from a sequence of labels.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::NameTooLong`] if total wire length exceeds 255 octets.
    pub fn new(labels: Vec<Label>) -> Result<Self, NameError> {
        let mut total_len = 1usize;
        for l in &labels {
            total_len = total_len
                .checked_add(1)
                .and_then(|t| t.checked_add(l.len()))
                .ok_or(NameError::NameTooLong(MAX_NAME_LEN.saturating_add(1)))?;
        }
        if total_len > MAX_NAME_LEN {
            return Err(NameError::NameTooLong(total_len));
        }
        let mut wire = Vec::with_capacity(total_len);
        for l in labels {
            let len_u8 = match u8::try_from(l.len()) {
                Ok(len) => len,
                Err(_) => return Err(NameError::LabelTooLong(l.len())),
            };
            wire.push(len_u8);
            wire.extend_from_slice(l.as_bytes());
        }
        wire.push(0);
        Ok(Self {
            wire: wire.into_boxed_slice(),
        })
    }

    /// Returns an iterator over the labels of this domain name, from left to right.
    #[must_use]
    pub fn labels(&self) -> LabelIter<'_> {
        LabelIter::new(&self.wire)
    }

    /// Returns an iterator over the byte offsets of each label in this name.
    #[must_use]
    pub fn label_offsets(&self) -> LabelOffsets<'_> {
        LabelOffsets {
            wire: &self.wire,
            offset: 0,
        }
    }

    /// Returns the number of non-root labels in this domain name.
    #[must_use]
    pub fn label_count(&self) -> usize {
        let mut count = 0usize;
        let mut offset = 0usize;
        while let Some(&len) = self.wire.get(offset) {
            if len == 0 {
                break;
            }
            count = count.saturating_add(1);
            let next = match offset
                .checked_add(1)
                .and_then(|o| o.checked_add(usize::from(len)))
            {
                Some(n) => n,
                None => break,
            };
            if next > self.wire.len() {
                break;
            }
            offset = next;
        }
        count
    }

    /// Returns true if this is the root domain (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.wire.as_ref() == [0]
    }

    /// Computes the exact length in octets of this name when encoded on the wire.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Returns the wire-format representation of this name.
    #[must_use]
    pub fn as_wire_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Consumes the name and returns its wire-format bytes.
    #[must_use]
    pub fn into_wire(self) -> Box<[u8]> {
        self.wire
    }

    /// Returns a lowercased wire-format byte vector for hashing and compression.
    #[must_use]
    pub fn to_lowercase_wire(&self) -> Vec<u8> {
        self.wire.iter().map(u8::to_ascii_lowercase).collect()
    }

    /// Returns the parent domain name, or `None` if this is already root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        let &first_len = self.wire.first()?;
        if first_len == 0 {
            return None;
        }
        let next_offset = 1usize.checked_add(usize::from(first_len))?;
        let parent_wire = self.wire.get(next_offset..)?;
        Some(Self {
            wire: Box::from(parent_wire),
        })
    }

    /// Returns true if this name is in or equal to `other` (bailiwick check).
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        if other.is_root() {
            return true;
        }
        if other.wire.len() > self.wire.len() {
            return false;
        }
        for offset in self.label_offsets() {
            let matches = self
                .wire
                .get(offset..)
                .is_some_and(|slice| slice.eq_ignore_ascii_case(&other.wire));
            if matches {
                return true;
            }
        }
        false
    }

    /// Returns a new [`Name`] with all labels lowercased for RFC 4034 canonical form.
    #[must_use]
    pub fn to_canonical(&self) -> Self {
        Self {
            wire: self.to_lowercase_wire().into_boxed_slice(),
        }
    }

    /// Compares two names case-insensitively.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }

    /// Parses a domain name from presentation format (RFC 1035 §5.1).
    ///
    /// # Errors
    ///
    /// Returns [`NameError`] if a label is empty, exceeds 63 octets, or wire length > 255.
    pub fn from_ascii(s: &str) -> Result<Self, NameError> {
        if s.is_empty() || s == "." {
            return Ok(Self::root());
        }
        let trimmed = match s.strip_suffix('.') {
            Some(t) => t,
            None => s,
        };
        if trimmed.is_empty() {
            return Ok(Self::root());
        }
        let mut wire = Vec::with_capacity(trimmed.len().saturating_add(2));
        for part in trimmed.split('.') {
            let parsed_octets = parse_escaped_label(part)?;
            if parsed_octets.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if parsed_octets.len() > MAX_LABEL_LEN {
                return Err(NameError::LabelTooLong(parsed_octets.len()));
            }
            let len_u8 = match u8::try_from(parsed_octets.len()) {
                Ok(l) => l,
                Err(_) => return Err(NameError::LabelTooLong(parsed_octets.len())),
            };
            wire.push(len_u8);
            wire.extend_from_slice(&parsed_octets);
        }
        wire.push(0);
        if wire.len() > MAX_NAME_LEN {
            return Err(NameError::NameTooLong(wire.len()));
        }
        Ok(Self {
            wire: wire.into_boxed_slice(),
        })
    }
}

/// Parses presentation escapes in a label string.
fn parse_escaped_label(s: &str) -> Result<Vec<u8>, NameError> {
    let mut bytes = Vec::with_capacity(s.len());
    let mut chars = s.bytes().peekable();
    while let Some(b) = chars.next() {
        if b != b'\\' {
            bytes.push(b);
            continue;
        }
        let Some(escaped) = chars.next() else {
            return Err(NameError::NonAsciiInPresentation);
        };
        if escaped.is_ascii_digit() {
            let d1 = escaped.wrapping_sub(b'0');
            let Some(c2) = chars.next().filter(u8::is_ascii_digit) else {
                return Err(NameError::NonAsciiInPresentation);
            };
            let Some(c3) = chars.next().filter(u8::is_ascii_digit) else {
                return Err(NameError::NonAsciiInPresentation);
            };
            let d2 = c2.wrapping_sub(b'0');
            let d3 = c3.wrapping_sub(b'0');
            let val = u32::from(d1)
                .checked_mul(100)
                .and_then(|v| v.checked_add(u32::from(d2).checked_mul(10)?))
                .and_then(|v| v.checked_add(u32::from(d3)))
                .ok_or(NameError::NonAsciiInPresentation)?;
            let octet = u8::try_from(val).map_err(|_| NameError::NonAsciiInPresentation)?;
            bytes.push(octet);
        } else {
            bytes.push(escaped);
        }
    }
    Ok(bytes)
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.eq_ignore_case(other)
    }
}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for &b in &self.wire {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name(\"{self}\")")
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return write!(f, ".");
        }
        for l in self.labels() {
            write!(f, "{l}.")?;
        }
        Ok(())
    }
}
