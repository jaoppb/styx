//! Domain name representation and invariants.
//!
//! Enforces RFC 1035 ceilings at construction:
//! - Labels are at most 63 octets.
//! - Names are at most 255 octets in wire format.
//!
//! In accordance with RFC 1035 §2.3.3 and Phase 4/Phase 6 requirements, [`Name`]
//! preserves original case but compares and hashes case-insensitively.

use std::fmt;
use std::hash::{Hash, Hasher};

use crate::domain::error::NameError;

/// Maximum length of an RFC 1035 label in octets.
pub const MAX_LABEL_LEN: usize = 63;

/// Maximum length of an RFC 1035 domain name in wire format in octets.
pub const MAX_NAME_LEN: usize = 255;

/// An individual DNS label with validated length (1..=63 octets).
#[derive(Clone, Eq)]
pub struct Label {
    octets: Vec<u8>,
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
        write!(f, "Label(\"{}\")", self)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in &self.octets {
            if b == b'.' || b == b'\\' || b == b' ' {
                write!(f, "\\{}", b as char)?;
            } else if b.is_ascii_graphic() {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "\\{:03}", b)?;
            }
        }
        Ok(())
    }
}

/// A validated DNS domain name.
///
/// An empty list of labels represents the DNS root domain (`.`).
#[derive(Clone, Eq)]
pub struct Name {
    labels: Vec<Label>,
}

impl Name {
    /// Returns the root domain name (`.`).
    #[must_use]
    pub fn root() -> Self {
        Self { labels: Vec::new() }
    }

    /// Creates a name from a sequence of labels.
    ///
    /// # Errors
    ///
    /// Returns [`NameError::NameTooLong`] if the total wire format length exceeds 255 octets.
    pub fn new(labels: Vec<Label>) -> Result<Self, NameError> {
        let name = Self { labels };
        if name.wire_len() > MAX_NAME_LEN {
            return Err(NameError::NameTooLong(name.wire_len()));
        }
        Ok(name)
    }

    /// Returns a slice of the labels forming this name, from left to right.
    #[must_use]
    pub fn labels(&self) -> &[Label] {
        &self.labels
    }

    /// Returns the number of non-root labels in this domain name.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    /// Returns true if this is the root domain (`.`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Computes the exact length in octets of this name when encoded on the wire.
    ///
    /// Includes the length octet for each label and the terminating zero octet.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        let mut total: usize = 1; // terminating root octet
        for l in &self.labels {
            let next = total.checked_add(1).and_then(|t| t.checked_add(l.len()));
            match next {
                Some(t) => total = t,
                None => return usize::MAX,
            }
        }
        total
    }

    /// Returns the parent domain name, or `None` if this is already root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.labels.is_empty() {
            return None;
        }
        let mut parent_labels = self.labels.clone();
        if !parent_labels.is_empty() {
            parent_labels.remove(0);
        }
        Some(Self {
            labels: parent_labels,
        })
    }

    /// Returns true if this name is in or equal to `other` (bailiwick check).
    #[must_use]
    pub fn is_subdomain_of(&self, other: &Self) -> bool {
        if other.labels.len() > self.labels.len() {
            return false;
        }
        let offset = match self.labels.len().checked_sub(other.labels.len()) {
            Some(diff) => diff,
            None => return false,
        };
        for (i, other_label) in other.labels.iter().enumerate() {
            let self_idx = match offset.checked_add(i) {
                Some(idx) => idx,
                None => return false,
            };
            let Some(self_label) = self.labels.get(self_idx) else {
                return false;
            };
            if !self_label.eq_ignore_case(other_label) {
                return false;
            }
        }
        true
    }

    /// Returns a new [`Name`] with all labels lowercased for RFC 4034 canonical form.
    #[must_use]
    pub fn to_canonical(&self) -> Self {
        Self {
            labels: self.labels.iter().map(Label::as_lowercase).collect(),
        }
    }

    /// Compares two names case-insensitively.
    #[must_use]
    pub fn eq_ignore_case(&self, other: &Self) -> bool {
        if self.labels.len() != other.labels.len() {
            return false;
        }
        for (a, b) in self.labels.iter().zip(other.labels.iter()) {
            if !a.eq_ignore_case(b) {
                return false;
            }
        }
        true
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
        let mut labels = Vec::new();
        for part in trimmed.split('.') {
            let parsed_octets = parse_escaped_label(part)?;
            labels.push(Label::new(parsed_octets)?);
        }
        Self::new(labels)
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
        self.labels.len().hash(state);
        for l in &self.labels {
            l.hash(state);
        }
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name(\"{}\")", self)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.labels.is_empty() {
            return write!(f, ".");
        }
        for l in &self.labels {
            write!(f, "{}.", l)?;
        }
        Ok(())
    }
}
