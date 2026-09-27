//! EDNS(0) buffer size newtype and validation.

use crate::domain::error::ConfigError;

/// Validated EDNS(0) advertised UDP buffer size.
///
/// Must be at or above the RFC 1035 pre-EDNS minimum floor of 512 octets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EdnsBufferSize(u16);

impl Default for EdnsBufferSize {
    fn default() -> Self {
        Self(1232)
    }
}

impl EdnsBufferSize {
    /// Minimum legal EDNS buffer size in octets.
    pub const MIN_FLOOR: u16 = 512;

    /// Validates and constructs an `EdnsBufferSize`.
    ///
    /// # Errors
    /// Returns [`ConfigError::EdnsBufferTooSmall`] if `octets` is below 512.
    pub fn new(octets: u16) -> Result<Self, ConfigError> {
        if octets < Self::MIN_FLOOR {
            Err(ConfigError::EdnsBufferTooSmall(octets))
        } else {
            Ok(Self(octets))
        }
    }

    /// Returns the buffer size in octets.
    #[must_use]
    pub const fn octets(&self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edns_buffer_size_validation() {
        assert!(EdnsBufferSize::new(511).is_err());
        assert_eq!(EdnsBufferSize::new(512).unwrap().octets(), 512);
        assert_eq!(EdnsBufferSize::new(4096).unwrap().octets(), 4096);
    }
}
