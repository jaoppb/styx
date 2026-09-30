//! EDNS(0) buffer size newtype and validation.

use crate::domain::error::ConfigError;

/// Validated EDNS(0) advertised UDP buffer size.
///
/// Must be between the RFC 1035 pre-EDNS minimum floor of 512 octets and
/// the UDP receive buffer ceiling of 4,096 octets.
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

    /// Maximum supported EDNS buffer size in octets matching the UDP receive buffer.
    pub const MAX_CEILING: u16 = 4096;

    /// Validates and constructs an `EdnsBufferSize`.
    ///
    /// # Errors
    /// Returns [`ConfigError::EdnsBufferTooSmall`] if `octets` is below 512,
    /// or [`ConfigError::EdnsBufferTooLarge`] if `octets` exceeds 4096.
    pub fn new(octets: u16) -> Result<Self, ConfigError> {
        if octets < Self::MIN_FLOOR {
            Err(ConfigError::EdnsBufferTooSmall(octets))
        } else if octets > Self::MAX_CEILING {
            Err(ConfigError::EdnsBufferTooLarge(octets))
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
        assert!(matches!(
            EdnsBufferSize::new(511),
            Err(ConfigError::EdnsBufferTooSmall(511))
        ));
        assert_eq!(EdnsBufferSize::new(512).unwrap().octets(), 512);
        assert_eq!(EdnsBufferSize::new(4096).unwrap().octets(), 4096);
        assert!(matches!(
            EdnsBufferSize::new(4097),
            Err(ConfigError::EdnsBufferTooLarge(4097))
        ));
    }
}
