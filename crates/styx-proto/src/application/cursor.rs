//! The single audited primitive for bounds-checked DNS wire buffer reads.
//!
//! All byte slice access routes through [`Cursor`]. No other module in the crate
//! is permitted to perform raw offset indexing.

use crate::domain::error::DecodeError;

/// A bounds-checked read cursor over a byte buffer.
#[derive(Debug, Clone)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    position: usize,
    len: usize,
}

impl<'a> Cursor<'a> {
    /// Creates a new cursor starting at position 0 over the given buffer.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            position: 0,
            len: buf.len(),
        }
    }

    /// Returns the current cursor position.
    #[must_use]
    pub fn position(&self) -> usize {
        self.position
    }

    /// Returns the total length of the underlying buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the buffer has zero length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the count of remaining bytes available to read.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.len.saturating_sub(self.position)
    }

    /// Advances the cursor by `n` octets without reading them.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if advancing by `n` exceeds the buffer.
    pub fn advance(&mut self, n: usize) -> Result<usize, DecodeError> {
        let prev = self.position;
        let next = prev
            .checked_add(n)
            .ok_or(DecodeError::UnexpectedEof(usize::MAX))?;
        if next > self.len {
            return Err(DecodeError::UnexpectedEof(next));
        }
        self.position = next;
        Ok(prev)
    }

    /// Repositions the cursor at an absolute offset.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if `offset > len`.
    pub fn seek(&mut self, offset: usize) -> Result<(), DecodeError> {
        if offset > self.len {
            return Err(DecodeError::UnexpectedEof(offset));
        }
        self.position = offset;
        Ok(())
    }

    /// Reads a single octet and advances the cursor by 1.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if the cursor is at end of input.
    pub fn read_u8(&mut self) -> Result<u8, DecodeError> {
        let next = self
            .position
            .checked_add(1)
            .ok_or(DecodeError::UnexpectedEof(usize::MAX))?;
        let Some(&byte) = self.buf.get(self.position) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        self.position = next;
        Ok(byte)
    }

    /// Reads the next octet without advancing the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if the cursor is at end of input.
    pub fn peek_u8(&self) -> Result<u8, DecodeError> {
        let Some(&byte) = self.buf.get(self.position) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        Ok(byte)
    }

    /// Reads a 16-bit big-endian unsigned integer and advances by 2 octets.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than 2 octets remain.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let slice = self.read_slice(2)?;
        let Some(b0) = slice.first() else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        let Some(b1) = slice.get(1) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        Ok(u16::from_be_bytes([*b0, *b1]))
    }

    /// Reads a 32-bit big-endian unsigned integer and advances by 4 octets.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than 4 octets remain.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let slice = self.read_slice(4)?;
        let Some(b0) = slice.first() else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        let Some(b1) = slice.get(1) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        let Some(b2) = slice.get(2) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        let Some(b3) = slice.get(3) else {
            return Err(DecodeError::UnexpectedEof(self.position));
        };
        Ok(u32::from_be_bytes([*b0, *b1, *b2, *b3]))
    }

    /// Reads an exact slice of `len` octets and advances the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if fewer than `len` octets remain.
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        let start = self.position;
        let end = start
            .checked_add(len)
            .ok_or(DecodeError::UnexpectedEof(usize::MAX))?;
        if end > self.len {
            return Err(DecodeError::UnexpectedEof(end));
        }
        let Some(slice) = self.buf.get(start..end) else {
            return Err(DecodeError::UnexpectedEof(start));
        };
        self.position = end;
        Ok(slice)
    }

    /// Returns a slice from the backing buffer at an arbitrary offset and length.
    /// Does not advance the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnexpectedEof`] if `offset + len > total_len`.
    pub fn slice_at(&self, offset: usize, len: usize) -> Result<&'a [u8], DecodeError> {
        let end = offset
            .checked_add(len)
            .ok_or(DecodeError::UnexpectedEof(usize::MAX))?;
        if end > self.len {
            return Err(DecodeError::UnexpectedEof(end));
        }
        let Some(slice) = self.buf.get(offset..end) else {
            return Err(DecodeError::UnexpectedEof(offset));
        };
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_empty_buffer() {
        let mut cur = Cursor::new(&[]);
        assert!(matches!(cur.read_u8(), Err(DecodeError::UnexpectedEof(0))));
        assert!(matches!(
            cur.read_u16(),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(
            cur.read_u32(),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(
            cur.read_slice(1),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(cur.peek_u8(), Err(DecodeError::UnexpectedEof(0))));
        assert!(matches!(
            cur.advance(1),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(cur.seek(1), Err(DecodeError::UnexpectedEof(1))));
    }

    #[test]
    fn test_cursor_overflow_handling() {
        let mut cur = Cursor::new(&[1, 2, 3]);
        assert!(matches!(
            cur.read_slice(usize::MAX),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(
            cur.advance(usize::MAX),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(
            cur.slice_at(usize::MAX, 1),
            Err(DecodeError::UnexpectedEof(..))
        ));
        assert!(matches!(
            cur.slice_at(1, usize::MAX),
            Err(DecodeError::UnexpectedEof(..))
        ));
    }

    #[test]
    fn test_cursor_happy_path() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc];
        let mut cur = Cursor::new(&data);
        assert_eq!(cur.read_u8().unwrap(), 0x12);
        assert_eq!(cur.read_u16().unwrap(), 0x3456);
        assert_eq!(cur.peek_u8().unwrap(), 0x78);
        assert_eq!(cur.read_slice(2).unwrap(), &[0x78, 0x9a]);
        assert_eq!(cur.remaining(), 1);
        assert_eq!(cur.read_u8().unwrap(), 0xbc);
        assert_eq!(cur.remaining(), 0);
    }
}
