//! DNSSEC validation RDATA types (RFC 4034, RFC 5155).
//!
//! Includes DNSKEY, DS, RRSIG, NSEC, NSEC3, NSEC3PARAM, and TypeBitmap.

use crate::domain::name::Name;
use crate::domain::record::RecordType;

/// DNSSEC Type Bitmap (RFC 4034 §4.1.2, RFC 5155 §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeBitmap {
    windows: Vec<u8>,
}

fn check_window_bit(
    windows: &[u8],
    bitmap_start: usize,
    len: usize,
    target_byte_idx: usize,
    mask: u8,
) -> bool {
    if target_byte_idx >= len {
        return false;
    }
    let byte_offset = bitmap_start.saturating_add(target_byte_idx);
    match windows.get(byte_offset) {
        Some(&byte) => (byte & mask) != 0,
        None => false,
    }
}

impl TypeBitmap {
    /// Creates a type bitmap from wire format window blocks.
    #[must_use]
    pub fn new(windows: Vec<u8>) -> Self {
        Self { windows }
    }

    /// Returns the raw window block octets.
    #[must_use]
    pub fn windows(&self) -> &[u8] {
        &self.windows
    }

    /// Checks whether the specified [`RecordType`] is present in this bitmap.
    #[must_use]
    pub fn contains(&self, rtype: RecordType) -> bool {
        let code = rtype.value();
        let target_window = match u8::try_from(code >> 8) {
            Ok(w) => w,
            Err(_) => return false,
        };
        let type_in_window = match u8::try_from(code & 0xFF) {
            Ok(t) => t,
            Err(_) => return false,
        };
        let target_byte_idx = usize::from(type_in_window >> 3);
        let bit_in_byte = type_in_window & 0x07;
        let mask = 0x80 >> bit_in_byte;

        let mut offset = 0;
        while offset < self.windows.len() {
            let Some(&window_num) = self.windows.get(offset) else {
                break;
            };
            let Some(&bitmap_len) = self.windows.get(offset.saturating_add(1)) else {
                break;
            };
            let len = usize::from(bitmap_len);
            let bitmap_start = offset.saturating_add(2);
            let bitmap_end = bitmap_start.saturating_add(len);

            if window_num == target_window {
                return check_window_bit(&self.windows, bitmap_start, len, target_byte_idx, mask);
            }

            offset = bitmap_end;
        }
        false
    }
}

/// DNSKEY record data (RFC 4034 §2.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyRdata {
    flags: u16,
    protocol: u8,
    algorithm: u8,
    public_key: Vec<u8>,
}

impl DnskeyRdata {
    /// Creates a new [`DnskeyRdata`].
    #[must_use]
    pub fn new(flags: u16, protocol: u8, algorithm: u8, public_key: Vec<u8>) -> Self {
        Self {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    /// Key flags (Zone Key, Secure Entry Point).
    #[must_use]
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// Protocol field (must be 3).
    #[must_use]
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Security algorithm number.
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Public key cryptographic material.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Calculates the key tag according to RFC 4034 Appendix B.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        if self.algorithm == 1 {
            // RSA/MD5 special case (RFC 4034 Appendix B.1)
            let len = self.public_key.len();
            if len >= 3 {
                let idx1 = len.saturating_sub(3);
                let idx2 = len.saturating_sub(2);
                let b1 = match self.public_key.get(idx1) {
                    Some(&b) => b,
                    None => 0,
                };
                let b2 = match self.public_key.get(idx2) {
                    Some(&b) => b,
                    None => 0,
                };
                return (u16::from(b1) << 8) | u16::from(b2);
            }
            return 0;
        }

        // Standard RFC 4034 Appendix B.2 algorithm
        let mut wire = Vec::with_capacity(4usize.saturating_add(self.public_key.len()));
        wire.extend_from_slice(&self.flags.to_be_bytes());
        wire.push(self.protocol);
        wire.push(self.algorithm);
        wire.extend_from_slice(&self.public_key);

        let mut ac: u32 = 0;
        for (i, &byte) in wire.iter().enumerate() {
            if (i & 1) == 0 {
                ac = ac.wrapping_add(u32::from(byte) << 8);
            } else {
                ac = ac.wrapping_add(u32::from(byte));
            }
        }
        ac = ac.wrapping_add((ac >> 16) & 0xFFFF);
        match u16::try_from(ac & 0xFFFF) {
            Ok(tag) => tag,
            Err(e) => {
                tracing::debug!("key_tag conversion error: {e}");
                0
            }
        }
    }
}

/// Delegation Signer record data (RFC 4034 §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRdata {
    key_tag: u16,
    algorithm: u8,
    digest_type: u8,
    digest: Vec<u8>,
}

impl DsRdata {
    /// Creates a new [`DsRdata`].
    #[must_use]
    pub fn new(key_tag: u16, algorithm: u8, digest_type: u8, digest: Vec<u8>) -> Self {
        Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    /// Key tag of the DNSKEY RR referred to.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Algorithm of the DNSKEY RR referred to.
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Digest algorithm type used to create the digest.
    #[must_use]
    pub fn digest_type(&self) -> u8 {
        self.digest_type
    }

    /// Cryptographic digest of the DNSKEY RR.
    #[must_use]
    pub fn digest(&self) -> &[u8] {
        &self.digest
    }
}

/// RRSIG resource record signature data (RFC 4034 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigRdata {
    type_covered: RecordType,
    algorithm: u8,
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: Name,
    signature: Vec<u8>,
}

impl RrsigRdata {
    /// Creates a new [`RrsigRdata`].
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        type_covered: RecordType,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: Name,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        }
    }

    /// RRtype covered by this signature.
    #[must_use]
    pub fn type_covered(&self) -> RecordType {
        self.type_covered
    }

    /// Cryptographic algorithm used to create the signature.
    #[must_use]
    pub fn algorithm(&self) -> u8 {
        self.algorithm
    }

    /// Number of labels in original RRSIG owner name before wildcard expansion.
    #[must_use]
    pub fn labels(&self) -> u8 {
        self.labels
    }

    /// TTL of the covered RRset as it appears in the authoritative zone.
    #[must_use]
    pub fn original_ttl(&self) -> u32 {
        self.original_ttl
    }

    /// Signature expiration timestamp (seconds since UNIX epoch).
    #[must_use]
    pub fn signature_expiration(&self) -> u32 {
        self.signature_expiration
    }

    /// Signature inception timestamp (seconds since UNIX epoch).
    #[must_use]
    pub fn signature_inception(&self) -> u32 {
        self.signature_inception
    }

    /// Key tag of the DNSKEY that produced the signature.
    #[must_use]
    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    /// Owner name of the DNSKEY that produced the signature.
    #[must_use]
    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    /// Cryptographic signature octets.
    #[must_use]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// NSEC Next Secure record data (RFC 4034 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NsecRdata {
    next_domain: Name,
    types: TypeBitmap,
}

impl NsecRdata {
    /// Creates a new [`NsecRdata`].
    #[must_use]
    pub fn new(next_domain: Name, types: TypeBitmap) -> Self {
        Self { next_domain, types }
    }

    /// Next owner name in canonical order.
    #[must_use]
    pub fn next_domain(&self) -> &Name {
        &self.next_domain
    }

    /// Bitmap of RRtypes present at the owner name.
    #[must_use]
    pub fn types(&self) -> &TypeBitmap {
        &self.types
    }
}

/// NSEC3 hashed next secure record data (RFC 5155 §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3Rdata {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
    next_hashed_owner: Vec<u8>,
    types: TypeBitmap,
}

impl Nsec3Rdata {
    /// Creates a new [`Nsec3Rdata`].
    #[must_use]
    pub fn new(
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed_owner: Vec<u8>,
        types: TypeBitmap,
    ) -> Self {
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed_owner,
            types,
        }
    }

    /// Hash algorithm identifier (1 = SHA-1).
    #[must_use]
    pub fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// NSEC3 flags.
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Number of hash iterations.
    #[must_use]
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Binary salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Next hashed owner name in hash order.
    #[must_use]
    pub fn next_hashed_owner(&self) -> &[u8] {
        &self.next_hashed_owner
    }

    /// RRtypes present at unhashed owner name.
    #[must_use]
    pub fn types(&self) -> &TypeBitmap {
        &self.types
    }

    /// Returns whether the Opt-Out flag is set (RFC 5155 §3.1.2).
    #[must_use]
    pub fn opt_out(&self) -> bool {
        (self.flags & 0x01) != 0
    }
}

/// NSEC3PARAM parameters record data (RFC 5155 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nsec3ParamRdata {
    hash_algorithm: u8,
    flags: u8,
    iterations: u16,
    salt: Vec<u8>,
}

impl Nsec3ParamRdata {
    /// Creates a new [`Nsec3ParamRdata`].
    #[must_use]
    pub fn new(hash_algorithm: u8, flags: u8, iterations: u16, salt: Vec<u8>) -> Self {
        Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        }
    }

    /// Hash algorithm identifier.
    #[must_use]
    pub fn hash_algorithm(&self) -> u8 {
        self.hash_algorithm
    }

    /// Flags field (currently all reserved).
    #[must_use]
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// Number of hash iterations.
    #[must_use]
    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    /// Binary salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}
