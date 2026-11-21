//! What an NSEC or NSEC3 type bitmap says about the name that owns it.
//!
//! Both proof kinds read the same rules off the same bitmap, so they live here once: a
//! rule fixed in one proof kind and not the other is how a validator ends up accepting a
//! forged denial on one path only.

use styx_proto::domain::rdata::TypeBitmap;
use styx_proto::{Name, RecordType};

/// The record types present at one owner name, as its NSEC or NSEC3 bitmap lists them.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OwnerTypes<'a> {
    owner: &'a Name,
    types: &'a TypeBitmap,
}

impl<'a> OwnerTypes<'a> {
    pub(crate) fn new(owner: &'a Name, types: &'a TypeBitmap) -> Self {
        Self { owner, types }
    }

    fn has(&self, rtype: RecordType) -> bool {
        self.types.contains(rtype)
    }

    /// The parent side of a zone cut: NS without SOA (RFC 4035 §2.3).
    pub(crate) fn is_delegation(&self) -> bool {
        self.has(RecordType::NS) && !self.has(RecordType::SOA)
    }

    /// Whether this name cannot be a closest encloser: a delegation point or a DNAME,
    /// below which the zone is not authoritative (RFC 5155 §8.3, RFC 6672 §5.3.2).
    pub(crate) fn ends_authority(&self) -> bool {
        self.is_delegation() || self.has(RecordType::DNAME)
    }

    /// A delegation to an unsigned child: NS without DS or SOA (RFC 4035 §5.2).
    pub(crate) fn is_unsigned_delegation(&self) -> bool {
        self.is_delegation() && !self.has(RecordType::DS)
    }

    /// Whether the bitmap proves that `qtype` does not exist at its owner (NODATA).
    ///
    /// Neither the type nor a CNAME may be present. A DS RRset lives on the parent side
    /// of a cut, so a DS denial must not come from a zone apex (SOA present), which is
    /// the child's own NSEC: only the root has no parent to ask (RFC 4035 §3.1.4.1,
    /// RFC 5155 §8.6). Any other type below a delegation belongs to the child, so a
    /// delegation proves nothing about it. Meta-type `ANY` is denied only when the bitmap
    /// contains no types at all (e.g., an NSEC3 empty non-terminal).
    pub(crate) fn denies(&self, qtype: RecordType) -> bool {
        if self.has(qtype) || self.has(RecordType::CNAME) {
            return false;
        }
        if qtype == RecordType::DS {
            return !self.has(RecordType::SOA) || self.owner.is_root();
        }
        if qtype == RecordType::ANY {
            return self.types.windows().is_empty();
        }
        !self.is_delegation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A window-0 bitmap listing `types`, every one of which is below 256.
    fn bitmap(types: &[RecordType]) -> TypeBitmap {
        let mut octets = [0u8; 32];
        for rtype in types {
            let value = usize::from(rtype.value());
            octets[value >> 3] |= 0x80 >> (value & 7);
        }
        let last = octets.iter().rposition(|&octet| octet != 0).unwrap();
        let length = last.checked_add(1).unwrap();
        let mut windows = vec![0, u8::try_from(length).unwrap()];
        windows.extend_from_slice(&octets[..length]);
        TypeBitmap::new(windows)
    }

    #[test]
    fn a_ds_denial_from_a_zone_apex_proves_nothing_except_at_the_root() {
        let apex = bitmap(&[RecordType::SOA, RecordType::NS, RecordType::DNSKEY]);
        let child = Name::from_ascii("child.example.").unwrap();
        assert!(!OwnerTypes::new(&child, &apex).denies(RecordType::DS));
        assert!(OwnerTypes::new(&Name::root(), &apex).denies(RecordType::DS));

        let parent_side = bitmap(&[RecordType::NS]);
        assert!(OwnerTypes::new(&child, &parent_side).denies(RecordType::DS));
    }

    #[test]
    fn a_delegation_proves_no_type_but_ds() {
        let cut = bitmap(&[RecordType::NS]);
        let owner = Name::from_ascii("child.example.").unwrap();
        let types = OwnerTypes::new(&owner, &cut);
        assert!(!types.denies(RecordType::A));
        assert!(types.is_unsigned_delegation());
        assert!(types.ends_authority());
    }

    #[test]
    fn any_is_denied_only_when_bitmap_is_empty() {
        let owner = Name::from_ascii("www.example.").unwrap();
        let non_empty = bitmap(&[RecordType::A, RecordType::RRSIG, RecordType::NSEC]);
        assert!(!OwnerTypes::new(&owner, &non_empty).denies(RecordType::ANY));

        let empty = TypeBitmap::new(Vec::new());
        assert!(OwnerTypes::new(&owner, &empty).denies(RecordType::ANY));
    }
}
