//! How long a validated answer may live: never past the earliest RRSIG expiration it rests on.
//!
//! A record's TTL and its signature's validity are two different clocks (Phase 06, 6d.6).
//! Of the two ways to keep them apart — recompute the verdict on every cache hit, or bound
//! the cached entry by the signature — styx bounds the entry: a Secure answer's TTLs are
//! capped at the time its earliest RRSIG has left (RFC 4035 §5.3.3, a MUST), and an answer
//! whose signatures expire sooner than the cache's TTL floor is served but not cached, since
//! the floor would otherwise stretch the entry past them. So no cache entry outlives a
//! signature it was validated with, and an expired signature is never served with AD.
//!
//! The cap reads the wall clock, the entry's deadline the monotonic one: a wall clock set
//! back after admission can keep an entry past its signatures by as much as it moved.

use std::time::{SystemTime, UNIX_EPOCH};

use styx_proto::{Message, RData, Ttl};

/// RFC 1982 half-range: a serial-number difference at or past it means "before", not "after".
const SERIAL_HALF_RANGE: u32 = 0x8000_0000;

/// The time left at `now` before the earliest RRSIG in the answer or authority section of
/// `message` expires: zero for one already expired, `None` when the message has no RRSIG.
#[must_use]
pub fn remaining_signature_life(message: &Message, now: SystemTime) -> Option<Ttl> {
    let now = serial_seconds(now);
    message
        .answers
        .iter()
        .chain(&message.authorities)
        .filter_map(|record| match &record.rdata {
            RData::Rrsig(signature) => Some(seconds_until(signature.signature_expiration(), now)),
            _ => None,
        })
        .min()
        .map(Ttl::from_secs)
}

/// Lowers every answer and authority TTL above `limit` to it.
pub fn cap_ttls(message: &mut Message, limit: Ttl) {
    for record in message.answers.iter_mut().chain(&mut message.authorities) {
        record.ttl = record.ttl.min(limit);
    }
}

/// Seconds from `now` to `expiration`, both RRSIG serial times (RFC 4034 §3.1.5); zero once
/// `expiration` is not after `now`.
fn seconds_until(expiration: u32, now: u32) -> u32 {
    let ahead = expiration.wrapping_sub(now);
    if ahead < SERIAL_HALF_RANGE {
        ahead
    } else {
        0
    }
}

/// `now` as an RRSIG timestamp: seconds since the epoch modulo 2^32 (RFC 4034 §3.1.5).
fn serial_seconds(now: SystemTime) -> u32 {
    let seconds = now
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let [_, _, _, _, high, upper, lower, low] = seconds.to_be_bytes();
    u32::from_be_bytes([high, upper, lower, low])
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use styx_proto::{Name, Question, RecordClass, RecordType, ResourceRecord, RrsigRdata};

    use super::*;

    const NOW: u64 = 1_700_000_100;

    fn at(seconds: u64) -> SystemTime {
        UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .unwrap_or(UNIX_EPOCH)
    }

    fn rrsig(expiration: u32) -> ResourceRecord {
        let signature = RrsigRdata::new(
            RecordType::A,
            15,
            2,
            300,
            expiration,
            1_700_000_000,
            1,
            Name::root(),
            vec![0; 64],
        );
        ResourceRecord::new(
            Name::root(),
            RecordType::RRSIG,
            RecordClass::In,
            Ttl::from_secs(300),
            RData::Rrsig(signature),
        )
    }

    fn signed(expirations: &[u32]) -> Message {
        let question = Question::new(Name::root(), RecordType::A, RecordClass::In);
        let mut message = Message::response_to(1, question);
        message.answers.push(ResourceRecord::new(
            Name::root(),
            RecordType::A,
            RecordClass::In,
            Ttl::from_secs(3600),
            RData::A(Ipv4Addr::LOCALHOST),
        ));
        message
            .answers
            .extend(expirations.iter().map(|&expiration| rrsig(expiration)));
        message
    }

    #[test]
    fn the_earliest_expiration_bounds_the_life() {
        let message = signed(&[1_700_000_400, 1_700_000_200]);

        assert_eq!(
            remaining_signature_life(&message, at(NOW)),
            Some(Ttl::from_secs(100))
        );
    }

    #[test]
    fn an_expired_signature_leaves_no_life() {
        let message = signed(&[1_700_000_050]);

        assert_eq!(remaining_signature_life(&message, at(NOW)), Some(Ttl::ZERO));
    }

    #[test]
    fn a_message_without_rrsig_has_no_signature_bound() {
        assert_eq!(remaining_signature_life(&signed(&[]), at(NOW)), None);
    }

    /// RFC 4034 §3.1.5: timestamps are serial numbers, so an expiration just past the 2^32
    /// wrap still lies ahead of a `now` just before it.
    #[test]
    fn the_expiration_is_compared_across_the_serial_wrap() {
        let message = signed(&[10]);

        assert_eq!(
            remaining_signature_life(&message, at(u64::from(u32::MAX - 9))),
            Some(Ttl::from_secs(20))
        );
    }

    #[test]
    fn the_cap_only_lowers_ttls() {
        let mut message = signed(&[1_700_000_200]);

        cap_ttls(&mut message, Ttl::from_secs(100));

        let ttls: Vec<u32> = message.answers.iter().map(|r| r.ttl.seconds()).collect();
        assert_eq!(ttls, vec![100, 100]);
        cap_ttls(&mut message, Ttl::from_secs(500));
        let ttls: Vec<u32> = message.answers.iter().map(|r| r.ttl.seconds()).collect();
        assert_eq!(ttls, vec![100, 100]);
    }
}
