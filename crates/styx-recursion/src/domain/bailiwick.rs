//! The single place that answers "is this server entitled to speak for this name?".
//!
//! Applied to glue, to referral NS sets and to answers alike, before anything is
//! believed and before anything is offered to the answer cache. The answer cache's
//! own bailiwick rules are the second gate, not the first.

use styx_proto::Name;

use crate::domain::error::RecursionError;

/// Returns true when a server authoritative for `server_zone` may speak for
/// `record_name`: the name is the zone itself or lies below it.
#[must_use]
pub fn is_in_bailiwick(server_zone: &Name, record_name: &Name) -> bool {
    record_name.is_subdomain_of(server_zone)
}

/// Checks that a referral from a server for `parent` to `child` is one the descent
/// may follow while resolving `asked`.
///
/// # Errors
///
/// Returns [`RecursionError::DelegationLoop`] when `child` is `parent` itself or
/// not below it — following it would never get closer — and
/// [`RecursionError::OutOfBailiwick`] when `asked` is not inside `child`, so the
/// referral is about some other part of the tree.
pub fn check_referral(parent: &Name, child: &Name, asked: &Name) -> Result<(), RecursionError> {
    if child.eq_ignore_case(parent) || !is_in_bailiwick(parent, child) {
        return Err(RecursionError::DelegationLoop);
    }
    if !is_in_bailiwick(child, asked) {
        return Err(RecursionError::OutOfBailiwick);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    #[test]
    fn a_zone_speaks_for_itself_and_below_only() {
        assert!(is_in_bailiwick(
            &name("example.com."),
            &name("example.com.")
        ));
        assert!(is_in_bailiwick(
            &name("example.com."),
            &name("a.b.EXAMPLE.com.")
        ));
        assert!(!is_in_bailiwick(&name("example.com."), &name("com.")));
        assert!(!is_in_bailiwick(
            &name("example.com."),
            &name("badexample.com.")
        ));
        assert!(is_in_bailiwick(&Name::root(), &name("anything.example.")));
    }

    #[test]
    fn a_referral_must_descend_and_cover_the_asked_name() {
        let com = name("com.");
        let example = name("example.com.");
        let asked = name("www.example.com.");
        assert_eq!(check_referral(&com, &example, &asked), Ok(()));
        assert_eq!(
            check_referral(&com, &com, &asked),
            Err(RecursionError::DelegationLoop)
        );
        assert_eq!(
            check_referral(&example, &com, &asked),
            Err(RecursionError::DelegationLoop)
        );
        assert_eq!(
            check_referral(&com, &name("other.com."), &asked),
            Err(RecursionError::OutOfBailiwick)
        );
        assert_eq!(
            check_referral(&com, &name("example.net."), &asked),
            Err(RecursionError::DelegationLoop)
        );
    }
}
