//! What a fake name server knows and how it misbehaves: plain data, no I/O.
//!
//! A [`ZoneScript`] describes one server's view of the DNS — the records it serves,
//! the zones it delegates, the glue it attaches — and any scripted fault. The
//! responder in [`crate::responder`] turns a query plus a script into a response.
//! Names are compared case-insensitively and with or without a trailing dot.

use std::net::Ipv4Addr;

use styx_proto::{RecordType, ResourceRecord, ResponseCode};

/// Records served for one owner name and type.
#[derive(Debug, Clone)]
pub struct ScriptedAnswer {
    /// Owner name the records answer for.
    pub name: String,
    /// Record type.
    pub rtype: RecordType,
    /// Records returned in the answer section.
    pub records: Vec<ResourceRecord>,
}

/// A delegation: an NS record for `zone`, with optional glue.
#[derive(Debug, Clone)]
pub struct ScriptedReferral {
    /// Zone name being delegated.
    pub zone: String,
    /// Target nameserver name.
    pub ns_target: String,
    /// Glue address for the nameserver; `None` makes the delegation glue-less.
    pub glue_ip: Option<Ipv4Addr>,
}

/// An address record attached to every response's additional section, whether or
/// not it is glue for anything in it — the shape of an out-of-bailiwick poisoning
/// attempt, and how a root server's priming answer carries root addresses.
#[derive(Debug, Clone)]
pub struct ScriptedGlue {
    /// Owner name of the address record.
    pub name: String,
    /// The address.
    pub ip: Ipv4Addr,
}

/// A DNAME (RFC 6672): every name strictly below `owner` is an alias for the same
/// name below `target`.
#[derive(Debug, Clone)]
pub struct ScriptedDname {
    /// The DNAME owner.
    pub owner: String,
    /// The substituted suffix.
    pub target: String,
}

/// A fixed RCODE returned, with empty sections, for one question.
#[derive(Debug, Clone)]
pub struct ScriptedRcode {
    /// The question name this applies to.
    pub name: String,
    /// The question type this applies to; `None` matches every type.
    pub rtype: Option<RecordType>,
    /// The RCODE to return.
    pub rcode: ResponseCode,
}

/// The zone a server is authoritative for, used to attach an SOA to negative
/// answers (RFC 2308).
#[derive(Debug, Clone)]
pub struct ScriptedOrigin {
    /// The zone apex.
    pub zone: String,
    /// The SOA MINIMUM field, which bounds negative caching.
    pub negative_ttl: u32,
}

/// One fake server's scripted view of the DNS.
///
/// Every field is public so a test can read back what it scripted; tests build a
/// script through the builder methods.
#[derive(Debug, Clone, Default)]
pub struct ZoneScript {
    /// Records served authoritatively.
    pub answers: Vec<ScriptedAnswer>,
    /// Delegations to child zones.
    pub referrals: Vec<ScriptedReferral>,
    /// Address records attached to every response regardless of bailiwick.
    pub extra_glue: Vec<ScriptedGlue>,
    /// DNAME redirections.
    pub dnames: Vec<ScriptedDname>,
    /// Per-question RCODE overrides, checked before anything else is served.
    pub rcodes: Vec<ScriptedRcode>,
    /// The zone this server is authoritative for, if negative answers carry an SOA.
    pub origin: Option<ScriptedOrigin>,
    /// Answer every UDP query with TC=1 and empty sections, forcing TCP.
    pub truncate_udp: bool,
    /// Answer any query carrying an OPT record with FORMERR and no OPT.
    pub edns_intolerant: bool,
    /// Answer every query with AA=0 and empty sections: a lame delegation.
    pub lame: bool,
    /// Record every query and answer none: a server that times out.
    pub silent: bool,
}

impl ZoneScript {
    /// Creates an empty script: every query is answered NXDOMAIN.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Serves `records` for `name` and `rtype`.
    #[must_use]
    pub fn answer(mut self, name: &str, rtype: RecordType, records: Vec<ResourceRecord>) -> Self {
        self.answers.push(ScriptedAnswer {
            name: name.to_string(),
            rtype,
            records,
        });
        self
    }

    /// Delegates `zone` to `ns_target`, with glue address `glue_ip`.
    #[must_use]
    pub fn refer(mut self, zone: &str, ns_target: &str, glue_ip: Ipv4Addr) -> Self {
        self.referrals.push(ScriptedReferral {
            zone: zone.to_string(),
            ns_target: ns_target.to_string(),
            glue_ip: Some(glue_ip),
        });
        self
    }

    /// Delegates `zone` to `ns_target` with no glue, so the resolver must look the
    /// nameserver's address up separately.
    #[must_use]
    pub fn refer_without_glue(mut self, zone: &str, ns_target: &str) -> Self {
        self.referrals.push(ScriptedReferral {
            zone: zone.to_string(),
            ns_target: ns_target.to_string(),
            glue_ip: None,
        });
        self
    }

    /// Attaches an address record for `name` to every response.
    #[must_use]
    pub fn extra_glue(mut self, name: &str, ip: Ipv4Addr) -> Self {
        self.extra_glue.push(ScriptedGlue {
            name: name.to_string(),
            ip,
        });
        self
    }

    /// Redirects every name strictly below `owner` to the same name below `target`.
    #[must_use]
    pub fn dname(mut self, owner: &str, target: &str) -> Self {
        self.dnames.push(ScriptedDname {
            owner: owner.to_string(),
            target: target.to_string(),
        });
        self
    }

    /// Answers `rcode` to `name`, for `rtype` only or for every type when `None`.
    #[must_use]
    pub fn rcode(mut self, name: &str, rtype: Option<RecordType>, rcode: ResponseCode) -> Self {
        self.rcodes.push(ScriptedRcode {
            name: name.to_string(),
            rtype,
            rcode,
        });
        self
    }

    /// Marks this server authoritative for `zone`, attaching an SOA with the given
    /// negative TTL to every NXDOMAIN and NODATA answer.
    #[must_use]
    pub fn origin(mut self, zone: &str, negative_ttl: u32) -> Self {
        self.origin = Some(ScriptedOrigin {
            zone: zone.to_string(),
            negative_ttl,
        });
        self
    }

    /// Truncates every UDP answer, forcing a TCP retry.
    #[must_use]
    pub fn truncate_udp(mut self) -> Self {
        self.truncate_udp = true;
        self
    }

    /// Rejects every query that carries EDNS with FORMERR.
    #[must_use]
    pub fn edns_intolerant(mut self) -> Self {
        self.edns_intolerant = true;
        self
    }

    /// Records every query and never answers.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.silent = true;
        self
    }

    /// Answers every query non-authoritatively with nothing in it.
    #[must_use]
    pub fn lame(mut self) -> Self {
        self.lame = true;
        self
    }
}

/// Lower-cases `name` and gives it exactly one trailing dot.
pub(crate) fn normalise(name: &str) -> String {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        ".".to_string()
    } else {
        format!("{trimmed}.")
    }
}

/// Returns true when `name` equals `zone` or lies below it. Both normalised.
pub(crate) fn is_at_or_below(name: &str, zone: &str) -> bool {
    zone == "." || name == zone || name.ends_with(&format!(".{zone}"))
}
