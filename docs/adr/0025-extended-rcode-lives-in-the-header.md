# ADR 0025 — The extended RCODE lives in the header, and BADVERS answers a bad EDNS version

- **Status**: accepted
- **Date**: 2026-10-16
- **Phase**: 1 — Wire codec
- **Extends**: [ADR 0006](0006-edns-opt-first-class-field.md)

## Context

Issue #87: a query whose OPT carries EDNS version 1 was answered FORMERR. RFC 6891 §6.1.3
makes BADVERS (RCODE 16) with an OPT advertising version 0 a MUST, and the codec already
reported the case as its own error, `DecodeError::UnsupportedEdnsVersion`, that no caller
matched.

Building the reply exposed a second problem. RCODE 16 does not fit the header's four bits;
its upper octet lives in the OPT TTL. The codec kept the two halves apart: the decoder built
`Header::rcode` from the nibble alone and kept the upper octet in `Opt::extended_rcode`,
while the encoder wrote the nibble from the header and the upper octet from the `Opt`.
Nothing tied them together, so a reply with rcode 16 and an OPT whose own field was 0 went
out as NOERROR, and an upstream BADVERS decoded as NOERROR.

## Decision

**`Header::rcode` is the only place the 12-bit response code lives.** The decoder merges
the OPT's upper octet into it with `ResponseCode::from_parts`; the encoder splits it with
`ResponseCode::split`. `Opt` loses its `extended_rcode` field, accessor and constructor
parameter. Encoding an rcode above 15 on a message with no OPT is
`EncodeError::ExtendedRcodeWithoutOpt`, never a silent truncation to the nibble.

**An unsupported EDNS version hands the query back.** `DecodeError::UnsupportedEdnsVersion`
carries an `UnsupportedEdns` with the version, the header and the question section already
parsed. BADVERS wins as soon as the first OPT with a version other than 0 is seen: the
header, the question and the records before the OPT must have parsed, and nothing after the
OPT is validated, because a version-1 OPT body is not defined by version-0 rules.

**Both listeners answer BADVERS.** The reply echoes ID, opcode, RD and the question and
carries RCODE 16. `ResponseWriter` keeps the OPT, creating one when absent, whenever the
reply's rcode is above 15, so the reply advertises version 0 and the server's payload size.
Like FORMERR it bypasses the pipeline, and an inbound response (QR=1) is dropped silently.

**An upstream BADVERS is a failure.** Styx sends only EDNS version 0, so a member answering
BADVERS is broken. `Do53Forwarder` maps it to `UpstreamError::Malformed`; the recursor
already classified any unlisted rcode as a server failure.

## Consequences

- Every `Opt::new` call site lost its second argument.
- A server's BADVERS used to read as NOERROR and could be passed on as an empty answer; it
  is now rcode 16 end to end.
- The reply carries the question, so it is larger than FORMERR. It stays within the request
  size and the UDP admission budget applies before it.

## Alternatives rejected

- **Build the reply's OPT by hand in each listener.** Smallest diff, but the invariant would
  live in two call sites and every later extended rcode would repeat the trick.
- **Keep both fields and let the encoder OR them.** Leaves two sources of truth and an
  ambiguous precedence rule.
- **A header-only BADVERS like the FORMERR path.** Needs no codec change, but a client that
  matches replies on the question section may discard it.
