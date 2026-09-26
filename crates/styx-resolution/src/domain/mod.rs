//! Domain layer: ports (traits) and the error enums they return.
//!
//! Depends outward on nothing but `styx-proto` and third-party crates. It may
//! not use `crate::application`, `crate::infrastructure`, or any sibling
//! feature crate.
//!
//! A port names no concrete infrastructure and no sibling feature crate. The
//! `FilterPolicy` port lands here, and `styx-filtering` is wired into it by
//! the binary — that indirection is what keeps the two features independent.
//!
//! No synchronous I/O, no `unwrap`, no `expect`, no `panic!`.

pub mod answer;
pub mod clock;
pub mod error;
pub mod ports;
pub mod request;

pub use answer::{AnswerSource, ForgedAnswer, ForgedSource, ResolutionOutcome, ResolvedSource};
pub use clock::Clock;
pub use error::{ConfigError, ListenerError, PipelineError, ServerError};
pub use ports::{FilterPolicy, FilterVerdict, LocalRecords, QueryDetail, QueryObserver};
pub use request::{ClientId, MaxResponseSize, RequestContext, Transport};
