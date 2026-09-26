//! Hot-path domain ports.

pub mod filter;
pub mod local;
pub mod observer;

pub use filter::{FilterPolicy, FilterVerdict};
pub use local::LocalRecords;
pub use observer::{QueryDetail, QueryObserver};
