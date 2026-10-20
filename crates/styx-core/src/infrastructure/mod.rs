//! Infrastructure layer: adapters implementing domain ports.

pub mod clock;
pub mod sleeper;

pub use clock::SystemClock;
pub use sleeper::SystemSleeper;
