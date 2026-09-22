//! styx — the composition root.
//!
//! This binary is the **only** crate permitted to name every feature crate at
//! once. Cross-feature wiring happens here and nowhere else: a feature crate
//! declares a port in its `domain`, and this binary constructs the adapter and
//! injects it. There is no service locator and no reflection — collaborators
//! are passed to constructors by value at startup.
//!
//! Phase 0 delivers the crate, its `web` feature and the tracing convention.
//! DNS listeners, the resolver and the Leptos SSR handler are wired in from
//! phase 2 onward.

use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

/// Log filter used when `RUST_LOG` is unset or unusable.
const DEFAULT_LOG_FILTER: LevelFilter = LevelFilter::INFO;

/// Starts the process.
///
/// Phase 0 has nothing to run: this initialises the subscriber and reports the
/// build configuration, which is what makes the `web` feature and the tracing
/// convention observable before there is any product code to observe.
fn main() {
    init_tracing();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        web = cfg!(feature = "web"),
        "styx starting"
    );

    if cfg!(feature = "web") {
        tracing::info!("web UI compiled in; the admin interface arrives in phase 11");
    } else {
        tracing::info!("headless build: no web UI compiled in");
    }
}

/// Installs the `tracing` subscriber, taking its filter from the environment.
///
/// The level is read from `RUST_LOG` and never hardcoded — a hardcoded level
/// is what arch-lint's `tracing-env-init` rule rejects. An unset `RUST_LOG`
/// yields [`DEFAULT_LOG_FILTER`]; an unparseable one falls back to it and says
/// so, because a typo in the environment should degrade the log level rather
/// than take the resolver down.
fn init_tracing() {
    let builder = EnvFilter::builder().with_default_directive(DEFAULT_LOG_FILTER.into());

    // The error is reported rather than discarded, but it cannot be reported
    // until the subscriber it describes has been installed.
    let (filter, rejected) = match builder.from_env() {
        Ok(filter) => (filter, None),
        Err(error) => (EnvFilter::new(DEFAULT_LOG_FILTER.to_string()), Some(error)),
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Some(error) = rejected {
        tracing::warn!(
            %error,
            fallback = %DEFAULT_LOG_FILTER,
            "RUST_LOG could not be parsed; using the fallback filter"
        );
    }
}
