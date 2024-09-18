//! # Test Utilities for Vercre
//!
//! Some hard-coded provider trait implementations that can be used for testing
//! and examples.
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.

pub mod holder;
pub mod issuer;
pub mod sample;
pub mod store;
pub mod verifier;

use std::sync::Once;

use tracing::Level;
use tracing_subscriber::FmtSubscriber;

// initalise tracing once for all tests
static INIT: Once = Once::new();

#[macro_export]
macro_rules! snapshot{
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_suffix(format!($($expr,)*));
        settings.set_prepend_module_to_snapshot(false);
        let _guard = settings.bind_to_scope();
    }
}

/// Initialise tracing for tests.
///
/// # Panics
///
/// Panics if the tracing subscriber cannot be set.
pub fn init_tracer() {
    INIT.call_once(|| {
        let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
        tracing::subscriber::set_global_default(subscriber).expect("subscriber set");
    });
}
