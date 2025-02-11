//! # Test Utilities for Credibil VC
//!
//! Some hard-coded provider trait implementations that can be used for testing
//! and examples.

#![allow(missing_docs)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
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

/// Configure Insta snapshot name.
///
/// # Example
///
/// ```rust,ignore
/// snapshot!("issuer:immediate");
///
/// ...
///
/// assert_snapshot!("credential", vc, {
///    ".validFrom" => "[validFrom]",
///    ".credentialSubject" => insta::sorted_redaction()
/// });
/// ```
///
/// will result in a snapshot named `credential@issuer:immediate.snap`.
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
