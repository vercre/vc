use std::fmt::Display;

use rstest::fixture;
use vercre_test_utils::issuer;

#[macro_export]
macro_rules! snapshot{
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_suffix(format!($($expr,)*));
        settings.set_prepend_module_to_snapshot(false);
        let _guard = settings.bind_to_scope();
    }
}

#[fixture]
pub fn provider() -> issuer::Provider {
    issuer::Provider::new()
}

/// Issuance variants
pub enum Issuance {
    Immediate,
    Deferred,
}

impl Display for Issuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Issuance::Immediate => write!(f, "immediate"),
            Issuance::Deferred => write!(f, "deferred"),
        }
    }
}
