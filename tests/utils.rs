#![allow(missing_docs)]

use std::fmt::Display;

use rstest::fixture;
use test_issuer::ProviderImpl;

#[fixture]
pub fn provider() -> ProviderImpl {
    ProviderImpl::new()
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
