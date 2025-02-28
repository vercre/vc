//! An API for the issuance and verification of Verifiable Credentials based on
//! the [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
//! and [OpenID for Verifiable Presentations](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! specifications.
//!
//! # Feature Flags
//!
//! There is no default feature. The following features are available:
//!
//! * `issuer` - Enables the issuer API.
//! * `verifier` - Enables the verifier API.

#[cfg(feature = "issuer")]
pub mod issuer;

#[cfg(feature = "verifier")]
pub mod verifier;

pub mod core;
mod dif_exch;
mod iso_mdl;
pub mod openid;
pub mod status;
pub mod w3c_vc;

pub mod test_utils;

/// Re-export top-level provider traits and types
pub mod provider {
    pub use crate::openid::provider::{Result, StateStore};
}

/// Re-export DID resolution
pub mod did {
    pub use credibil_did::*;
}

/// Re-export cryptographic types and functions
pub mod infosec {
    pub use credibil_infosec::*;
}

/// Re-export basic types
pub use crate::core::{Kind, Quota, urlencode};
