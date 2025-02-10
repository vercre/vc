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
pub mod dif_exch;
pub mod iso_mdl;
pub mod openid;
pub mod status;
pub mod w3c_vc;

#[cfg(test)]
mod test_utils;
