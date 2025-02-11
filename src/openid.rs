//! # `OpenID` for Verifiable Credentials Types
//!
//! Types and logic used in the `OpenID4VC` specifications and consumed by
//! `vercre-issuer`,`vercre-verifier`, and `vercre-holder` crates.
//!
//! The crate is for internal use within Vercre project and is not intended to
//! be used directly by the end users. Any public types are re-exported through
//! the respective top-level `vercre-xxx` crates.

mod error;
pub mod issuer;
pub mod oauth;
pub mod provider;
pub mod verifier;

pub use self::error::Error;

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
