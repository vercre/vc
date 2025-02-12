//! # `OpenID` for Verifiable Credentials Types
//!
//! Types and logic used in the `OpenID4VC` specifications and consumed by
//! `issuer` and `verifier` feature endpoints.

mod error;
pub mod issuer;
pub mod oauth;
pub mod provider;
pub mod verifier;

pub use self::error::Error;

/// Result type for `OpenID` for Verifiable Credential Issuance and Verifiable
/// Presentations.
pub type Result<T, E = Error> = std::result::Result<T, E>;
