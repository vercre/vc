//! # Verifiable Credentials
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.
//!
//! This library encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in a way
//! that is cryptographically secure, privacy respecting, and machine-verifiable.

pub mod model;
pub mod proof;
pub mod schema;
pub mod status;

pub use anyhow::anyhow;
pub use vercre_did::{dereference, Resource};

// TODO: move this macro to a more appropriate location (its own crate perhaps).
// N.B. the current dependency tree is a little complex, so this is a temporary
// solution that avoids cyclic dependencies.

/// Generate a closure to resolve public key material required by `Jws::decode`.
///
/// # Example
///
/// ```rust,ignore
/// use vercre_datasec::{verify_key, SecOps};
///
/// let resolver = SecOps::resolver(&provider, &request.credential_issuer)?;
/// let jwt = jws::decode(proof_jwt, verify_key!(resolver)).await?;
/// ...
/// ```
#[doc(hidden)]
#[macro_export]
macro_rules! verify_key {
    ($resolver:expr) => {{
        // create local reference before moving into closure
        let resolver = $resolver;

        move |kid: String| async move {
            let resp = $crate::dereference(&kid, None, resolver).await?;
            let Some($crate::Resource::VerificationMethod(vm)) = resp.content_stream else {
                return Err($crate::anyhow!("Verification method not found"));
            };
            vm.method_type.jwk().map_err(|e| $crate::anyhow!("JWK not found: {e}"))
        }
    }};
}
