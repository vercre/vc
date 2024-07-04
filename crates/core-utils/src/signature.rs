//! # Signature
//!
//! The `signature` module provides `Signer` and `Verifier` traits for Vercre.

use std::future::{Future, IntoFuture};

pub use crate::jose::jwa::Algorithm;
use crate::jose::jwk::Jwk;

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;

    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}

/// Verifier is used by implementers to provide verification functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Verifier: Send + Sync {
    /// Dereference DID URL to the public key JWK specified in the URL fragment.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL cannot be dereferenced to a JWK
    fn deref_jwk(&self, did_url: &str) -> impl Future<Output = anyhow::Result<Jwk>> + Send;
}
