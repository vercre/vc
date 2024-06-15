//! # Signature
//!
//! The `signature` module provides `Signer` and `Verifier` traits for Vercre.

use std::future::{Future, IntoFuture};

pub use crate::jws::Algorithm;
pub use crate::provider::Result;

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
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send;
}

/// Verifier is used by implementers to provide verification functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Verifier: Send + Sync {
    /// Verify the provided signature for a given message.
    ///
    /// # Errors
    ///
    /// Returns an error if the signature is invalid.
    fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()>;

    /// Resolve the verification method to a public key.
    fn resolve(&self, verification_method: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
