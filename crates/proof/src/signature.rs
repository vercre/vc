//! # Signature
//!
//! The `signature` module provides `Signer` and `Verifier` traits for Vercre.

use std::future::{Future, IntoFuture};

pub use crate::jose::jwa::Algorithm;
use crate::jose::jwk::PublicKeyJwk;

// AKA DataSecurity, SafeGuard, Guardian, Protection

/// The security trait provides a set of methods for signing, encrypting,
/// verifying, and decrypting data. Implementers of this trait are expected to
/// provide the necessary cryptographic functionality to support Verifiable
/// Credential issuance and Verifiable Presentation submissions.
pub trait Security: Send + Sync {
    /// Signer provides digital signing-related funtionality.
    /// The `identifier` parameter is one of `credential_issuer` or `verifier_id`.
    fn signer(&self, identifier: &str) -> impl Signer;

    /// Verifier provides digital signature verification functionality.
    fn verifier(&self, identifier: &str) -> impl Verifier;

    /// Encryptor provides data encryption functionality.
    fn encryptor(&self, identifier: &str) -> impl Encryptor;

    /// Decryptor provides data decryption functionality.
    fn decryptor(&self, identifier: &str) -> impl Decryptor;
}

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
    fn deref_jwk(&self, did_url: &str)
        -> impl Future<Output = anyhow::Result<PublicKeyJwk>> + Send;
}

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Encryptor: Send + Sync {
    fn encrypt(
        &self, plaintext: &[u8], recipient_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn public_key(&self) -> Vec<u8>;
}

/// Verifier is used by implementers to provide verification functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Decryptor: Send + Sync {
    fn decrypt(
        &self, ciphertext: &[u8], sender_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
