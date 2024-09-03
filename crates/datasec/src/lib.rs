#![feature(let_chains)]

//! # Data Security for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

pub mod jose;

use std::future::{Future, IntoFuture};

pub use crate::jose::jwa::Algorithm;
pub use crate::jose::jwk::PublicKeyJwk;
pub use crate::jose::jwt::Jwt;

/// The `SecOps` trait is used to provide methods needed for signing, encrypting,
/// verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait SecOps: Send + Sync {
    /// Signer provides digital signing-related funtionality.
    /// The `identifier` parameter is one of `credential_issuer` or `verifier_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the signer cannot be created.
    fn signer(&self, identifier: &str) -> anyhow::Result<impl Signer>;

    /// Encryptor provides data encryption functionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the encryptor cannot be created.
    fn encryptor(&self, identifier: &str) -> anyhow::Result<impl Encryptor>;

    /// Decryptor provides data decryption functionality.
    ///
    /// # Errors
    ///
    /// Returns an error if the decryptor cannot be created.
    fn decryptor(&self, identifier: &str) -> anyhow::Result<impl Decryptor>;
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

/// Encryptor is used by implementers to provide encryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Encryptor: Send + Sync {
    /// Encrypt the plaintext using the recipient's public key.
    fn encrypt(
        &self, plaintext: &[u8], recipient_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// The public key of the encryptor.
    fn public_key(&self) -> Vec<u8>;
}

/// Decryptor is used by implementers to provide decryption functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Decryptor: Send + Sync {
    /// Decrypt the ciphertext using the sender's public key.
    fn decrypt(
        &self, ciphertext: &[u8], sender_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}

