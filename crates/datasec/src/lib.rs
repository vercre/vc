#![feature(let_chains)]

//! # Data Security for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.

pub mod cose;
pub mod jose;

use std::future::{Future, IntoFuture};

use serde::{Deserialize, Serialize};

pub use crate::jose::jwa::Algorithm;
pub use crate::jose::jwk::PublicKeyJwk;
pub use crate::jose::jwt::Jwt;

/// The `SecOps` trait is used to provide methods needed for signing,
/// encrypting, verifying, and decrypting data.
///
/// Implementers of this trait are expected to provide the necessary
/// cryptographic functionality to support Verifiable Credential issuance and
/// Verifiable Presentation submissions.
pub trait SecOps: Send + Sync {
    /// Signer provides digital signing-related funtionality.
    /// The `identifier` parameter is one of `credential_issuer` or
    /// `verifier_id`.
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
    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// The public key of the key pair used in signing. The possibility of key
    /// rotation mean this key should only be referenced at the point of signing.
    fn public_key(&self) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;
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

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    #[serde(rename = "OKP")]
    Okp,

    /// Elliptic curve key pair
    #[serde(rename = "EC")]
    Ec,

    /// Octet string
    #[serde(rename = "oct")]
    Oct,
}



/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum Curve {
    /// Ed25519 curve
    #[default]
    Ed25519,

    /// secp256k1 curve
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,
}

/// The intended usage of the public `KeyType`. This enum is serialized
/// `untagged`
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyUse {
    /// Public key is to be used for signature verification
    #[default]
    #[serde(rename = "sig")]
    Signature,

    /// Public key is to be used for encryption
    #[serde(rename = "enc")]
    Encryption,
}
