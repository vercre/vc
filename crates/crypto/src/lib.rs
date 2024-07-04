#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::missing_errors_doc)]

//! # Cryptographic Support
//!
//! This module provides cryptographic support.

// use signature::Keypair;

/// A `Keyring` contains a set of related keys
pub trait Keyring: Signer + Encryptor {}

pub trait Signer {
    type VerifyingKey;

    fn sign(&self, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn verifying_key(&self) -> anyhow::Result<Self::VerifyingKey>;
}

pub trait Verifier {
    type VerifyingKey;

    fn verify(
        &self, data: &[u8], signature: &[u8], verifying_key: &Self::VerifyingKey,
    ) -> anyhow::Result<()>;
}

pub trait Encryptor {
    type PublicKey;

    // ECDH-ES, RSA
    fn encrypt(&self, msg: &[u8], public_key: &Self::PublicKey) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> Self::PublicKey;
}

pub trait Decryptor {
    type PublicKey;

    fn decrypt(&self, encrypted: &[u8]) -> anyhow::Result<Vec<u8>>;
}

