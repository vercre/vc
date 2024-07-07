#![allow(missing_docs)]
#![allow(dead_code)]
#![allow(clippy::missing_errors_doc)]

//! # Cryptographic Support
//!
//! This module provides cryptographic support.

pub mod jose;
pub mod signature;

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
    // type PublicKey;

    // ECDH-ES, RSA
    fn encrypt(&self, plaintext: &[u8], recipient_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn public_key(&self) -> Vec<u8>;
}

pub trait Decryptor {
    // type PublicKey;

    fn decrypt(&self, ciphertext: &[u8], sender_public_key: &[u8]) -> anyhow::Result<Vec<u8>>;
}
