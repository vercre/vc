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
pub trait Keyring: Signer {}

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
