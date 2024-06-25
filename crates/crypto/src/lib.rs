#![allow(missing_docs)]

//! # Cryptographic Support
//!
//! This module provides cryptographic support.

pub mod local;

// use signature::Keypair;

/// A `Keyring` contains a set of related keys
pub trait Keyring {
    type VerifyingKey;

    fn generate(&self, name: &str) -> anyhow::Result<Self::VerifyingKey>;

    fn sign(&self, name: &str, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    fn verifying_key(&self, name: &str) -> anyhow::Result<Self::VerifyingKey>;

    // fn verify(&self, name: &str, data: &[u8], signature: &[u8]) -> anyhow::Result<()>;
}

// pub enum Algorithm {
//     Ed25519,
//     X25519,
// }

// pub(crate) mod private {
//     use super::*;

//     pub trait Sealed {}
// }
