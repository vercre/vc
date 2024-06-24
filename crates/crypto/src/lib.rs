#![allow(missing_docs)]

//! # Cryptographic Support
//!
//! This module provides cryptographic support.

pub mod local;

use signature::Keypair;

/// A `Keyring` contains a set of related keys
pub trait Keyring {
    fn generate(&self, name: &str, alg: &Algorithm) -> anyhow::Result<impl Keypair>;

    fn keypair(&self, name: &str) -> anyhow::Result<impl Keypair>;

    fn sign(&self, name: &str, data: &[u8]) -> anyhow::Result<Vec<u8>>;

    // fn verify(&self, name: &str, data: &[u8], signature: &[u8]) -> anyhow::Result<()>;
}

pub enum Algorithm {
    Ed25519,
    X25519,
}

// pub(crate) mod private {
//     use super::*;

//     pub trait Sealed {}
// }
