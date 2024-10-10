//! # COSE
//!
//! This module provides types for working with CBOR Object Signing and Encryption (COSE) keys.

pub mod cbor;
mod key;

pub use cbor::Tag24;
#[allow(clippy::module_name_repetitions)]
pub use key::CoseKey;
