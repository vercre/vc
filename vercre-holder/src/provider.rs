//! # Provider
//!
//! The provider traits exported by this module are used to inject functionality into the wallet
//! such as signing, state management and callbacks.
//!
//! See individual trait documentation for specific details.

mod client;
mod storer;

pub use client::{IssuerClient, VerifierClient};
pub use dif_exch::Constraints;
pub use openid4vc::issuance::TxCode;
pub use endpoint::{
    Algorithm, IssuerMetadata, Jwk, Payload, Result, Signer, StateManager, Verifier,
};
pub use storer::CredentialStorer;
