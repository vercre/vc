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
pub use openid4vc::endpoint::{
    Algorithm, IssuerMetadata, Payload, PublicKeyJwk, Result, Signer, StateManager, Verifier,
};
pub use openid4vc::issuance::TxCode;
pub use storer::CredentialStorer;
