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
pub use openid4vc::endpoint::{IssuerMetadata, Payload, Result, StateManager};
pub use openid4vc::issuance::TxCode;
pub use proof::jose::jwk::PublicKeyJwk;
pub use proof::signature::{Algorithm, Signer, Verifier};
pub use storer::CredentialStorer;
