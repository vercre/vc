//! # Provider
//!
//! The provider traits exported by this module are used to inject functionality into the wallet
//! such as signing, state management and callbacks.
//!
//! See individual trait documentation for specific details.

mod client;
mod input;
mod status_listener;
mod storer;

pub use client::{IssuerClient, VerifierClient};
pub use input::{IssuanceInput, PresentationInput};
pub use openid4vc::issuance::TxCode;
pub use provider::{Algorithm, Callback, Jwk, Payload, Result, Signer, StateManager, Verifier};
pub use status_listener::{IssuanceListener, PresentationListener};
pub use storer::CredentialStorer;
pub use vercre_exch::Constraints;
