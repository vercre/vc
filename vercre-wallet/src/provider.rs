//! # Provider
//!
//! The provider traits exported by this module are used to inject functionality into the wallet
//! such as signing, state management and callbacks.
//!
//! See individual trait documentation for specific details.

mod input;
mod issuer_client;
mod status_listener;
mod storer;
mod verifier_client;

pub use input::{IssuanceInput, PresentationInput};
pub use issuer_client::IssuerClient;
pub use status_listener::{IssuanceListener, PresentationListener};
pub use storer::CredentialStorer;
pub use vercre_core::provider::{Algorithm, Callback, Result, Signer, StateManager};
pub use verifier_client::VerifierClient;
