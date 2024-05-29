//! # Provider
//!
//! The provider traits exported by this module are used to inject functionality into the wallet
//! such as signing, state management and callbacks.
//!
//! See individual trait documentation for specific details.

mod issuer_client;
mod storer;
mod status_listener;

pub use issuer_client::IssuerClient;
pub use storer::CredentialStorer;
pub use status_listener::StatusListener;
pub use vercre_core::provider::{Algorithm, Callback, Result, Signer, StateManager};
