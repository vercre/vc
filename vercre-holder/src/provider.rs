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
pub use status_listener::{IssuanceListener, PresentationListener};
pub use storer::CredentialStorer;
pub use vercre_core::metadata::CredentialConfiguration;
pub use vercre_core::provider::{Callback, Result, StateManager};
pub use vercre_core::signature::{Algorithm, Signer};
pub use vercre_core::vci::TxCode;
pub use vercre_exch::Constraints;
