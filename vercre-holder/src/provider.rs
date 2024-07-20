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
pub use openid::provider::{Result, StateManager};
pub use openid::issuer::{IssuerMetadata, TxCode};
pub use proof::jose::jwk::PublicKeyJwk;
pub use proof::signature::{Algorithm, Signer, Verifier};
pub use storer::CredentialStorer;

/// A trait that combines all the provider traits required to be implemented
/// by holder clients.
#[allow(clippy::module_name_repetitions)]
pub trait HolderProvider:
    IssuerClient + VerifierClient + CredentialStorer + StateManager + Signer + Verifier + Clone
{
}
