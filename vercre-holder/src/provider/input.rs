//! # Input provider
//!
//! These providers allow for feedback from the wallet client's "holder" for things such as
//! accepting a credential offer, entering a PIN, authorizing a presentation request, etc. Where
//! the holder is a human, the client might implement this provider through a GUI or CLI, for
//! example.
use std::future::Future;

use crate::credential::Credential;

// TODO: Remove this.

/// `PresentationInput` is a provider that allows the wallet client to provide input to the
/// presentation flow.
#[allow(clippy::module_name_repetitions)]
pub trait PresentationInput {
    /// Authorize (true) or reject (false) a presentation request.
    fn authorize(
        &self, flow_id: &str, credentials: Vec<Credential>,
    ) -> impl Future<Output = bool> + Send;
}
