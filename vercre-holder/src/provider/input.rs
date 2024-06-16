//! # Input provider
//!
//! These providers allow for feedback from the wallet client's "holder" for things such as
//! accepting a credential offer, entering a PIN, authorizing a presentation request, etc. Where
//! the holder is a human, the client might implement this provider through a GUI or CLI, for
//! example.
use std::collections::HashMap;
use std::future::Future;

use openid4vc::issuance::CredentialConfiguration;
use openid4vc::issuance::TxCode;

use crate::credential::Credential;

/// `IssuanceInput` is a provider that allows the wallet client to provide input to the issuance
/// flow.
#[allow(clippy::module_name_repetitions)]
pub trait IssuanceInput {
    /// Accept (true) or reject (false) an issuance offer.
    // TODO: All credentials offered accepted/rejected, or can we accept some and reject others?
    fn accept(
        &self, flow_id: &str, config: &HashMap<String, CredentialConfiguration>,
    ) -> impl Future<Output = bool> + Send;

    /// Provide a PIN.
    fn pin(&self, flow_id: &str, tx_code: &TxCode) -> impl Future<Output = String> + Send;
}

/// `PresentationInput` is a provider that allows the wallet client to provide input to the
/// presentation flow.
#[allow(clippy::module_name_repetitions)]
pub trait PresentationInput {
    /// Authorize (true) or reject (false) a presentation request.
    fn authorize(
        &self, flow_id: &str, credentials: Vec<Credential>,
    ) -> impl Future<Output = bool> + Send;
}
