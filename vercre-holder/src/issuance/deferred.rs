//! # Deferred Credentials Endpoint
//!
//! Use a previously issued transaction ID to retrieve a credential.

use anyhow::bail;
use vercre_issuer::DeferredCredentialRequest;

use super::{IssuanceState, Status};

impl IssuanceState {
    /// Construct a deferred credential request.
    ///
    /// # Errors
    /// Will return an error if the issuance state is not consistent with
    /// constructing such a request.
    pub fn deferred_request(&self, transaction_id: &str) -> anyhow::Result<DeferredCredentialRequest> {
        if self.status != Status::TokenReceived {
            bail!("invalid issuance state status");
        }
        let Some(token_response) = &self.token else {
            bail!("token not found in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata on issuance state");
        };
        let def_cred_request = DeferredCredentialRequest {
            transaction_id: transaction_id.into(),
            credential_issuer: issuer.credential_issuer.clone(),
            access_token: token_response.access_token.clone(),
        };
        Ok(def_cred_request)
    }

    /// Add a deferred transaction ID to the issuance state.
    pub fn add_deferred(&mut self, tx_id: &String, cfg_id: &String) {
        self.deferred.insert(tx_id.into(), cfg_id.into());
    }

    /// Remove a pending deferred credential transaction from state.
    pub fn remove_deferred(&mut self, transaction_id: &str) {
        self.deferred.remove(transaction_id);
    }
}
