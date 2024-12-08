//! # Issuance Offer Endpoint
//!
//! The offer endpoint processes an issuance offer request where the offer
//! originates with an issuer. The endpoint uses the holder client to get
//! metadata and present the offer details for acceptance/rejection by the
//! holder.

use std::collections::HashMap;

use anyhow::anyhow;
use vercre_openid::issuer::{CredentialConfiguration, CredentialOffer};

use super::{IssuanceState, Status};

impl IssuanceState {
    /// Update the issuance state with the issuer's offer information.
    ///
    /// Requires issuer and oauth server metadata to be set.
    ///
    /// # Errors
    /// Will return an error if the state is not in the correct state to apply
    /// an offer.
    pub fn offer(
        &mut self, offer: &CredentialOffer,
    ) -> anyhow::Result<HashMap<String, CredentialConfiguration>> {
        // Check current state is valid for this operation.
        if self.status != Status::AuthServerSet {
            let e = anyhow!("invalid state to apply an offer");
            tracing::error!(target: "IssuanceState::offer", ?e);
            return Err(e);
        }

        self.offer = Some(offer.clone());
        self.status = Status::Offered;
        self.offered()
    }

    /// Convenience method to get the credential configurations in the offer in
    /// a way that makes it easier to present to the holder.
    /// 
    /// # Errors
    /// Will return an error if the issuer metadata has not been set on the flow
    /// or an attempt is made to call this function before setting an offer on
    /// the flow state.
    pub fn offered(&self) -> anyhow::Result<HashMap<String, CredentialConfiguration>> {
        // Explicitly extract the credential configurations from the issuer
        // metadata that match the credentials on offer to make it easier to
        // present to the holder.
        let Some(issuer) = &self.issuer else {
            let e = anyhow!("issuer metadata has not been set on flow state");
            tracing::error!(target: "IssuanceState::offered", ?e);
            return Err(e);
        };
        let Some(offer) = &self.offer else {
            let e = anyhow!("offer has not been set on flow state");
            tracing::error!(target: "IssuanceState::offered", ?e);
            return Err(e);
        };
        let mut offered = HashMap::<String, CredentialConfiguration>::new();
        let creds_supported = &issuer.credential_configurations_supported;
        for cfg_id in &offer.credential_configuration_ids {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                let e = anyhow!("unsupported credential type in offer");
                tracing::error!(target: "IssuanceState::offer", ?e);
                return Err(e);
            };
            offered.insert(cfg_id.clone(), found.clone());
        }
        Ok(offered)
    }
}
