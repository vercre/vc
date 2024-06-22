//! # Issuance Offer Endpoint
//!
//! The offer endpoint processes an issuance offer request where the offer originates with an
//! issuer. The endpoint uses the holder client to get metadata and present the offer details for
//! acceptance/rejection by the holder.

use std::fmt::Debug;

use anyhow::anyhow;
use openid4vc::issuance::{CredentialConfiguration, CredentialOffer, MetadataRequest};
use tracing::instrument;
use uuid::Uuid;

use super::{Issuance, Status};
use crate::provider::{IssuerClient, StateManager};
use crate::Endpoint;

/// `OfferRequest` is the request to the `offer` endpoint to initiate an issuance flow.
#[derive(Clone, Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct OfferRequest {
    /// Wallet client identifier. This is used by the issuance service to issue an access token so
    /// should be unique to the holder's agent. Care should be taken to ensure this is not shared
    /// across holders in the case of headless, multi-tenant agents.
    pub client_id: String,
    /// The credential offer from the issuer.
    pub offer: CredentialOffer,
}

impl<P> Endpoint<P>
where
    P: IssuerClient + StateManager + Debug,
{
    /// Initiates the issuance flow triggered by a new credential offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn offer(&self, request: &OfferRequest) -> anyhow::Result<Issuance> {
        tracing::debug!("Endpoint::offer");

        if request.offer.credential_configuration_ids.is_empty() {
            let e = anyhow!("no credential IDs");
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        }
        let Some(grants) = &request.offer.grants else {
            let e = anyhow!("no grants");
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        };
        if grants.pre_authorized_code.is_none() {
            let e = anyhow!("no pre-authorized code");
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        }

        // Establish a new issuance flow state
        let mut issuance = Issuance {
            id: Uuid::new_v4().to_string(),
            client_id: request.client_id.clone(),
            status: Status::Offered,
            ..Default::default()
        };

        // Set up a credential configuration for each credential offered
        issuance.offer = request.offer.clone();
        for id in &request.offer.credential_configuration_ids {
            issuance.offered.insert(id.into(), CredentialConfiguration::default());
        }

        // Process the offer and establish a metadata request, passing that to the provider to
        // use.
        let md_request = MetadataRequest {
            credential_issuer: request.offer.credential_issuer.clone(),
            languages: None, // The wallet client should provide any specific languages required.
        };

        // The wallet client's provider makes the metadata request to the issuer.
        let md_response = match self.provider.get_metadata(&issuance.id, &md_request).await {
            Ok(md) => md,
            Err(e) => {
                tracing::error!(target: "Endpoint::offer", ?e);
                return Err(e);
            }
        };

        // Update the flow state with issuer's metadata.
        let creds_supported = &md_response.credential_issuer.credential_configurations_supported;

        for (cfg_id, cred_cfg) in &mut issuance.offered {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                let e = anyhow!("unsupported credential type in offer");
                tracing::error!(target: "Endpoint::offer", ?e);
                return Err(e);
            };
            *cred_cfg = found.clone();
        }
        issuance.status = Status::Ready;

        // Stash the state for the next step.
        if let Err(e) = self.put_issuance(&issuance).await {
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        };

        Ok(issuance)
    }
}
