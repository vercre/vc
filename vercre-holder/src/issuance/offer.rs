//! # Issuance Offer Endpoint
//!
//! The offer endpoint processes an issuance offer request where the offer originates with an
//! issuer. The endpoint uses the holder client to get metadata and present the offer details for
//! acceptance/rejection by the holder.

use std::fmt::Debug;

use tracing::instrument;
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::metadata::CredentialConfiguration;
use vercre_core::vci::{CredentialOffer, MetadataRequest};
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::provider::{Callback, IssuerClient};
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
    P: Callback + IssuerClient + Debug,
{
    /// Orchestrates the issuance flow triggered by a new credential offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn offer(&self, request: &OfferRequest) -> Result<Issuance> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: IssuerClient + Debug + Sync + Send,
{
    type Provider = P;
    type Request = OfferRequest;
    type Response = Issuance;

    async fn verify(&mut self, _provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        if req.offer.credential_configuration_ids.is_empty() {
            err!(Err::InvalidRequest, "no credential IDs");
        }
        let Some(grants) = &req.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        if grants.pre_authorized_code.is_none() {
            err!(Err::InvalidRequest, "no pre-authorized code");
        }

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        // Establish a new issuance flow state
        let mut issuance = Issuance {
            id: Uuid::new_v4().to_string(),
            status: Status::Offered,
            ..Default::default()
        };
        // Set up a credential configuration for each credential offered
        issuance.offer = req.offer.clone();
        for id in &req.offer.credential_configuration_ids {
            issuance.offered.insert(id.into(), CredentialConfiguration::default());
        }

        // Process the offer and establish a metadata request, passing that to the provider to
        // use.
        let md_request = MetadataRequest {
            credential_issuer: req.offer.credential_issuer.clone(),
            languages: None, // The wallet client should provide any specific languages required.
        };

        // The wallet client's provider makes the metadata request to the issuer.
        let md_response = provider.get_metadata(&issuance.id, &md_request).await?;

        // Update the flow state with issuer's metadata.
        let creds_supported = &md_response.credential_issuer.credential_configurations_supported;

        for (cfg_id, cred_cfg) in &mut issuance.offered {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                err!(Err::InvalidRequest, "unsupported credential type in offer");
            };
            *cred_cfg = found.clone();
        }
        issuance.status = Status::Ready;

        Ok(issuance)
    }
}
