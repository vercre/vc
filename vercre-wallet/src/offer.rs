//! # Offer endpoint.
//!
//! Used for receiving a credential offer from an issuer.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::metadata::CredentialConfiguration;
use vercre_core::provider::{Callback, Client, Signer, StateManager, Storer};
use vercre_core::vci::CredentialOffer;
use vercre_core::{err, Result};

use super::Endpoint;
use crate::issuance::model::{Issuance, Status};

impl<P> Endpoint<P>
where
    P: Callback + Client + Signer + StateManager + Storer + Clone + Debug,
{
    /// Receive offer endpoint receives a a credential offer request from an issuer. Returns the
    /// credential issuer URL which can be used to retrieve metadata. It is the responsibility of
    /// the client to retrieve the metadata and pass it to the wallet's metadata endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn offer(&self, request: &CredentialOffer) -> Result<String> {
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
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = CredentialOffer;
    type Response = String;

    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        if req.credential_configuration_ids.is_empty() {
            err!(Err::InvalidRequest, "no credential IDs");
        }
        if req.grants.is_none() {
            err!(Err::InvalidRequest, "no grants");
        }

        // Do not progress if an issuance is already being processed for this offer.
        let stashed_issuance = provider.get_opt("issuance").await?;
        if stashed_issuance.is_some() {
            err!(Err::InvalidRequest, "credential already being processed");
        }

        Ok(self)
    }

    /// Populate the state store with the credential offer and an Offered status.
    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Stash the offer in state so it can be retrieved for further use in the issuance flow
        let mut issuance = Issuance {
            offer: req.clone(),
            status: Status::Offered,
            ..Default::default()
        };
        for id in req.credential_configuration_ids.iter() {
            issuance.offered.insert(id.to_owned(), CredentialConfiguration::default());
        }
        provider.put_opt("issuance", serde_json::to_vec(&issuance)?, None).await?;

        Ok(req.credential_issuer.clone())
    }
}
