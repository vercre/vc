//! # Endpoint to accept an offer
//! 
//! Used to update the issuance status to `Accepted` when the Holder has accepted an offer, or to
//! `PendingPin` when a user has accepted an offer and a PIN is required. To reject an offer and
//! clear the issuance state, use the reset endpoint.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager};
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::storer::CredentialStorer;
use crate::{Endpoint, Flow};

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Accept endpoint updates the issuance status to `Accepted` when the Holder has accepted an
    /// offer, or to `PendingPin` when a user has accepted an offer and a PIN is required.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn accept(&self) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            issuance: Issuance::default(),
        };

        vercre_core::Endpoint::handle_request(self, &(), ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    issuance: Issuance,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = ();
    type Response = ();

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt(&Flow::Issuance.to_string()).await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::Ready {
            err!(Err::InvalidRequest, "invalid issuance status");
        }
        let Some(grants) = &issuance.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        if grants.pre_authorized_code.is_none() {
            err!(Err::InvalidRequest, "no pre-authorized code");
        };
        self.issuance = issuance;

        Ok(self)
    }

    async fn process(&self, provider: &P, _req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Update the issuance status
        let mut issuance = self.issuance.clone();
        let Some(grants) = &issuance.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        let Some(pre_auth_code) = &grants.pre_authorized_code else {
            err!(Err::InvalidRequest, "no pre-authorized code");
        };
        if pre_auth_code.tx_code.is_some() {
            issuance.status = Status::PendingPin;
        } else {
            issuance.status = Status::Accepted;
        }
        provider.put_opt(&Flow::Issuance.to_string(), serde_json::to_vec(&issuance)?, None).await?;

        Ok(())
    }
}
