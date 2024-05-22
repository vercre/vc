//! # PIN endpoint.
//!
//! Used to set a Personal Identification Number (PIN) for a token request.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager, Storer};
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Storer + Clone + Debug,
{
    /// PIN endpoint receives a PIN from the wallet client, stashes it in state for use later in
    /// the flow, and updates the issuance status.
    #[instrument(level = "debug", skip(self))]
    pub async fn pin(&self, request: &String) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            issuance: Issuance::default(),
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
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
    type Request = String;
    type Response = ();

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt("issuance").await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::PendingPin {
            err!(Err::InvalidRequest, "invalid issuance status");
        }
        self.issuance = issuance;

        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut issuance = self.issuance.clone();
        issuance.pin = Some(req.clone());
        issuance.status = Status::Accepted;
        provider.put_opt("issuance", serde_json::to_vec(&issuance)?, None).await?;

        Ok(())
    }
}
