//! # Issuance Offer Set PIN
//!
//! The `pin` endpoint is used to set a PIN for use in the token request as part of the issuance
//! flow.

use std::fmt::Debug;

use chrono::{DateTime, Utc};
use openid4vc::error::Err;
use openid4vc::{err, Result};
use tracing::instrument;

use crate::issuance::{Issuance, Status};
use crate::provider::{Callback, StateManager};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + StateManager + Debug,
{
    /// Progresses the issuance flow triggered by a holder setting a PIN.
    /// The request is the issuance flow ID.
    #[instrument(level = "debug", skip(self))]
    pub async fn pin(&self, request: String) -> Result<Issuance> {
        let ctx = Context {
            issuance: Issuance::default(),
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, &request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    issuance: Issuance,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = String;
    type Response = Issuance;
    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        println!("verifying PIN request");

        // Get current state of flow and check internals for consistency with request.
        let current_state = provider.get(req).await?;
        let Ok(issuance) = serde_json::from_slice::<Issuance>(&current_state) else {
            err!(Err::InvalidRequest, "unable to decode issuance state");
        };

        if issuance.status != Status::PendingPin {
            err!(Err::InvalidRequest, "Invalid issuance state");
        };

        println!("restored issuance from state {issuance:?}");

        self.issuance = issuance;
        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        println!("processing PIN request");

        // Update the state of the flow to indicate the PIN has been set.
        let mut issuance = self.issuance.clone();
        issuance.pin = Some(req.clone());
        issuance.status = Status::Accepted;

        // Stash the state for the next step.
        provider
            .put(&issuance.id, serde_json::to_vec(&issuance)?, DateTime::<Utc>::MAX_UTC)
            .await?;

        println!("PIN set");

        Ok(issuance)
    }
}
