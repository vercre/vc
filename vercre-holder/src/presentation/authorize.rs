//! # Issuance Authorization Endpoint
//!
//! The authorize endpoint receives confirmation from the holder that they authorize the agent to
//! present the credential to the verifier.

use std::fmt::Debug;

use chrono::{DateTime, Utc};
use openid4vc::error::Err;
use openid4vc::{err, Result};
use tracing::instrument;

use super::{Presentation, Status};
use crate::provider::{Callback, StateManager, VerifierClient};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + StateManager + VerifierClient + Debug,
{
    /// Updates the status of the flow as authorized. The request is the presentation flow ID
    /// generated by the `request` endpoint.
    #[instrument(level = "debug", skip(self))]
    pub async fn authorize(&self, request: String) -> Result<Presentation> {
        let ctx = Context {
            presentation: Presentation::default(),
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, &request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    presentation: Presentation,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = String;
    type Response = Presentation;

    // Get current state of flow and check internals for consistency with request.
    async fn verify(&mut self, provider: &Self::Provider, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        let current_state = provider.get(req).await?;
        let Ok(presentation) = serde_json::from_slice::<Presentation>(&current_state) else {
            err!(Err::InvalidRequest, "unable to decode presentation state");
        };

        if presentation.status != Status::Requested {
            err!(Err::InvalidRequest, "Invalid presentation state");
        }
        self.presentation = presentation;
        Ok(self)
    }

    // Update the presentation state to authorized and stash the state for the next step
    async fn process(
        &self, provider: &Self::Provider, _req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");
        let mut presentation = self.presentation.clone();
        presentation.status = Status::Authorized;
        provider.put(&presentation.id, serde_json::to_vec(&presentation)?, DateTime::<Utc>::MAX_UTC).await?;
        Ok(presentation)
    }
}
