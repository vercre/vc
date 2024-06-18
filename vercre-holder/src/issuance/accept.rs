//! # Issuance Offer Acceptance
//!
//! The `accept` endpoint is used to register acceptance of a credential issuance offer with the
//! issuance flow. If a PIN is required, this endpoint will simply update the state to indicate
//! that, otherwise it will proceed with the token request and credential requests.

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
    /// Progresses the issuance flow triggered by a holder accepting a credential offer.
    /// The request is the issuance flow ID.
    #[instrument(level = "debug", skip(self))]
    pub async fn accept(&self, request: String) -> Result<Issuance> {
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

        // Get current state of flow and check internals for consistency with request.
        let current_state = provider.get(req).await?;
        let Ok(issuance) = serde_json::from_slice::<Issuance>(&current_state) else {
            err!(Err::InvalidRequest, "unable to decode issuance state");
        };

        if issuance.status != Status::Ready {
            err!(Err::InvalidRequest, "Invalid issuance state");
        }
        let Some(grants) = &issuance.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        if grants.pre_authorized_code.is_none() {
            err!(Err::InvalidRequest, "no pre-authorized code");
        }
        self.issuance = issuance;
        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, _req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut issuance = self.issuance.clone();

        // Check if PIN is required. Unwraps are OK because we've already checked these fields in
        // verify.
        let grants = self.issuance.offer.grants.as_ref().expect("grants exist on offer");
        let pre_auth_code =
            grants.pre_authorized_code.as_ref().expect("pre-authorized code exists on offer");
        if pre_auth_code.tx_code.is_some() {
            issuance.status = Status::PendingPin;
        } else {
            issuance.status = Status::Accepted;
        }

        // Stash the state for the next step.
        provider
            .put(&issuance.id, serde_json::to_vec(&issuance)?, DateTime::<Utc>::MAX_UTC)
            .await?;

        Ok(issuance)
    }
}
