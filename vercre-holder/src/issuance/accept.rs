//! # Issuance Offer Acceptance
//! 
//! The `accept` endpoint is used to register acceptance of a credential issuance offer with the
//! issuance flow. If a PIN is required, this endpoint will simply update the state to indicate
//! that, otherwise it will proceed with the token request and credential requests.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::provider::{Callback, CredentialStorer, IssuerClient, Signer};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + CredentialStorer + IssuerClient + Signer + Debug,
{
    /// Progresses the issuance flow triggered by a holder accepting a credential offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn accept(&self, request: &Issuance) -> Result<Issuance> {
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
    P: CredentialStorer + IssuerClient + Signer + Debug,
{
    type Provider = P;
    type Request = Issuance;
    type Response = Issuance;

    async fn verify(&mut self, _provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");
        if req.status != Status::Offered {
            err!(Err::InvalidRequest, "Invalid issuance state");
        }
        let Some(grants) = &req.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        if grants.pre_authorized_code.is_none() {
            err!(Err::InvalidRequest, "no pre-authorized code");
        }
        Ok(self)
    }

    async fn process(&self, _provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut new_state = req.clone();

        // Check if PIN is required. Unwraps are OK because we've already checked these fields in
        // verify.
        let grants = req.offer.grants.as_ref().expect("grants exist on offer");
        let pre_auth_code =
            grants.pre_authorized_code.as_ref().expect("pre-authorized code exists on offer");
        if pre_auth_code.tx_code.is_some() {
            new_state.status = Status::PendingPin;
            return Ok(new_state);
        };
        new_state.status = Status::Accepted;
        Ok(new_state)
    }
}