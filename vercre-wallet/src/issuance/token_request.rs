//! # Token Request endpoint.
//! 
//! Used to build a token request that can be sent to the issuer to retrieve an access token that
//! can be used to exchange for credentials.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager};
use vercre_core::vci::{GrantType, TokenRequest};
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::storer::CredentialStorer;
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Token request endpoint uses the issuance state to construct a token request that the wallet
    /// client can send to the issuance service.
    #[instrument(level = "debug", skip(self))]
    pub async fn token_request(&self, request: &String) -> Result<TokenRequest> {
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
    type Response = TokenRequest;

    async fn verify(&mut self, provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Check we are processing an offer and we are at the expected point in the flow.
        let Some(stashed) = provider.get_opt("issuance").await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.status != Status::Accepted {
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

    async fn process(&self, _provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // pre-authorized flow
        let Some(grants) = &self.issuance.offer.grants else {
            err!(Err::InvalidRequest, "Missing grants");
        };
        let Some(pre_auth_code) = &grants.pre_authorized_code else {
            err!(Err::InvalidRequest, "No pre-authorized code");
        };

        let req = TokenRequest {
            credential_issuer: self.issuance.offer.credential_issuer.clone(),
            client_id: req.clone(),
            grant_type: GrantType::PreAuthorizedCode,
            pre_authorized_code: Some(pre_auth_code.pre_authorized_code.clone()),
            user_code: self.issuance.pin.clone(),

            ..Default::default()
        };

        Ok(req)
    }
}
