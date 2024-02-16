//! # Dynamic Client Registration

use std::fmt::Debug;

use anyhow::anyhow;
use chrono::Utc;
use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::vci::{RegistrationRequest, RegistrationResponse};
use vercre_core::{err, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Handler;
use crate::state::State;

/// Registration request handler.
impl<P> Handler<P, RegistrationRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<RegistrationResponse> {
        trace!("Handler::call");
        self.handle_request(Context::new()).await
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Client,
{
    // client_meta: ClientMetadata,
    provider: Option<P>,
}

impl<P> Context<P>
where
    P: Client,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");
        Self { provider: None }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + StateManager + Debug,
{
    type Provider = P;
    type Request = RegistrationRequest;
    type Response = RegistrationResponse;

    #[instrument]
    async fn init(&mut self, req: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        self.provider = Some(provider);
        Ok(self)
    }

    #[instrument]
    async fn verify(&self, req: &Self::Request) -> Result<&Self> {
        trace!("Context::verify");

        let Some(provider) = &self.provider else {
            err!("State manager not set");
        };

        let buf = match StateManager::get(provider, &req.access_token).await {
            Ok(buf) => buf,
            Err(e) => err!(Err::ServerError(e), "State not found"),
        };
        let state = State::try_from(buf)?;

        // token (access or acceptance) expiry
        let expires = state.expires_at.signed_duration_since(Utc::now()).num_seconds();
        if expires < 0 {
            err!(Err::InvalidRequest, "Access Token has expired");
        }

        Ok(self)
    }

    #[instrument]
    async fn process(&self, req: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        let Some(provider) = &self.provider else {
            err!("State manager not set");
        };

        let Ok(client_meta) = provider.register(&req.client_metadata).await else {
            err!("Registration failed");
        };

        Ok(RegistrationResponse {
            client_metadata: client_meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER};
    use test_utils::wallet;

    use super::*;
    use crate::state::{Expire, State, TokenState};

    #[tokio::test]
    async fn registration_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";

        // set up state
        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .build();

        state.token = Some(TokenState {
            access_token: access_token.to_string(),
            token_type: "Bearer".to_string(),
            ..Default::default()
        });

        StateManager::put(&&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state saved");

        let body = json!({
            "client_id": wallet::did(),
            "redirect_uris": [
                "http://localhost:3000/callback"
            ],
            "grant_types": [
                "authorization_code",
                "urn:ietf:params:oauth:grant-type:pre-authorized_code"
            ],
            "response_types": [
                "code"
            ],
            "scope": "openid credential",
            "credential_offer_endpoint": "openid-credential-offer://"
        });

        let mut request = serde_json::from_value::<RegistrationRequest>(body)
            .expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        request.access_token = access_token.to_string();

        let response = Handler::new(&provider, request).call().await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".client_id" => "[client_id]",
        });
    }
}
