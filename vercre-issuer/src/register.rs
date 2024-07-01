//! # Dynamic Client Registration Endpoint

use std::fmt::Debug;

use chrono::Utc;
use openid4vc::error::Err;
pub use openid4vc::issuance::{RegistrationRequest, RegistrationResponse};
use openid4vc::Result;
use endpoint::{Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject};
use tracing::instrument;
use w3c_vc::proof::Signer;

use super::Endpoint;
use crate::state::State;

impl<P> Endpoint<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Callback
        + Clone
        + Debug,
{
    /// Registration request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn register(&self, request: &RegistrationRequest) -> Result<RegistrationResponse> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };
        endpoint::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> endpoint::Context for Context<P>
where
    P: ClientMetadata + StateManager + Debug,
{
    type Provider = P;
    type Request = RegistrationRequest;
    type Response = RegistrationResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(
        &mut self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<&Self> {
        tracing::debug!("Context::verify");

        let buf = match StateManager::get(provider, &request.access_token).await {
            Ok(buf) => buf,
            Err(e) => return Err(Err::ServerError(format!("State not found: {e}"))),
        };
        let state = State::try_from(buf)?;

        // token (access or acceptance) expiry
        let expires = state.expires_at.signed_duration_since(Utc::now()).num_seconds();
        if expires < 0 {
            return Err(Err::InvalidRequest("access Token has expired".into()));
        }

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let Ok(client_meta) = provider.register(&request.client_metadata).await else {
            return Err(Err::ServerError("Registration failed".into()));
        };

        Ok(RegistrationResponse {
            client_metadata: client_meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER};

    use super::*;
    use crate::state::{Expire, Token};

    #[tokio::test]
    async fn registration_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";

        // set up state
        let mut state = State::builder()
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_issuer(CREDENTIAL_ISSUER.to_string())
            .build()
            .expect("should build state");

        state.token = Some(Token {
            access_token: access_token.to_string(),
            token_type: "Bearer".into(),
            ..Default::default()
        });

        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state saved");

        let body = json!({
            "client_id": CLIENT_ID,
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
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();
        request.access_token = access_token.to_string();

        let response = Endpoint::new(provider).register(&request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".client_id" => "[client_id]",
        });
    }
}
