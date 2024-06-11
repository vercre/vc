//! # Dynamic Client Registration Endpoint

use std::fmt::Debug;

use anyhow::anyhow;
use chrono::Utc;
use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
pub use vercre_core::vci::{RegistrationRequest, RegistrationResponse};
use vercre_core::{err, Result};
use vercre_vc::proof::Signer;

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
        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
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
            Err(e) => err!(Err::ServerError(anyhow::anyhow!(e)), "State not found"),
        };
        let state = State::try_from(buf)?;

        // token (access or acceptance) expiry
        let expires = state.expires_at.signed_duration_since(Utc::now()).num_seconds();
        if expires < 0 {
            err!(Err::InvalidRequest, "access Token has expired");
        }

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let Ok(client_meta) = provider.register(&request.client_metadata).await else {
            err!("Registration failed");
        };

        Ok(RegistrationResponse {
            client_metadata: client_meta,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use providers::issuance::{Provider, ISSUER};
    use providers::wallet;
    use serde_json::json;

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
            .credential_issuer(ISSUER.to_string())
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
            "client_id": wallet::CLIENT_ID,
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

        let response = Endpoint::new(provider).register(&request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".client_id" => "[client_id]",
        });
    }
}
