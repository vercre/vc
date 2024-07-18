//! # Dynamic Client Registration Endpoint

use chrono::Utc;
use openid::issuer::{Provider, RegistrationRequest, RegistrationResponse, StateManager};
use openid::{Error, Result};
use tracing::instrument;

// use crate::shell;
use crate::state::State;

/// Registration request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn register(
    provider: impl Provider, request: &RegistrationRequest,
) -> Result<RegistrationResponse> {
    // shell(&mut ctx, provider.clone(), request, verify).await?;
    // shell(&mut ctx, provider, request, process).await
    verify(provider.clone(), request).await?;
    process(provider, request).await
}

async fn verify(provider: impl Provider, request: &RegistrationRequest) -> Result<()> {
    tracing::debug!("Context::verify");

    let buf = match StateManager::get(&provider, &request.access_token).await {
        Ok(buf) => buf,
        Err(e) => return Err(Error::ServerError(format!("State not found: {e}"))),
    };
    let state = State::try_from(buf)?;

    // token (access or acceptance) expiry
    let expires = state.expires_at.signed_duration_since(Utc::now()).num_seconds();
    if expires < 0 {
        return Err(Error::InvalidRequest("access Token has expired".into()));
    }

    Ok(())
}

async fn process(
    provider: impl Provider, request: &RegistrationRequest,
) -> Result<RegistrationResponse> {
    tracing::debug!("Context::process");

    let Ok(client_meta) = provider.register(&request.client_metadata).await else {
        return Err(Error::ServerError("Registration failed".into()));
    };

    Ok(RegistrationResponse {
        client_metadata: client_meta,
    })
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

        let response = register(provider, &request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".client_id" => "[client_id]",
        });
    }
}
