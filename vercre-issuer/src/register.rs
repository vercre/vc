//! # Dynamic Client Registration Endpoint

use tracing::instrument;
use vercre_openid::issuer::{Provider, RegistrationRequest, RegistrationResponse, StateStore};
use vercre_openid::{Error, Result};

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
    verify(provider.clone(), request).await?;
    process(provider, request).await
}

async fn verify(provider: impl Provider, request: &RegistrationRequest) -> Result<()> {
    tracing::debug!("register::verify");

    // verify state is still accessible (has not expired)
    match StateStore::get::<State>(&provider, &request.access_token).await {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::ServerError(format!("State not found: {e}"))),
    }
}

async fn process(
    provider: impl Provider, request: &RegistrationRequest,
) -> Result<RegistrationResponse> {
    tracing::debug!("register::process");

    let Ok(client_meta) = provider.register(&request.client_metadata).await else {
        return Err(Error::ServerError("Registration failed".into()));
    };

    Ok(RegistrationResponse {
        client_metadata: client_meta,
    })
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER};

    use super::*;
    use crate::state::{Expire, Step, Token};

    #[tokio::test]
    async fn registration_ok() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "ABCDEF";

        // set up state
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            ..State::default()
        };

        state.current_step = Step::Token(Token {
            access_token: access_token.to_string(),
            ..Token::default()
        });

        StateStore::put(&provider, access_token, &state, state.expires_at)
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
