//! # Pushed Authorization Request Endpoint [RFC9126]
//!
//! This endpoint allows clients to push the payload of an authorization request
//! to the server, returning a request URI to use in a subsequent call to the
//! authorization endpoint.
//!
//! [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)

use chrono::{Duration, Utc};
use tracing::instrument;
use vercre_core::gen;
use vercre_openid::issuer::{
    AuthorizationRequest, Provider, PushedAuthorizationResponse, StateStore,
};
use vercre_openid::{Error, Result};

use crate::state::{PushedAuthorization, Stage, State};

/// Endpoint for the Wallet to push an Authorization Request when using Pushed
/// Authorization Requests.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn par(
    provider: impl Provider, request: AuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    verify(&provider, &request).await?;
    process(&provider, request).await
}

#[allow(dead_code)]
#[allow(clippy::unused_async)]
async fn verify(_provider: &impl Provider, _request: &AuthorizationRequest) -> Result<()> {
    tracing::debug!("par::verify");

    // TODO: Authenticate the client in the same way as at the token endpoint
    // TODO: Validate the pushed request as for authorization endpoint

    Ok(())
}

#[allow(dead_code)]
async fn process(
    provider: &impl Provider, request: AuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    tracing::debug!("par::process");

    // generate a request URI and expiry between 5 - 600 secs
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", gen::uri_token());
    let expires_in = Duration::seconds(600);

    // save request to state for retrieval by authorization endpoint
    let state = State {
        subject_id: None,
        stage: Stage::PushedAuthorization(PushedAuthorization {
            request: request.clone(),
            expires_at: Utc::now() + expires_in,
        }),
        expires_at: Utc::now() + expires_in,
    };
    StateStore::put(provider, &request_uri, &state, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(PushedAuthorizationResponse {
        request_uri,
        expires_in: expires_in.num_seconds(),
    })
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use insta::assert_yaml_snapshot as assert_snapshot;
    // use rstest::rstest;
    use sha2::{Digest, Sha256};
    use vercre_macros::authorization_request;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;
    extern crate self as vercre_issuer;

    #[tokio::test]
    async fn request() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        let request = authorization_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "EmployeeID_JWT",
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        });
        let response = par(provider.clone(), request).await.expect("response is valid");
        assert_snapshot!("par:request:response", response, {
            ".request_uri" => "[request_uri]",
        });

        // check saved state
        let state =
            StateStore::get::<State>(&provider, &response.request_uri).await.expect("state exists");
        assert_snapshot!(format!("par:request:state"), state, {
            ".expires_at" => "[expires_at]",
            ".stage.expires_at" => "[expires_at]"
        });
    }
}
