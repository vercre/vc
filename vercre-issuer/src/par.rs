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
    Metadata, Provider, PushedAuthorizationRequest, PushedAuthorizationResponse, StateStore,
};
use vercre_openid::{Error, Result};

use crate::authorize;
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
    provider: impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    verify(&provider, &request).await?;
    process(&provider, request).await
}

// Verify the pushed Authorization Request.
#[allow(clippy::unused_async)]
async fn verify(provider: &impl Provider, request: &PushedAuthorizationRequest) -> Result<()> {
    tracing::debug!("par::verify");

    // TODO: authenticate the client in the same way as at the token endpoint
    //       (client assertion)

    let req_obj = &request.request;

    // verify the pushed RequestObject using `/authorize` endpoint logic
    let Ok(issuer) = Metadata::issuer(provider, &req_obj.credential_issuer).await else {
        return Err(Error::InvalidClient("invalid `credential_issuer`".into()));
    };
    let mut ctx = authorize::Context {
        issuer,
        ..authorize::Context::default()
    };
    ctx.verify(provider, &request.request).await?;

    Ok(())
}

// Process the pushed Authorization Request.
#[allow(dead_code)]
async fn process(
    provider: &impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    tracing::debug!("par::process");

    // generate a request URI and expiry between 5 - 600 secs
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", gen::uri_token());
    let expires_in = Duration::seconds(600);

    // save request to state for retrieval by authorization endpoint
    let state = State {
        subject_id: None,
        stage: Stage::PushedAuthorization(PushedAuthorization {
            request: request.request.clone(),
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
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use test_utils::snapshot;
    use vercre_openid::issuer::AuthorizationRequest;

    use super::*;

    #[tokio::test]
    async fn request() {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        let value = json!({
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
        let request = serde_json::from_value(value).expect("request is valid");

        let AuthorizationRequest::Object(req_obj) = request else {
            panic!("Invalid Authorization Request");
        };

        let request = PushedAuthorizationRequest {
            request: req_obj,
            client_assertion: None,
        };
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
