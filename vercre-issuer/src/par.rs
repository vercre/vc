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
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_openid::issuer::{AuthorizationRequest, CreateOfferRequest, OfferType, SendType};
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn request() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let create_req = CreateOfferRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
            subject_id: Some(NORMAL_USER.to_string()),
            pre_authorize: true,
            tx_code_required: true,
            send_type: SendType::ByRef,
        };
        let create_resp =
            crate::create_offer(provider.clone(), create_req).await.expect("should create offer");

        let OfferType::Uri(uri) = create_resp.offer_type else {
            panic!("no URI found in response");
        };
        let Some(_id) = uri.strip_prefix(&format!("{CREDENTIAL_ISSUER}/credential_offer/")) else {
            panic!("should have prefix");
        };

        let offer_req = AuthorizationRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            // id: id.to_string(),
            ..Default::default()
        };
        let response = par(provider, offer_req).await.expect("response is valid");

        assert_snapshot!("par:request:response", response,  {
            // ".credential_offer.grants.authorization_code.issuer_state" => "[issuer_state]",
            r#".**["pre-authorized_code"]"# => "[pre-authorized_code]",
        });
    }
}
