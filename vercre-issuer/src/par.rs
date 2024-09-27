//! # Pushed Authorization Request Endpoint
//!
//! This endpoint allows clients to push the payload of an authorization request
//! to the server, returning a request URI to use in a subsequent call to the
//! authorization endpoint.
//!
//! [PAR]: (https://www.rfc-editor.org/rfc/rfc9126.html)

use tracing::instrument;
use vercre_openid::issuer::{
    Provider, PushedAuthorizationRequest, PushedAuthorizationResponse, StateStore,
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
    provider: impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    process(&provider, request).await
}

async fn process(
    provider: &impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    tracing::debug!("par::process");

    let Stage::Par(par) = &state.stage else {
        return Err(Error::InvalidRequest("no offer found".into()));
    };
    StateStore::put(provider, &state_key, &state, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(PushedAuthorizationResponse { .. })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_openid::issuer::{CreateOfferRequest, OfferType, SendType};
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;

    #[tokio::test]
    async fn request_jwt() {
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
        let Some(id) = uri.strip_prefix(&format!("{CREDENTIAL_ISSUER}/credential_offer/")) else {
            panic!("should have prefix");
        };

        let offer_req = PushedAuthorizationRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            id: id.to_string(),
        };
        let offer_resp = credential_offer(provider, offer_req).await.expect("response is valid");

        assert_snapshot!("credential_offer:request_jwt:response", offer_resp,  {
            // ".credential_offer.grants.authorization_code.issuer_state" => "[issuer_state]",
            r#".**["pre-authorized_code"]"# => "[pre-authorized_code]",
        });
    }
}
