//! # Request Object Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created Authorization
//! Request Object.
//!
//! The Request Object is created by the Verifier when calling the `Create Request`
//! endpoint to create an Authorization Request. Instead of sending the Request
//! Object to the Wallet, the Verifier sends an Authorization Request containing a
//! `request_uri` which can be used to retrieve the saved Request Object.
//!
//! Per the [JWT VC Presentation Profile], the Request Object MUST be returned as an
//! encoded JWT.
//!
//! [JWT VC Presentation Profile]: (https://identity.foundation/jwt-vc-presentation-profile)

use openid::verifier::{
    Provider, RequestObjectRequest, RequestObjectResponse, RequestObjectType, StateManager,
};
use openid::{Error, Result};
use proof::jose::jws::{self, Type};
use tracing::instrument;

use crate::state::State;

/// Endpoint for the Wallet to request the Verifier's Request Object when engaged
/// in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn request_object(
    provider: impl Provider, request: &RequestObjectRequest,
) -> Result<RequestObjectResponse> {
    process(provider, request).await
}

async fn process(
    provider: impl Provider, request: &RequestObjectRequest,
) -> Result<RequestObjectResponse> {
    tracing::debug!("Context::process");

    // retrieve request object from state
    let buf = StateManager::get(&provider, &request.state)
        .await
        .map_err(|e| Error::ServerError(format!("issue fetching state: {e}")))?;
    let state = State::from_slice(&buf)
        .map_err(|e| Error::ServerError(format!("issue deserializing state: {e}")))?;
    let req_obj = state.request_object;

    // verify client_id (perhaps should use 'verify' method?)
    if req_obj.client_id != format!("{}/post", request.client_id) {
        return Err(Error::InvalidRequest("client ID mismatch".into()));
    }

    let jwt = jws::encode(Type::Request, &req_obj, provider.clone())
        .await
        .map_err(|e| Error::ServerError(format!("issue encoding jwt: {e}")))?;

    Ok(RequestObjectResponse {
        request_object: RequestObjectType::Jwt(jwt),
    })
}

#[cfg(test)]
mod tests {
    use dif_exch::PresentationDefinition;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use openid::verifier::{
        ClientIdScheme, ClientMetadataType, PresentationDefinitionType, RequestObject, ResponseType,
    };
    use test_utils::verifier::{Provider, VERIFIER_ID};

    use super::*;

    #[tokio::test]
    async fn request_jwt() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let state_key = "ABCDEF123456";
        let nonce = "1234567890";

        let req_obj = RequestObject {
            response_type: ResponseType::VpToken,
            client_id: format!("{VERIFIER_ID}/post"),
            state: Some(state_key.to_string()),
            nonce: nonce.to_string(),
            response_mode: Some("direct_post".into()),
            response_uri: Some(format!("{VERIFIER_ID}/post")),
            presentation_definition: PresentationDefinitionType::Object(
                PresentationDefinition::default(),
            ),
            client_id_scheme: Some(ClientIdScheme::RedirectUri),
            client_metadata: ClientMetadataType::Object(Default::default()),

            // TODO: populate these
            redirect_uri: None,
            scope: None,
        };

        let state = State::builder().request_object(req_obj).build().expect("should build state");
        StateManager::put(&provider, &state_key, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        let request = RequestObjectRequest {
            client_id: VERIFIER_ID.to_string(),
            state: state_key.to_string(),
        };
        let response = request_object(provider.clone(), &request).await.expect("response is valid");

        let RequestObjectType::Jwt(jwt_enc) = &response.request_object else {
            panic!("no JWT found in response");
        };

        let jwt: jws::Jwt<RequestObject> =
            jws::decode(&jwt_enc, &Provider::new()).await.expect("jwt is valid");

        assert_snapshot!("response", jwt);

        // request state should not exist
        assert!(StateManager::get(&provider, state_key).await.is_ok());
    }
}
