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

use std::fmt::Debug;

use core_utils::jws::{self, Type};
use openid4vc::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use openid4vc::presentation::{
    ClientIdScheme, PresentationDefinitionType, RequestObjectRequest, RequestObjectResponse,
    ResponseType,
};
use openid4vc::Result;
use provider::{Callback, ClientMetadata, Signer, StateManager};
use tracing::instrument;

use super::Endpoint;
use crate::state::State;

/// Request Object request handler.
impl<P> Endpoint<P>
where
    P: ClientMetadata + StateManager + Signer + Callback + Clone + Debug,
{
    /// Endpoint for the Wallet to request the Verifier's Request Object when engaged
    /// in a cross-device flow.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn request_object(
        &self, request: &RequestObjectRequest,
    ) -> Result<RequestObjectResponse> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: ClientMetadata + StateManager + Signer + Callback + Clone + Debug,
{
    type Provider = P;
    type Request = RequestObjectRequest;
    type Response = RequestObjectResponse;

    // TODO: return callback_id
    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // retrieve request object from state
        let buf = StateManager::get(provider, &request.state)
            .await
            .map_err(|e| Err::ServerError(format!("issue fetching state: {e}")))?;
        let state = State::from_slice(&buf)
            .map_err(|e| Err::ServerError(format!("issue deserializing state: {e}")))?;
        let req_obj = state.request_object;

        // verify client_id (perhaps should use 'verify' method?)
        if req_obj.client_id != format!("{}/post", request.client_id) {
            return Err(Err::InvalidRequest("client ID mismatch".into()));
        }

        let jwt = jws::encode(Type::Request, &req_obj, provider.clone())
            .await
            .map_err(|e| Err::ServerError(format!("issue encoding jwt: {e}")))?;

        Ok(RequestObjectResponse {
            request_object: None,
            jwt: Some(jwt),
        })
    }
}

#[cfg(test)]
mod tests {
    use dif_exch::PresentationDefinition;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use openid4vc::presentation::{ClientMetadataType, RequestObject};
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
        let response = Endpoint::new(provider.clone())
            .request_object(&request)
            .await
            .expect("response is valid");

        let jwt_enc = response.jwt.expect("jwt exists");
        let jwt: jws::Jwt<RequestObject> =
            jws::decode(&jwt_enc, &Provider::new()).await.expect("jwt is valid");

        assert_snapshot!("response", jwt);

        // request state should not exist
        assert!(StateManager::get(&provider, state_key).await.is_ok());
    }
}
