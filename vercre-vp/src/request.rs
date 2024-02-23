//! # Request Object Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created Authorization
//! Request Object.
//!
//! The Request Object is created by the Verifier when calling the `Initiate` endpoint to
//! create an Authorization Request. Instead of sending the Request Object to the Wallet,
//! the Verifier sends an Authorization Request containing a `request_uri` which can be
//! used to retrieve the saved Request Object.
//!
//! Per the [JWT VC Presentation Profile], the Request Object MUST be returned as an
//! encoded JWT.
//!
//! [JWT VC Presentation Profile]: https://identity.foundation/jwt-vc-presentation-profile

use std::fmt::Debug;

use anyhow::anyhow;
use tracing::{instrument, trace};
use vercre_core::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vp::{RequestObjectRequest, RequestObjectResponse};
use vercre_core::{err, Callback, Client, Result, Signer, StateManager};

use super::Endpoint;
use crate::state::State;

/// Request Object request handler.
impl<P> Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
{
    /// Endpoint for the Wallet to request the Verifier's Request Object when engaged
    /// in a cross-device flow.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn request_object(
        &self, request: impl Into<RequestObjectRequest>,
    ) -> Result<RequestObjectResponse> {
        self.handle_request(request.into(), Context {}).await
    }
}

#[derive(Debug)]
struct Context;

impl super::Context for Context {
    type Request = RequestObjectRequest;
    type Response = RequestObjectResponse;

    // TODO: return callback_id
    fn callback_id(&self) -> Option<String> {
        None
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + StateManager + Signer + Callback + Clone + Debug,
    {
        trace!("Context::process");

        // retrieve request object from state
        let Ok(buf) = StateManager::get(provider, &request.state).await else {
            err!("State not found");
        };
        let Ok(state) = State::from_slice(&buf) else {
            err!("State is expired or corrupted");
        };
        let req_obj = state.request_object;

        // verify client_id (perhaps should use 'verify' method?)
        if req_obj.client_id != format!("{}/post", request.client_id) {
            err!(Err::InvalidRequest, "Client ID mismatch");
        }

        let jwt = req_obj.to_jwt()?.sign(provider.clone()).await?;

        Ok(RequestObjectResponse {
            request_object: None,
            jwt: Some(jwt),
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use test_utils::vp_provider::{Provider, VERIFIER};
    use vercre_core::jwt::Jwt;
    use vercre_core::vp::RequestObject;

    use super::*;

    #[tokio::test]
    async fn request_jwt() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let state_key = "ABCDEF123456";
        let nonce = "1234567890";

        let req_obj = RequestObject {
            response_type: "vp_token".to_string(),
            client_id: format!("{VERIFIER}/post"),
            state: Some(state_key.to_string()),
            nonce: nonce.to_string(),
            response_mode: Some("direct_post".to_string()),
            response_uri: Some(format!("{VERIFIER}/post")),
            presentation_definition: None, // Some(pd.clone()),
            client_id_scheme: Some("redirect_uri".to_string()),
            client_metadata: None, // Some(self.client_meta.clone()),

            // TODO: populate these
            redirect_uri: None,
            scope: None,
            presentation_definition_uri: None,
            client_metadata_uri: None,
        };

        let state = State::builder().request_object(req_obj).build().expect("should build state");
        StateManager::put(&provider, &state_key, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        let request = RequestObjectRequest {
            client_id: VERIFIER.to_string(),
            state: state_key.to_string(),
        };
        let response = Endpoint::new(provider.clone())
            .request_object(request)
            .await
            .expect("response is valid");

        let jwt_enc = response.jwt.expect("jwt exists");
        let jwt = jwt_enc.parse::<Jwt<RequestObject>>().expect("jwt is valid");

        assert_snapshot!("response", jwt);

        // request state should not exist
        assert!(StateManager::get(&provider, state_key).await.is_ok());
    }
}
