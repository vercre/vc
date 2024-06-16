//! # Create Request Endpoint
//!
//! This endpoint is used to prepare an [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html)
//! Authorization Request to use to request Verifiable Presentations from an End-User's Wallet.
//!
//! While based on the [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html)
//! specification, the endpoint only implements a subset of the specification
//! requirements as recommended in the [JWT VC Presentation Profile](https://identity.foundation/jwt-vc-presentation-profile).
//! Aside from reducing complexity, the profile enables greater presentation
//! interoperability between Wallets and Verifiers.
//!
//! The Verifier requests an Authorization Request be prepared by articulating the
//! Credential(s) desired using a Credential Definition and, optionally, specifying
//! the device flow that will be used.
//!
//! # Example
//!
//! ```json
//! {
//!     "purpose": "To verify employment",
//!     "input_descriptors": [{
//!         "id": "employment",
//!         "constraints": {
//!             "fields": [{
//!                 "path":["$.type"],
//!                 "filter": {
//!                     "type": "string",
//!                     "const": "EmployeeIDCredential"
//!                 }
//!             }]
//!         }
//!     }],
//!     "device_flow": "CrossDevice"
//! }
//! ```
//!
//! The prepared Authorization Request Object may be sent by value or by reference as
//! defined in JWT-Secured Authorization Request (JAR) [RFC9101](https://www.rfc-editor.org/rfc/rfc9101).
//! If sent by value, the Request Object is sent directly to the Wallet as a URL fragment in the
//! Authorization Request. If by reference, the Authorization Request will contain a
//! `request_uri` pointing to the prepared Request Object.

use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::anyhow;
#[allow(clippy::module_name_repetitions)]
pub use openid4vc::presentation::{
    CreateRequestRequest, CreateRequestResponse, DeviceFlow, RequestObject,
};
use tracing::instrument;
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, ClientMetadata, StateManager};
use vercre_core::{err, gen, Result};
use vercre_exch::{Format, PresentationDefinition};
use vercre_vc::proof::{Algorithm, Signer};

use super::Endpoint;
use crate::state::State;

// TODO: request supported Client Identifier schemes from the Wallet
// TODO: add support for other Client Identifier schemes

// StaticConfigurationValues
// {
//   "authorization_endpoint": "openid4vp:",
//   "response_types_supported": [
//     "vp_token"
//   ],
//   "vp_formats_supported": {
//     "jwt_vp_json": {
//       "alg_values_supported": ["ES256"]
//     },
//     "jwt_vc_json": {
//       "alg_values_supported": ["ES256"]
//     }
//   },
//   "request_object_signing_alg_values_supported": [
//     "ES256"
//   ]
// }

/// `CreateRequest` Request handler.
impl<P> Endpoint<P>
where
    P: ClientMetadata + StateManager + Signer + Callback + Clone + Debug,
{
    /// Initiate an Authorization Request flow.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn create_request(
        &self, request: &CreateRequestRequest,
    ) -> Result<CreateRequestResponse> {
        let ctx = Context {
            callback_id: request.callback_id.clone(),
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: ClientMetadata + StateManager + Clone + Debug,
{
    type Provider = P;
    type Request = CreateRequestRequest;
    type Response = CreateRequestResponse;

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    async fn verify(&mut self, _: &Self::Provider, request: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        if request.input_descriptors.is_empty() {
            err!(Err::InvalidRequest, "no credentials specified");
        }
        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // TODO: build dynamically...
        let fmt = Format {
            alg: Some(vec![Algorithm::EdDSA.to_string()]),
            proof_type: None,
        };

        let pres_def = PresentationDefinition {
            id: Uuid::new_v4().to_string(),
            purpose: Some(request.purpose.clone()),
            input_descriptors: request.input_descriptors.clone(),
            format: Some(HashMap::from([("jwt_vc".into(), fmt)])),
            name: None,
        };
        let state_key = gen::state_key();

        // get client metadata
        let Ok(client_meta) = ClientMetadata::metadata(provider, &request.client_id).await else {
            err!(Err::InvalidRequest, "invalid client_id");
        };

        let mut req_obj = RequestObject {
            response_type: "vp_token".into(),
            state: Some(state_key.clone()),
            nonce: gen::nonce(),
            presentation_definition: Some(pres_def),
            client_metadata: Some(client_meta),
            client_id_scheme: Some("redirect_uri".into()),
            ..Default::default()
        };

        let mut response = CreateRequestResponse::default();

        // Response Mode "direct_post" is RECOMMENDED for cross-device flows.
        // TODO: replace hard-coded endpoints with Provider-set values
        if request.device_flow == DeviceFlow::CrossDevice {
            req_obj.response_mode = Some("direct_post".into());
            req_obj.client_id = format!("{}/post", request.client_id);
            req_obj.response_uri = Some(format!("{}/post", request.client_id));
            response.request_uri = Some(format!("{}/request/{state_key}", request.client_id));
        } else {
            req_obj.client_id = format!("{}/callback", request.client_id);
            response.request_object = Some(req_obj.clone());
        }

        // save request object in state
        let state = State::builder()
            .request_object(req_obj)
            .build()
            .map_err(|e| Err::ServerError(anyhow!(e)))?;
        StateManager::put(provider, &state_key, state.to_vec(), state.expires_at).await?;

        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use providers::presentation::Provider;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn same_device() {
        test_utils::init_tracer();
        let provider = Provider::new();

        // create offer to 'send' to the app
        let body = json!({
            "purpose": "To verify employment",
            "input_descriptors": [{
                "id": "employment",
                "constraints": {
                    "fields": [{
                        "path":["$.type"],
                        "filter": {
                            "type": "string",
                            "const": "EmployeeIDCredential"
                        }
                    }]
                }
            }],
            "device_flow": "SameDevice"
        });

        let mut request =
            serde_json::from_value::<CreateRequestRequest>(body).expect("should deserialize");
        request.client_id = "http://vercre.io".into();

        let response =
            Endpoint::new(provider.clone()).create_request(&request).await.expect("response is ok");

        assert_eq!(response.request_uri, None);
        assert_let!(Some(req_obj), &response.request_object);

        // check redacted fields are present
        assert!(req_obj.client_metadata.is_some());
        assert!(req_obj.presentation_definition.is_some());

        // compare response with saved state
        let state_key = req_obj.state.as_ref().expect("has state");
        let buf = StateManager::get(&provider, state_key).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_eq!(req_obj.nonce, state.request_object.nonce);
        assert_snapshot!("sd-response", response, {
            ".request_object.presentation_definition"  => "[presentation_definition]",
            ".request_object.client_metadata" => "[client_metadata]",
            ".request_object.state" => "[state]",
            ".request_object.nonce" => "[nonce]",
        });
    }

    #[tokio::test]
    async fn cross_device() {
        test_utils::init_tracer();
        let provider = Provider::new();

        // create offer to 'send' to the app
        let body = json!({
            "purpose": "To verify employment",
            "input_descriptors": [{
                "id": "employment",
                "constraints": {
                    "fields": [{
                        "path":["$.type"],
                        "filter": {
                            "type": "string",
                            "const": "EmployeeIDCredential"
                        }
                    }]
                }
            }],
            "device_flow": "CrossDevice"
        });

        let mut request =
            serde_json::from_value::<CreateRequestRequest>(body).expect("should deserialize");
        request.client_id = "http://vercre.io".into();

        let response =
            Endpoint::new(provider.clone()).create_request(&request).await.expect("response is ok");

        assert!(response.request_object.is_none());
        assert_let!(Some(req_uri), response.request_uri);

        // check state for RequestObject
        let state_key = req_uri.split('/').last().expect("has state");
        let buf = StateManager::get(&provider, state_key).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("cd-state", state, {
            ".expires_at" => "[expires_at]",
            ".request_object.presentation_definition"  => "[presentation_definition]",
            ".request_object.client_metadata" => "[client_metadata]",
            ".request_object.state" => "[state]",
            ".request_object.nonce" => "[nonce]",
        });
    }
}
