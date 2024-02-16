//! # Initiate Endpoint
//!
//! This endpoint is used to **prepare** an [RFC6749] Authorization Request to use
//! to request Verifiable Presentations from an End-User's Wallet.
//!
//! While based on the [OpenID4VP] specification, the endpoint only implements a subset
//! of the specification requirements as recommended in the [JWT VC Presentation
//! Profile]. Aside from reducing complexity, the profile enables greater presentation
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
//!     "credentials": [
//!         {"type": ["VerifiableCredential", "EmployeeIDCredential"]},
//!         {"type": ["VerifiableCredential", "CitizenshipCredential"]}
//!    ],
//!     "device_flow": "CrossDevice"
//! }
//! ```
//!
//! The prepared Authorization Request Object may be sent by value or by reference as
//! defined in JWT-Secured Authorization Request (JAR) [RFC9101]. If sent by value,
//! the Request Object is sent directly to the Wallet as a URL fragment in the
//! Authorization Request. If by reference, the Authorization Request will contain a
//! `request_uri` pointing to the prepared Request Object.
//!
//! [OpenID4VP]: https://openid.net/specs/openid-connect-verifiable-presentations-1_0.html
//! [JWT VC Presentation Profile]: https://identity.foundation/jwt-vc-presentation-profile
//! [RFC6749]: https://www.rfc-editor.org/rfc/rfc6749.html
//! [RFC9101]: https://www.rfc-editor.org/rfc/rfc9101.html

use std::collections::HashMap;
use std::convert::From;
use std::fmt::Debug;

// use serde_json::map::Map;
// use serde_json::Value;
use tracing::{instrument, trace};
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::metadata::CredentialDefinition;
use vercre_core::vp::{DeviceFlow, InvokeRequest, InvokeResponse, RequestObject};
use vercre_core::w3c::vp::{
    Constraints, Field, Filter, FilterValue, Format, InputDescriptor, PresentationDefinition,
};
use vercre_core::{err, gen, Algorithm, Callback, Client, Result, Signer, StateManager};

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

/// Initiate Request handler.
impl<P> Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
{
    /// Initiate an Authorization Request flow.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn initiate(&self, request: impl Into<InvokeRequest>) -> Result<InvokeResponse> {
        let request = request.into();
        let ctx = Context {
            callback_id: request.callback_id.clone(),
        };

        self.handle_request(request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context {
    callback_id: Option<String>,
}

impl super::Context for Context {
    type Request = InvokeRequest;
    type Response = InvokeResponse;

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    #[instrument]
    async fn verify<P>(&self, provider: &P, request: &Self::Request) -> Result<&Self>
    where
        P: Client + StateManager + Debug,
    {
        trace!("Context::verify");

        if request.credentials.is_empty() {
            err!(Err::InvalidRequest, "No credentials specified");
        }
        Ok(self)
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + StateManager + Debug,
    {
        trace!("Context::process");

        // generate presentation_definition
        let def = self.build_def(&request.credentials);
        let state_key = gen::state_key();

        // get client metadata
        let Ok(client_meta) = Client::metadata(provider, &request.client_id).await else {
            err!(Err::InvalidRequest, "Invalid client_id");
        };

        let mut req_obj = RequestObject {
            response_type: "vp_token".to_string(),
            state: Some(state_key.clone()),
            nonce: gen::nonce(),
            presentation_definition: Some(def),
            client_metadata: Some(client_meta),
            client_id_scheme: Some("redirect_uri".to_string()),
            ..Default::default()
        };

        let mut response = InvokeResponse::default();

        // Response Mode "direct_post" is RECOMMENDED for cross-device flows.
        // TODO: replace hard-coded endpoints with Provider-set values
        if request.device_flow == DeviceFlow::CrossDevice {
            req_obj.response_mode = Some("direct_post".to_string());
            req_obj.client_id = format!("{}/post", request.client_id);
            req_obj.response_uri = Some(format!("{}/post", request.client_id));
            response.request_uri = Some(format!("{}/request/{state_key}", request.client_id));
        } else {
            req_obj.client_id = format!("{}/callback", request.client_id);
            response.request_object = Some(req_obj.clone());
        }

        // save request object in state
        let state = State::builder().request_object(&req_obj).build();
        StateManager::put(provider, &state_key, state.to_vec(), state.expires_at).await?;

        Ok(response)
    }
}

impl Context {
    #[instrument]
    fn build_def(&self, cred_defs: &[CredentialDefinition]) -> PresentationDefinition {
        trace!("creating presentation definition");

        let mut input_descs = Vec::<InputDescriptor>::new();

        for cred_def in cred_defs {
            let fields = vec![
                (Field {
                    // TODO: build JSONPath query properly
                    path: vec!["$.type".to_string()],
                    filter: Some(Filter {
                        type_: "string".to_string(),
                        value: FilterValue::Const("EmployeeIDCredential".to_string()),
                    }),

                    ..Field::default()
                }),
            ];

            input_descs.push(InputDescriptor {
                // TODO: check types == [VerifiableCredential, <specific type>]
                id: cred_def.type_[1].clone(),
                constraints: Constraints {
                    fields: Some(fields),
                    limit_disclosure: None,
                },
                name: None,
                purpose: None,
                format: None, // Some(HashMap::<String, Format>::new()),
            });
        }

        let fmt = Format {
            alg: Some(vec![Algorithm::ES256K.to_string()]),
            proof_type: None,
        };

        // presentation definition
        PresentationDefinition {
            id: Uuid::new_v4().to_string(),
            input_descriptors: input_descs,
            name: None,
            purpose: None,
            format: Some(HashMap::from([("jwt_vc".to_string(), fmt)])),
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vp_provider::Provider;

    use super::*;

    #[tokio::test]
    async fn same_device() {
        test_utils::init_tracer();
        let provider = Provider::new();

        // create offer to 'send' to the app
        let body = json!({
            "credentials": [
                {"type": ["VerifiableCredential", "EmployeeIDCredential"]},
                {"type": ["VerifiableCredential", "CitizenshipCredential"]}
            ],
            "device_flow": "SameDevice"
        });

        let mut request =
            serde_json::from_value::<InvokeRequest>(body).expect("should deserialize");
        request.client_id = "http://credibil.io".to_string();

        let response =
            Endpoint::new(provider.clone()).initiate(request).await.expect("response is ok");

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
            "credentials": [
                {"type": ["VerifiableCredential", "EmployeeIDCredential"]},
                {"type": ["VerifiableCredential", "CitizenshipCredential"]}
            ],
        });

        let mut request =
            serde_json::from_value::<InvokeRequest>(body).expect("should deserialize");
        request.client_id = "http://credibil.io".to_string();

        let response =
            Endpoint::new(provider.clone()).initiate(request).await.expect("response is ok");

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
