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

use core_utils::gen;
use dif_exch::{ClaimFormat, PresentationDefinition};
use openid::endpoint::{StateManager, VerifierMetadata, VerifierProvider};
use openid::verifier::{
    ClientIdScheme, ClientMetadataType, CreateRequestRequest, CreateRequestResponse, DeviceFlow,
    PresentationDefinitionType, RequestObject, ResponseType,
};
use openid::{Error, Result};
use proof::signature::Algorithm;
use tracing::instrument;
use uuid::Uuid;

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

/// Initiate an Authorization Request flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn create_request(
    provider: impl VerifierProvider, request: &CreateRequestRequest,
) -> Result<CreateRequestResponse> {
    verify(request).await?;
    process(provider, request).await
}

#[allow(clippy::unused_async)]
async fn verify(request: &CreateRequestRequest) -> Result<()> {
    tracing::debug!("Context::verify");

    if request.input_descriptors.is_empty() {
        return Err(Error::InvalidRequest("no credentials specified".into()));
    }
    Ok(())
}

async fn process(
    provider: impl VerifierProvider, request: &CreateRequestRequest,
) -> Result<CreateRequestResponse> {
    tracing::debug!("Context::process");

    // TODO: build dynamically...
    let fmt = ClaimFormat {
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
    let Ok(client_meta) = VerifierMetadata::metadata(&provider, &request.client_id).await else {
        return Err(Error::InvalidRequest("invalid client_id".into()));
    };

    let mut req_obj = RequestObject {
        response_type: ResponseType::VpToken,
        state: Some(state_key.clone()),
        nonce: gen::nonce(),
        presentation_definition: PresentationDefinitionType::Object(pres_def),
        client_metadata: ClientMetadataType::Object(client_meta),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
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
        .map_err(|e| Error::ServerError(format!("issue building state: {e}")))?;
    StateManager::put(&provider, &state_key, state.to_vec(), state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(response)
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::verifier::Provider;

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

        let response = create_request(provider.clone(), &request).await.expect("response is ok");

        assert_eq!(response.request_uri, None);
        assert_let!(Some(req_obj), &response.request_object);

        // check redacted fields are present
        let md = match req_obj.client_metadata {
            ClientMetadataType::Object(_) => true,
            _ => false,
        };
        assert!(md);

        let pd = match req_obj.presentation_definition {
            PresentationDefinitionType::Object(_) => true,
            _ => false,
        };
        assert!(pd);

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

        let response = create_request(provider.clone(), &request).await.expect("response is ok");

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
