//! # Presentation Request Endpoint
//!
//! The `request` endpoint can take a request for presentation in the form of a
//! URI to go get the request details or all of the details as a `RequestObject`
//! struct serialized to a URL query parameter.

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;
pub use vercre_core::urlencode;
use vercre_core::Kind;
use vercre_datasec::jose::jws;
use vercre_dif_exch::Constraints;
use vercre_openid::verifier::{RequestObject, RequestObjectResponse, RequestObjectType};
use vercre_w3c_vc::verify_key;

use super::{Presentation, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, DidResolver, HolderProvider, Verifier};

/// `RequestResponse` is the response from the `request` endpoint. It contains
/// enough information for the holder to authorize (or reject) the presentation
/// request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct RequestResponse {
    /// The presentation flow identifier.
    pub presentation_id: String,

    /// The status of the presentation flow.
    pub status: Status,

    /// The list of credentials that match the verifier's request.
    pub credentials: Vec<Credential>,
}

/// Initiates the presentation flow triggered by a new presentation request
/// where the form of the request is a URI to retrieve the request details or a
/// `RequestObject` struct as a URL query parameter.
#[instrument(level = "debug", skip(provider))]
pub async fn request(
    provider: impl HolderProvider, request: &String,
) -> anyhow::Result<RequestResponse> {
    let Ok(request_str) = urlencoding::decode(request) else {
        let e = anyhow!("unable to decode request url string");
        tracing::error!(target: "Endpoint::request", ?e);
        return Err(e);
    };

    // Initiate a new presentation flow
    let mut presentation = Presentation {
        id: Uuid::new_v4().to_string(),
        status: Status::Requested,
        ..Default::default()
    };

    // Parse or get-then-parse the presentation request
    let req_obj = if request.contains("&presentation_definition") {
        urlencode::from_str::<RequestObject>(request).map_err(|e| {
            tracing::error!(target: "Endpoint::request", ?e);
            anyhow!("issue parsing RequestObject: {e}")
        })?
    } else {
        let req_obj_response =
            Verifier::request_object(&provider, &request_str).await.map_err(|e| {
                tracing::error!(target: "Endpoint::request", ?e);
                e
            })?;
        parse_request_object_response(&req_obj_response, &provider).await.map_err(|e| {
            tracing::error!(target: "Endpoint::request", ?e);
            e
        })?
    };
    presentation.request.clone_from(&req_obj);

    // Get the credentials from the holder's credential store that match the
    // verifier's request.
    let filter = build_filter(&req_obj).map_err(|e| {
        tracing::error!(target: "Endpoint::request", ?e);
        e
    })?;
    presentation.filter.clone_from(&filter);
    let credentials = CredentialStorer::find(&provider, Some(filter)).await?;
    presentation.credentials.clone_from(&credentials);

    // Stash the presentation flow for subsequent steps
    if let Err(e) = super::put_presentation(provider, &presentation).await {
        tracing::error!(target: "Endpoint::request", ?e);
        return Err(e);
    }

    // Return enough state for the holder agent to make a decision on whether to
    // authorize the presentation request or reject it.
    let response = RequestResponse {
        presentation_id: presentation.id,
        status: presentation.status,
        credentials: presentation.credentials.clone(),
    };

    Ok(response)
}

/// Extract a presentation `RequestObject` from a `RequestObjectResponse`.
async fn parse_request_object_response(
    res: &RequestObjectResponse, resolver: &impl DidResolver,
) -> anyhow::Result<RequestObject> {
    let RequestObjectType::Jwt(token) = &res.request_object else {
        bail!("no serialized JWT found in response");
    };
    let jwt: jws::Jwt<RequestObject> = jws::decode(token, verify_key!(resolver))
        .await
        .map_err(|e| anyhow!("failed to parse JWT: {e}"))?;

    Ok(jwt.claims)
}

/// Construct a credential filter (`JSONPath`) from the presentation definition
/// contained in the presentation request.
// TODO: How to handle multiple input descriptors?
fn build_filter(request: &RequestObject) -> anyhow::Result<Constraints> {
    let pd = match &request.presentation_definition {
        Kind::Object(pd) => pd,
        Kind::String(_) => bail!("presentation_definition_uri is unsupported"),
    };
    if pd.input_descriptors.is_empty() {
        bail!("no input descriptors found");
    }
    let constraints = pd.input_descriptors[0].constraints.clone();

    Ok(constraints)
}
