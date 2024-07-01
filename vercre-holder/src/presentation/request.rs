//! # Presentation Request Endpoint
//!
//! The `request` endpoint can take a request for presentation in the form of a URI to go get the
//! request details or all of the details as a `PresentationRequest` struct serialized to a URL
//! query parameter.

use std::fmt::Debug;

use anyhow::{anyhow, bail};
use core_utils::jws;
use dif_exch::Constraints;
use openid4vc::presentation::{
    PresentationDefinitionType, RequestObject, RequestObjectResponse, RequestObjectType,
};
use tracing::instrument;
use uuid::Uuid;

use super::{Presentation, Status};
use crate::provider::{CredentialStorer, StateManager, Verifier, VerifierClient};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: CredentialStorer + StateManager + Verifier + VerifierClient + Debug,
{
    /// Initiates the presentation flow triggered by a new presentation request where the form of
    /// the request is a URI to retrieve the request details or a `PresentationRequest` struct as a
    /// URL query parameter.
    #[instrument(level = "debug", skip(self))]
    pub async fn request(&self, request: &String) -> anyhow::Result<Presentation> {
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
            match parse_presentation_definition(request) {
                Ok(req_obj) => req_obj,
                Err(e) => {
                    tracing::error!(target: "Endpoint::request", ?e);
                    return Err(e);
                }
            }
        } else {
            let req_obj_response =
                match self.provider.get_request_object(&presentation.id, &request_str).await {
                    Ok(req_obj_response) => req_obj_response,
                    Err(e) => {
                        tracing::error!(target: "Endpoint::request", ?e);
                        return Err(e);
                    }
                };
            match parse_request_object_response(&req_obj_response, &self.provider).await {
                Ok(req_obj) => req_obj,
                Err(e) => {
                    tracing::error!(target: "Endpoint::request", ?e);
                    return Err(e);
                }
            }
        };
        presentation.request.clone_from(&req_obj);

        // Get the credentials from the holder's credential store that match the verifier's request.
        let filter = match build_filter(&req_obj) {
            Ok(filter) => filter,
            Err(e) => {
                tracing::error!(target: "Endpoint::request", ?e);
                return Err(e);
            }
        };
        presentation.filter.clone_from(&filter);
        let credentials = self.provider.find(Some(filter)).await?;
        presentation.credentials.clone_from(&credentials);

        // Stash the presentation flow for subsequent steps
        if let Err(e) = self.put_presentation(&presentation).await {
            tracing::error!(target: "Endpoint::request", ?e);
            return Err(e);
        }

        Ok(presentation)
    }
}

/// Extract a presentation request from a query string parameter.
fn parse_presentation_definition(request: &str) -> anyhow::Result<RequestObject> {
    let req_obj = serde_qs::from_str::<RequestObject>(request)?;
    Ok(req_obj)
}

/// Extract a presentation `RequestObject` from a `RequestObjectResponse`.
async fn parse_request_object_response(
    res: &RequestObjectResponse, verifier: &impl Verifier,
) -> anyhow::Result<RequestObject> {
    let RequestObjectType::Jwt(token) = &res.request_object else {
        bail!("no serialized JWT found in response");
    };
    let jwt: jws::Jwt<RequestObject> = match jws::decode(token, verifier).await {
        Ok(jwt) => jwt,
        Err(e) => bail!("failed to parse JWT: {e}"),
    };

    Ok(jwt.claims)
}

/// Construct a credential filter (`JSONPath`) from the presentation definition contained in the
/// presentation request.
// TODO: How to handle multiple input descriptors?
fn build_filter(request: &RequestObject) -> anyhow::Result<Constraints> {
    let pd = match &request.presentation_definition {
        PresentationDefinitionType::Object(pd) => pd,
        PresentationDefinitionType::Uri(_) => bail!("presentation_definition_uri is unsupported"),
    };
    if pd.input_descriptors.is_empty() {
        bail!("no input descriptors found");
    }
    let constraints = pd.input_descriptors[0].constraints.clone();

    Ok(constraints)
}
