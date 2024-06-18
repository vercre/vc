//! # Presentation Request Endpoint
//!
//! The `request` endpoint can take a request for presentation in the form of a URI to go get the
//! request details or all of the details as a `PresentationRequest` struct serialized to a URL
//! query parameter.

use std::fmt::Debug;

use chrono::{DateTime, Utc};
use core_utils::jws;
use openid4vc::error::Err;
use openid4vc::presentation::{RequestObject, RequestObjectResponse};
use openid4vc::{err, Result};
use tracing::instrument;
use uuid::Uuid;
use vercre_exch::Constraints;

use crate::provider::{Callback, CredentialStorer, StateManager, Verifier, VerifierClient};
use crate::Endpoint;

use super::{Presentation, Status};

impl<P> Endpoint<P>
where
    P: Callback + CredentialStorer + StateManager + Verifier + VerifierClient + Debug,
{
    /// Initiates the presentation flow triggered by a new presentation request where the form of
    /// the request is a URI to retrieve the request details or a `PresentationRequest` struct as a
    /// URL query parameter.
    #[instrument(level = "debug", skip(self))]
    pub async fn request(&self, request: &String) -> Result<Presentation> {
        let ctx = Context {
            method: RequestMethod::Uri,
            request_str: String::new(),
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
enum RequestMethod {
    #[default]
    Uri,
    Param,
}

#[derive(Debug, Default)]
struct Context<P> {
    method: RequestMethod,
    request_str: String,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: CredentialStorer + StateManager + VerifierClient + Verifier + Debug,
{
    type Provider = P;
    type Request = String;
    type Response = Presentation;

    async fn verify(&mut self, _provider: &Self::Provider, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        let Ok(request) = urlencoding::decode(req) else {
            err!(Err::InvalidRequest, "unable to decode request url string");
        };
        if request.contains("&presentation_definition") {
            self.method = RequestMethod::Param;
        }
        self.request_str = request.into();

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, _req: &Self::Request,
    ) -> Result<Self::Response> {
        // Initiate a new presentation flow
        let mut presentation = Presentation {
            id: Uuid::new_v4().to_string(),
            status: Status::Requested,
            ..Default::default()
        };

        // Parse or get-then-parse the presentation request
        let req_obj = match self.method {
            RequestMethod::Uri => {
                let req_obj_response =
                    provider.get_request_object(&presentation.id, &self.request_str).await?;
                parse_request_object_response(&req_obj_response, provider).await?
            }
            RequestMethod::Param => parse_presentation_definition(&self.request_str)?,
        };
        presentation.request.clone_from(&req_obj);

        // Get the credentials from the holder's credential store that match the verifier's request.
        let filter = build_filter(&req_obj)?;
        presentation.filter.clone_from(&filter);
        let credentials = provider.find(Some(filter)).await?;
        presentation.credentials.clone_from(&credentials);

        // Stash the presentation flow for subsequent steps
        provider
            .put(&presentation.id, serde_json::to_vec(&presentation)?, DateTime::<Utc>::MAX_UTC)
            .await?;

        Ok(presentation)
    }
}

/// Extract a presentation request from a query string parameter.
fn parse_presentation_definition(request: &str) -> Result<RequestObject> {
    let req_obj = serde_qs::from_str::<RequestObject>(request)?;
    Ok(req_obj)
}

/// Extract a presentation `RequestObject` from a `RequestObjectResponse`.
async fn parse_request_object_response(
    res: &RequestObjectResponse, verifier: &impl Verifier,
) -> Result<RequestObject> {
    if res.request_object.is_some() {
        return Ok(res.request_object.clone().unwrap());
    }

    let Some(token) = &res.jwt else {
        err!(Err::InvalidRequest, "no serialized JWT found in response");
    };
    let jwt: jws::Jwt<RequestObject> = match jws::decode(token, verifier).await {
        Ok(jwt) => jwt,
        Err(e) => err!(Err::InvalidRequest, "failed to parse JWT: {e}"),
    };

    Ok(jwt.claims)
}

/// Construct a credential filter (`JSONPath`) from the presentation definition contained in the
/// presentation request.
// TODO: How to handle multiple input descriptors?
fn build_filter(request: &RequestObject) -> Result<Constraints> {
    let Some(pd) = &request.presentation_definition else {
        err!(Err::InvalidRequest, "no presentation definition found");
    };
    if pd.input_descriptors.is_empty() {
        err!(Err::InvalidRequest, "no input descriptors found");
    }
    let constraints = pd.input_descriptors[0].constraints.clone();

    Ok(constraints)
}
