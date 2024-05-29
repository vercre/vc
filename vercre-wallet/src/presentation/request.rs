//! # Presentation Request Endpoint.
//!
//! The presentation request endpoint is responsible for handling incoming requests for a credential
//! presentation. Use this endpoint to initiate a presentation flow.
//!
//! The request can be encountered in two ways: the whole request object serialised into a URL
//! parameter, or just a URI to go fetch the request object. Helper methods are provided to parse
//! the request object from a URL parameter or the response from fetching.

use std::fmt::Debug;

use anyhow::anyhow;
use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::jwt::Jwt;
use vercre_core::vp::{RequestObject, RequestObjectResponse};
use vercre_core::w3c::PresentationDefinition;
use vercre_core::{err, Result};

use crate::presentation::{Presentation, Status};
use crate::provider::{Callback, CredentialStorer, Signer, StateManager};
use crate::{Endpoint, Flow};

/// Helper function to parse a presentation request object from a URL parameter. The parameter needs
/// to contain "&`presentation_definition`=" and it is assumed to be URL-encoded.
///
/// # Errors
///
/// Returns an error if parsing fails.
#[allow(clippy::module_name_repetitions)]
pub fn request_from_url_param(url_param: &str) -> anyhow::Result<RequestObject> {
    let request_str = urlencoding::decode(url_param)?;

    if !request_str.contains("&presentation_definition=") {
        return Err(anyhow!("No presentation_definition parameter found"));
    }

    // extract RequestObject from query string
    let req_obj = serde_qs::from_str::<RequestObject>(&request_str)?;

    Ok(req_obj)
}

/// Helper function to parse a presentation request object from the response of fetching from
/// previously provided URI in the form of a `RequestObjectResponse`.
///
/// # Errors
///
/// Returns an error if parsing fails.
#[allow(clippy::module_name_repetitions)]
pub fn request_from_response(res: &RequestObjectResponse) -> anyhow::Result<RequestObject> {
    let Some(jwt_enc) = res.jwt.clone() else {
        return Err(anyhow!("no encoded JWT found in response"));
    };
    let Ok(jwt) = jwt_enc.parse::<Jwt<RequestObject>>() else {
        return Err(anyhow!("failed to parse JWT"));
    };

    Ok(jwt.claims)
}

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Request endpoint receives a a presentation request from a verifier in the form of a URL
    /// parameter. Initializes a presentation flow state object and stashes that in the state
    /// storage provider.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid, a presentation flow is already in progress or
    /// the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn request(&self, request: &RequestObject) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            presentation_definition: PresentationDefinition::default(),
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    presentation_definition: PresentationDefinition,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = RequestObject;
    type Response = ();

    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        // Do not progress if a presentation is already being processed.
        let stashed_presentation = provider.get_opt(&Flow::Presentation.to_string()).await?;
        if stashed_presentation.is_some() {
            err!(Err::InvalidRequest, "presentation already being processed");
        }

        if req.response_uri.is_none() {
            err!(Err::InvalidRequest, "no response uri");
        }
        let Some(pd) = &req.presentation_definition else {
            err!(Err::InvalidRequest, "no presentation definition");
        };
        self.presentation_definition = pd.clone();

        // TODO: More request validation

        Ok(self)
    }

    /// Populate the state store with the presentation request and a Requested status.
    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Build the presentation object
        // TODO: build credential query from presentation definition
        let presentation = Presentation {
            filter: Some(self.presentation_definition.input_descriptors[0].constraints.clone()),
            request: Some(req.clone()),
            status: Status::Requested,
            ..Default::default()
        };

        // Stash the presentation object
        provider
            .put_opt(&Flow::Presentation.to_string(), serde_json::to_vec(&presentation)?, None)
            .await?;

        Ok(())
    }
}
