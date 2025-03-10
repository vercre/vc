//! # Pushed Authorization Request Endpoint [RFC9126]
//!
//! This endpoint allows clients to push the payload of an authorization request
//! to the server, returning a request URI to use in a subsequent call to the
//! authorization endpoint.
//!
//! [RFC9126]: (https://www.rfc-editor.org/rfc/rfc9126.html)

use chrono::{Duration, Utc};
use tracing::instrument;

use crate::core::generate;
use crate::oid4vci::endpoint::{Body, Handler, Request};
use crate::oid4vci::provider::{Metadata, Provider, StateStore};
use crate::oid4vci::server::authorize;
use crate::oid4vci::state::{PushedAuthorization, Stage, State};
use crate::oid4vci::types::{PushedAuthorizationRequest, PushedAuthorizationResponse};
use crate::oid4vci::{Error, Result};
use crate::server;

/// Endpoint for the Wallet to push an Authorization Request when using Pushed
/// Authorization Requests.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn par(
    credential_issuer: &str, provider: &impl Provider, request: PushedAuthorizationRequest,
) -> Result<PushedAuthorizationResponse> {
    tracing::debug!("par");

    verify(provider, &request).await?;

    // generate a request URI and expiry between 5 - 600 secs
    let request_uri = format!("urn:ietf:params:oauth:request_uri:{}", generate::uri_token());
    let expires_in = Duration::seconds(600);

    // save request to state for retrieval by authorization endpoint
    let state = State {
        subject_id: None,
        stage: Stage::PushedAuthorization(PushedAuthorization {
            request: request.request.clone(),
            expires_at: Utc::now() + expires_in,
        }),
        expires_at: Utc::now() + expires_in,
    };
    StateStore::put(provider, &request_uri, &state, state.expires_at)
        .await
        .map_err(|e| server!("issue saving state: {e}"))?;

    Ok(PushedAuthorizationResponse {
        request_uri,
        expires_in: expires_in.num_seconds(),
    })
}

impl Handler for Request<PushedAuthorizationRequest> {
    type Response = PushedAuthorizationResponse;

    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        par(credential_issuer, provider, self.body)
    }
}

impl Body for PushedAuthorizationRequest {}

// Verify the pushed Authorization Request.
#[allow(clippy::unused_async)]
async fn verify(provider: &impl Provider, request: &PushedAuthorizationRequest) -> Result<()> {
    tracing::debug!("par::verify");

    // TODO: authenticate the client in the same way as at the token endpoint
    //       (client assertion)

    let req_obj = &request.request;

    // verify the pushed RequestObject using `/authorize` endpoint logic
    let Ok(issuer) = Metadata::issuer(provider, &req_obj.credential_issuer).await else {
        return Err(Error::InvalidClient("invalid `credential_issuer`".to_string()));
    };
    let mut ctx = authorize::Context {
        issuer,
        ..authorize::Context::default()
    };
    ctx.verify(provider, &request.request).await?;

    Ok(())
}
