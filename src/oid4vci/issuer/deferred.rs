//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the
//! Credential Endpoint or Batch Credential Endpoint in cases where the
//! Credential Issuer was not able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is
//! valid for the issuance of the Credential previously requested at the
//! Credential Endpoint or the Batch Credential Endpoint.

use http::HeaderMap;
use http::header::AUTHORIZATION;
use tracing::instrument;

use crate::oid4vci::endpoint::{Body, Handler, Request};
use crate::oid4vci::issuer::credential::credential;
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::{Stage, State};
use crate::oid4vci::types::{DeferredCredentialRequest, DeferredCredentialResponse, ResponseType};
use crate::oid4vci::{Error, Result};
use crate::{invalid, server};

/// Deferred credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
async fn deferred(
    issuer: &str, provider: &impl Provider, request: DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    tracing::debug!("deferred");

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<State>(provider, &request.transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".to_string()));
    };
    if state.is_expired() {
        return Err(invalid!("state expired"));
    }
    let Stage::Deferred(deferred_state) = state.stage else {
        return Err(server!("Deferred state not found."));
    };

    // make credential request
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, request.access_token.parse().unwrap());
    let req = Request {
        body: deferred_state.credential_request,
        headers: Some(headers),
    };
    let response = credential(issuer, provider, req).await?;

    // is issuance still pending?
    if let ResponseType::TransactionId { .. } = response.response {
        // TODO: make retry interval configurable
        return Err(Error::IssuancePending(5));
    }

    // remove deferred state item
    StateStore::purge(provider, &request.transaction_id)
        .await
        .map_err(|e| server!("issue purging state: {e}"))?;

    Ok(response)
}

impl Handler for Request<DeferredCredentialRequest> {
    type Response = DeferredCredentialResponse;

    fn handle(
        self, issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        deferred(issuer, provider, self.body)
    }
}

impl Body for DeferredCredentialRequest {}
