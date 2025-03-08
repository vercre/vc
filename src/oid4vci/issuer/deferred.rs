//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the
//! Credential Endpoint or Batch Credential Endpoint in cases where the
//! Credential Issuer was not able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is
//! valid for the issuance of the Credential previously requested at the
//! Credential Endpoint or the Batch Credential Endpoint.

use tracing::instrument;

use crate::oid4vci::endpoint::Request;
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
pub async fn deferred(
    credential_issuer: &str, provider: impl Provider, request: DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    process(credential_issuer, &provider, request).await
}

impl Request for DeferredCredentialRequest {
    type Response = DeferredCredentialResponse;

    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        deferred(credential_issuer, provider.clone(), self)
    }
}

async fn process(
    credential_issuer: &str, provider: &impl Provider, request: DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    tracing::debug!("deferred::process");

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<State>(provider, &request.transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".into()));
    };
    if state.is_expired() {
        return Err(invalid!("state expired"));
    }

    let Stage::Deferred(deferred_state) = state.stage else {
        return Err(server!("Deferred state not found."));
    };

    // remove deferred state item
    StateStore::purge(provider, &request.transaction_id)
        .await
        .map_err(|e| server!("issue purging state: {e}"))?;

    // make credential request
    let mut cred_req = deferred_state.credential_request;
    cred_req.access_token.clone_from(&request.access_token);

    let response = credential(credential_issuer, provider, cred_req).await?;

    // is issuance still pending?
    if let ResponseType::TransactionId { .. } = response.response {
        // TODO: make retry interval configurable
        return Err(Error::IssuancePending(5));
    }

    Ok(DeferredCredentialResponse {
        credential_response: response,
    })
}
