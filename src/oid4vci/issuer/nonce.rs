// TODO: implement Notification endpoint

//! # Nonce Endpoint
//!
//! This endpoint allows a Client to acquire a fresh `c_nonce` value.
//!
//! Any Credential Issuer requiring `c_nonce` values in Credential
//! Request proofs will support the Nonce Endpoint.

use chrono::Utc;
use tracing::instrument;

use crate::core::generate;
use crate::oid4vci::Result;
use crate::oid4vci::endpoint::Handler;
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::Expire;
use crate::oid4vci::types::{NonceRequest, NonceResponse};
use crate::server;

/// Notification request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn nonce(
    credential_issuer: &str, provider: impl Provider, request: NonceRequest,
) -> Result<NonceResponse> {
    process(&provider, request).await
}

impl Handler for NonceRequest {
    type Response = NonceResponse;

    fn handle(
        self, credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        nonce(credential_issuer, provider.clone(), self)
    }
}

#[allow(clippy::unused_async)]
#[allow(dead_code)]
async fn process(provider: &impl Provider, _: NonceRequest) -> Result<NonceResponse> {
    tracing::debug!("nonce::process");

    let c_nonce = generate::nonce();
    let expire_at = Utc::now() + Expire::Authorized.duration();

    StateStore::put(provider, &c_nonce, &c_nonce, expire_at)
        .await
        .map_err(|e| server!("failed to purge state: {e}"))?;

    Ok(NonceResponse { c_nonce })
}
