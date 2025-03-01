//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this
//! endpoint returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use tracing::instrument;

use crate::oid4vp::endpoint::Request;
use crate::oid4vp::provider::{Metadata, Provider};
use crate::oid4vp::types::{MetadataRequest, MetadataResponse};
use crate::oid4vp::{Error, Result};

/// Endpoint for Wallets to request Verifier (Client) metadata.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn metadata(
    provider: impl Provider, request: MetadataRequest,
) -> Result<MetadataResponse> {
    process(provider, &request).await
}

impl Request for MetadataRequest {
    type Response = MetadataResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        metadata(provider.clone(), self)
    }
}

async fn process(provider: impl Provider, req: &MetadataRequest) -> Result<MetadataResponse> {
    tracing::debug!("metadata::process");

    Ok(MetadataResponse {
        client: Metadata::verifier(&provider, &req.client_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue getting metadata: {e}")))?,
    })
}
