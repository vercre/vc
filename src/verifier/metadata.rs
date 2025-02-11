//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this
//! endpoint returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use tracing::instrument;

use crate::openid::verifier::{Metadata, MetadataRequest, MetadataResponse, Provider};
use crate::openid::{Error, Result};

/// Endpoint for Wallets to request Verifier (Client) metadata.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn metadata(
    provider: impl Provider, request: &MetadataRequest,
) -> Result<MetadataResponse> {
    process(provider, request).await
}

async fn process(provider: impl Provider, req: &MetadataRequest) -> Result<MetadataResponse> {
    tracing::debug!("metadata::process");

    Ok(MetadataResponse {
        client: Metadata::verifier(&provider, &req.client_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue getting metadata: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    // use providers::wallet_provider::holder_provider::CLIENT_ID;
    use super::*;
    use crate::test_utils;
    use crate::test_utils::verifier::Provider;

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();
        let provider = Provider::new();

        let request = MetadataRequest {
            client_id: "http://localhost:8080".into(),
        };
        let response = metadata(provider, &request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".vp_formats" => insta::sorted_redaction()
        });
    }
}
