//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this endpoint
//! returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use openid::endpoint::{ClientMetadata, VerifierProvider};
use openid::verifier::{MetadataRequest, MetadataResponse};
use openid::{Error,Result};
use tracing::instrument;

/// Endpoint for Wallets to request Verifier (Client) metadata.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn metadata(
    provider: impl VerifierProvider, request: &MetadataRequest,
) -> Result<MetadataResponse> {
    process(provider, request).await
}

async fn process(
    provider: impl VerifierProvider, req: &MetadataRequest,
) -> Result<MetadataResponse> {
    tracing::debug!("Context::process");

    Ok(MetadataResponse {
        client: ClientMetadata::metadata(&provider, &req.client_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue getting metadata: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use test_utils::verifier::Provider;

    // use providers::wallet_provider::holder_provider::CLIENT_ID;
    use super::*;

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();
        let provider = Provider::new();

        let request = MetadataRequest {
            client_id: "http://vercre.io".into(),
        };
        let response = metadata(provider, &request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".vp_formats" => insta::sorted_redaction()
        });
    }
}
