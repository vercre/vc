//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this endpoint
//! returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use std::fmt::Debug;

use openid4vc::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use openid4vc::presentation::{MetadataRequest, MetadataResponse};
use openid4vc::Result;
use provider::{Callback, ClientMetadata, StateManager};
use tracing::instrument;
use w3c_vc::proof::Signer;

use super::Endpoint;

/// Metadata request handler.
impl<P> Endpoint<P>
where
    P: ClientMetadata + StateManager + Signer + Callback + Clone + Debug,
{
    /// Endpoint for Wallets to request Verifier (Client) metadata.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn metadata(&self, request: &MetadataRequest) -> Result<MetadataResponse> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        core_utils::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: ClientMetadata + StateManager + Signer + Callback + Clone + Debug,
{
    type Provider = P;
    type Request = MetadataRequest;
    type Response = MetadataResponse;

    // TODO: return callback_id
    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        Ok(MetadataResponse {
            client: ClientMetadata::metadata(provider, &req.client_id)
                .await
                .map_err(|e| Err::ServerError(format!("issue getting metadata: {e}")))?,
        })
    }
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
        let response = Endpoint::new(provider).metadata(&request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".vp_formats" => insta::sorted_redaction()
        });
    }
}
