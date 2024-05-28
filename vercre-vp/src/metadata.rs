//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this endpoint
//! returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

use std::fmt::Debug;

use tracing::instrument;
pub use vercre_core::metadata as types;
use vercre_core::provider::{Callback, Client, Signer, StateManager};
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vp::{MetadataRequest, MetadataResponse};
use vercre_core::Result;

use super::Endpoint;

/// Metadata request handler.
impl<P> Endpoint<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
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

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + StateManager + Signer + Callback + Clone + Debug,
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
            client: Client::metadata(provider, &req.client_id).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use test_utils::vp_provider::Provider;

    // use test_utils::wallet_provider::wallet::CLIENT_ID;
    use super::*;

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();
        let provider = Provider::new();

        let request = MetadataRequest {
            client_id: String::from("http://vercre.io"),
        };
        let response = Endpoint::new(provider).metadata(&request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".vp_formats" => insta::sorted_redaction()
        });
    }
}
