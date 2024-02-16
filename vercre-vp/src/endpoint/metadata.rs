//! # Metadata Endpoint
//!
//! This endpoint is used to make Verifier metadata available to the Wallet.
//!
//! As the Verifier is a client to the Wallet's Authorization Server, this endpoint
//! returns Client metadata as defined in [RFC7591].
//!
//! [RFC7591]: https://www.rfc-editor.org/rfc/rfc7591.html

use std::fmt::Debug;

use tracing::{instrument, trace};
use vercre_core::vp::{MetadataRequest, MetadataResponse};
use vercre_core::{Callback, Client, Result, Signer, StateManager};

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
    pub async fn metadata(&self, request: impl Into<MetadataRequest>) -> Result<MetadataResponse> {
        self.handle_request(request.into(), Context {}).await
    }
}

#[derive(Debug)]
struct Context;

impl super::Context for Context {
    type Request = MetadataRequest;
    type Response = MetadataResponse;

    // TODO: return callback_id
    fn callback_id(&self) -> Option<String> {
        None
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, req: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Debug,
    {
        trace!("Context::process");

        Ok(MetadataResponse {
            client: Client::metadata(provider, &req.client_id).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use test_utils::vp_provider::Provider;

    // use test_utils::wallet::CLIENT_ID;
    use super::*;

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();
        let provider = Provider::new();

        let request = MetadataRequest {
            client_id: "http://credibil.io".to_string(),
        };
        let response = Endpoint::new(provider).metadata(request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".vp_formats" => insta::sorted_redaction()
        });
    }
}
