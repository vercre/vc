//! # Metadata Handler

// use std::fmt::Debug;

use tracing::{instrument, trace};
use vercre_core::vci::{MetadataRequest, MetadataResponse};
use vercre_core::{Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Endpoint;

/// Metadata request handler.
impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Request Issuer metadata.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn metadata(&self, request: impl Into<MetadataRequest>) -> Result<MetadataResponse> {
        let request = request.into();

        let ctx = Context {
            // callback_id: request.callback_id.clone(),
        };

        self.handle_request(request, ctx).await
    }
}

#[derive(Debug)]
struct Context {
    // callback_id: Option<String>,
}

impl super::Context for Context {
    type Request = MetadataRequest;
    type Response = MetadataResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        // self.callback_id.clone()
        None
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
    {
        trace!("Context::process");

        let credential_issuer = Issuer::metadata(provider, &request.credential_issuer).await?;
        Ok(MetadataResponse { credential_issuer })
    }
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use test_utils::vci_provider::{Provider, ISSUER};

    use super::*;

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();

        let request = MetadataRequest {
            credential_issuer: ISSUER.to_string(),
        };
        let response =
            Endpoint::new(provider).metadata(request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".credentials_supported" => insta::sorted_redaction(),
            ".credentials_supported.*.credential_definition.credentialSubject" => insta::sorted_redaction()
        });
    }
}
