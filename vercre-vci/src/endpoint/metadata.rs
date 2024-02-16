//! # Metadata Handler

use std::fmt::Debug;
use std::marker::PhantomData;

use tracing::{instrument, trace};
use vercre_core::metadata::Issuer as IssuerMetadata;
use vercre_core::vci::{MetadataRequest, MetadataResponse};
use vercre_core::{Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Handler;

/// Metadata request handler.
impl<P> Handler<P, MetadataRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<MetadataResponse> {
        trace!("Handler::call");
        self.handle_request(Context::new()).await
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Issuer,
{
    issuer_meta: IssuerMetadata,
    _phantom: PhantomData<P>,
}

impl<P> Context<P>
where
    P: Issuer,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");
        Self {
            issuer_meta: IssuerMetadata::default(),
            _phantom: PhantomData,
        }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Issuer + Debug,
{
    type Provider = P;
    type Request = MetadataRequest;
    type Response = MetadataResponse;

    #[instrument]
    async fn init(&mut self, req: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        self.issuer_meta = Issuer::metadata(&provider, &req.credential_issuer).await?;
        Ok(self)
    }

    #[instrument]
    async fn process(&self, _: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        Ok(MetadataResponse {
            credential_issuer: self.issuer_meta.clone(),
        })
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
        let response = Handler::new(&provider, request).call().await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".credentials_supported" => insta::sorted_redaction(),
            ".credentials_supported.*.credential_definition.credentialSubject" => insta::sorted_redaction()
        });
    }
}
