//! # Metadata Endpoint
//!
//! The Credential Issuer Metadata contains information on the Credential Issuer's
//! technical capabilities, supported Credentials, and (internationalized) display
//! information.
//!
//! The Credential Issuer's configuration can be retrieved using the Credential Issuer
//! Identifier.
//!
//! Credential Issuers publishing metadata MUST make a JSON document available at the
//! path formed by concatenating the string `/.well-known/openid-credential-issuer` to
//! the Credential Issuer Identifier. If the Credential Issuer value contains a path
//! component, any terminating / MUST be removed before appending
//! `/.well-known/openid-credential-issuer`.
//!
//! The language(s) in HTTP Accept-Language and Content-Language Headers MUST use the values defined in [RFC3066](https://www.rfc-editor.org/rfc/rfc3066).
//!
//! Below is a non-normative example of a Credential Issuer Metadata request:
//!
//! ```http
//! GET /.well-known/openid-credential-issuer HTTP/1.1
//!     Host: server.example.com
//!     Accept-Language: fr-ch, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
//! ```

use tracing::{instrument, trace};
use vercre_core::vci::{MetadataRequest, MetadataResponse};
use vercre_core::{Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Endpoint;

impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Metadata request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn metadata(&self, request: impl Into<MetadataRequest>) -> Result<MetadataResponse> {
        let request = request.into();
        self.handle_request(request, Context {}).await
    }
}

#[derive(Debug)]
struct Context;

impl super::Context for Context {
    type Request = MetadataRequest;
    type Response = MetadataResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        None
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
    {
        trace!("Context::process");

        // TODO: add languages to request
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
            languages: None,
        };
        let response = Endpoint::new(provider).metadata(request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".credentials_supported" => insta::sorted_redaction(),
            ".credentials_supported.*.credential_definition.credentialSubject" => insta::sorted_redaction()
        });
    }
}
