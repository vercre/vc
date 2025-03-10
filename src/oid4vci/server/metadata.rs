//! # Authorization Server Metadata Endpoint
//!
//! The metadata for an authorization server is retrieved from a well-
//! known location as a JSON [RFC8259] document, which declares its
//! endpoint locations and authorization server capabilities.
//!
//! The data model for this metadata is defined in
//! [`openid::oauth::OAuthServer`] and [`openid::issuer::Server`].
//!
//! Credential Issuers publishing authorization server metadata MUST make a JSON
//! document available. This is usually at the path formed by concatenating the
//! string `/.well-known/oauth-authorization-server` to the Credential Issuer
//! Identifier.
//!
//! If the issuer identifier is different from the Credential Issuer Identifier,
//! this is added as a path component such as
//! `/.well-known/oauth-authorization-server/issuer1`.

use tracing::instrument;

use crate::oid4vci::Result;
use crate::oid4vci::endpoint::Handler;
use crate::oid4vci::provider::{Metadata, Provider};
use crate::oid4vci::types::{OAuthServerRequest, OAuthServerResponse};
use crate::server;

/// OAuth server metadata request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn metadata(
    provider: impl Provider, request: OAuthServerRequest,
) -> Result<OAuthServerResponse> {
    process(&provider, request).await
}

impl Handler for OAuthServerRequest {
    type Response = OAuthServerResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        metadata(provider.clone(), self)
    }
}

async fn process(
    provider: &impl Provider, request: OAuthServerRequest,
) -> Result<OAuthServerResponse> {
    tracing::debug!("oauth_server::process");

    let auth_server =
        Metadata::server(provider, &request.credential_issuer, request.issuer.as_deref())
            .await
            .map_err(|e| server!("issue getting authorization server metadata: {e}"))?;
    Ok(OAuthServerResponse {
        authorization_server: auth_server,
    })
}
