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

use crate::openid::issuer::{Metadata, OAuthServerRequest, OAuthServerResponse, Provider};
use crate::openid::{Error, Result};

// let authorization_server = Metadata::server(provider,
// &request.credential_issuer)     .await
//     .map_err(|e| Error::ServerError(format!("issue getting  authorization
// server metadata: {e}")))?;

/// OAuth server metadata request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn oauth_server(
    provider: impl Provider, request: OAuthServerRequest,
) -> Result<OAuthServerResponse> {
    process(&provider, request).await
}

async fn process(
    provider: &impl Provider, request: OAuthServerRequest,
) -> Result<OAuthServerResponse> {
    tracing::debug!("oauth_server::process");

    let auth_server =
        Metadata::server(provider, &request.credential_issuer, request.issuer.as_deref())
            .await
            .map_err(|e| {
                Error::ServerError(format!("issue getting authorization server metadata: {e}"))
            })?;
    Ok(OAuthServerResponse {
        authorization_server: auth_server,
    })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;

    use super::*;
    use crate::test_utils::issuer::{Provider, CREDENTIAL_ISSUER};
    use crate::{snapshot, test_utils};

    #[tokio::test]
    async fn metadata_ok() {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        let request = OAuthServerRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            issuer: None,
        };
        let response = oauth_server(provider, request).await.expect("response is ok");
        assert_snapshot!("oauth_server:metadata_ok:response", response, {
            ".grant_types_supported" => insta::sorted_redaction()
        });
    }
}
