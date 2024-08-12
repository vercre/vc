//! # Notification Endpoint
//!
//! This endpoint is used by the Wallet to notify the Credential Issuer of certain
//! events for issued Credentials. These events enable the Credential Issuer to take
//! subsequent actions after issuance. The Credential Issuer needs to return one or
//! more notification_id parameters in the Credential Response or the Batch Credential
//! Response for the Wallet to be able to use this Endpoint. Support for this endpoint
//! is OPTIONAL. The Issuer cannot assume that a notification will be sent for every
//! issued credential since the use of this Endpoint is not mandatory for the Wallet.
//!
//! The Wallet MUST present to the Notification Endpoint a valid Access Token issued at
//! the Token Endpoint as defined in Section 6.
//!
//! A Credential Issuer that requires a request to the Notification Endpoint MUST
//! ensure the Access Token issued by the Authorization Server is valid at the
//! Notification Endpoint.
//!
//! The notification from the Wallet is idempotent. When the Credential Issuer
//! receives multiple identical calls from the Wallet for the same `notification_id`,
//! it returns success. Due to the network errors, there are no guarantees that a
//! Credential Issuer will receive a notification within a certain time period or at
//! all.

use tracing::instrument;
use vercre_openid::issuance::{MetadataRequest, MetadataResponse, Provider};
use vercre_openid::{Error, Result};

/// Notification request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(self))]
pub async fn notification(
    provider: impl Provider, request: &NotificationRequest,
) -> Result<NotificationResponse> {
    let request = request.into();
    self.handle_request(request, Context {}).await
}

#[derive(Debug)]
struct Context;

async fn process<P>(
    provider: impl Provider, request: &NotificationRequest,
) -> Result<NotificationResponse> {
    tracing::debug!("notification::process");

    let credential_issuer = Issuer::metadata(provider, &request.credential_issuer).await?;
    Ok(NotificationResponse { credential_issuer })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use issuer_provider::{Provider, CREDENTIAL_ISSUER};

    use super::*;

    #[tokio::test]
    async fn notification_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();

        let request = MetadataRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            languages: None,
        };
        let response = Endpoint::new(provider).metadata(request).await.expect("response is ok");
        assert_snapshot!("response", response, {
            ".credential_configurations_supported" => insta::sorted_redaction(),
            ".credential_configurations_supported.*.credential_definition.credentialSubject" => insta::sorted_redaction()
        });
    }
}
