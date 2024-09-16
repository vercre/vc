// TODO: implement Notification endpoint

//! # Notification Endpoint
//!
//! This endpoint is used by the Wallet to notify the Credential Issuer of certain
//! events for issued Credentials. These events enable the Credential Issuer to take
//! subsequent actions after issuance.
//!
//! The Credential Issuer needs to return one or
//! more `notification_id` parameters in the Credential Response or the Batch Credential
//! Response for the Wallet to be able to use this Endpoint. Support for this endpoint
//! is OPTIONAL. The Issuer cannot assume that a notification will be sent for every
//! issued credential since the use of this Endpoint is not mandatory for the Wallet.
//!
//! The notification from the Wallet is idempotent. When the Credential Issuer
//! receives multiple identical calls from the Wallet for the same `notification_id`,
//! it returns success. Due to the network errors, there are no guarantees that a
//! Credential Issuer will receive a notification within a certain time period or at
//! all.

use tracing::instrument;
use vercre_openid::issuer::{
    NotificationEvent, NotificationRequest, NotificationResponse, Provider,
};
use vercre_openid::Result;

/// Notification request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn notification(
    provider: impl Provider, request: NotificationRequest,
) -> Result<NotificationResponse> {
    process(&provider, request).await
}

#[allow(clippy::unused_async)]
#[allow(dead_code)]
async fn process(
    _provider: &impl Provider, request: NotificationRequest,
) -> Result<NotificationResponse> {
    tracing::debug!("notification::process");

    match request.event {
        NotificationEvent::CredentialAccepted => {
            println!("CredentialAccepted");
        }
        NotificationEvent::CredentialFailure => {
            println!("CredentialFailure");
        }
        NotificationEvent::CredentialDeleted => {
            println!("CredentialDeleted");
        }
    }

    Ok(NotificationResponse {})
}

// #[cfg(test)]
// mod tests {
//     use insta::assert_yaml_snapshot as assert_snapshot;
//     use issuer_provider::{Provider, CREDENTIAL_ISSUER};

//     use super::*;

//     #[tokio::test]
//     async fn notification_ok() {
//         test_utils::init_tracer();

//         let provider = Provider::new();

//         let request = MetadataRequest {
//             credential_issuer: CREDENTIAL_ISSUER.to_string(),
//             languages: None,
//         };
//         let response = Endpoint::new(provider).metadata(request).await.expect("response is ok");
//         assert_snapshot!("response", response, {
//             ".credential_configurations_supported" => insta::sorted_redaction(),
//             ".credential_configurations_supported.*.credential_definition.credentialSubject" => insta::sorted_redaction()
//         });
//     }
// }
