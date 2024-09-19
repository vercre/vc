// TODO: implement Notification endpoint

//! # Notification Endpoint
//!
//! This endpoint is used by the Wallet to notify the Credential Issuer of
//! certain events for issued Credentials. These events enable the Credential
//! Issuer to take subsequent actions after issuance.
//!
//! The Credential Issuer needs to return one or
//! more `notification_id` parameters in the Credential Response or the Batch
//! Credential Response for the Wallet to be able to use this Endpoint. Support
//! for this endpoint is OPTIONAL. The Issuer cannot assume that a notification
//! will be sent for every issued credential since the use of this Endpoint is
//! not mandatory for the Wallet.
//!
//! The notification from the Wallet is idempotent. When the Credential Issuer
//! receives multiple identical calls from the Wallet for the same
//! `notification_id`, it returns success. Due to the network errors, there are
//! no guarantees that a Credential Issuer will receive a notification within a
//! certain time period or at all.

use tracing::instrument;
use vercre_openid::issuer::{NotificationRequest, NotificationResponse, Provider, StateStore};
use vercre_openid::{Error, Result};

use crate::state::{Stage, State};

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
    provider: &impl Provider, request: NotificationRequest,
) -> Result<NotificationResponse> {
    tracing::debug!("notification::process");

    let Ok(state) = StateStore::get::<State>(provider, &request.notification_id).await else {
        return Err(Error::AccessDenied("invalid access token".into()));
    };
    let Stage::Issued(credential) = state.stage else {
        return Err(Error::ServerError("issued state not found".into()));
    };

    StateStore::purge(provider, &request.notification_id)
        .await
        .map_err(|e| Error::ServerError(format!("failed to purge state: {e}")))?;

    tracing::info!(
        "notification: {:#?}, {:#?} for credential: {:#?}",
        request.event,
        request.event_description,
        credential
    );

    Ok(NotificationResponse {})
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_openid::issuer::NotificationEvent;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;
    use vercre_w3c_vc::model::VerifiableCredential;

    use super::*;
    use crate::state::{Credential, Expire};

    #[tokio::test]
    async fn notification_ok() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let notification_id = "123456";

        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: Some(NORMAL_USER.into()),
            stage: Stage::Issued(Credential {
                credential: VerifiableCredential::default(),
            }),
        };
        StateStore::put(&provider, notification_id, &state, state.expires_at)
            .await
            .expect("state exists");

        let request = NotificationRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            access_token: "ABCDEF".into(),
            notification_id: notification_id.into(),
            event: NotificationEvent::CredentialAccepted,
            event_description: Some("Credential accepted".into()),
        };
        let response = notification(provider.clone(), request).await.expect("response is ok");

        assert_snapshot!("notification:ok:response", response);

        assert_let!(Err(_), StateStore::get::<State>(&provider, notification_id).await);
    }
}
