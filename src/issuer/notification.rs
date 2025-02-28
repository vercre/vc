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

use super::state::{Stage, State};
use crate::openid::issuer::{NotificationRequest, NotificationResponse, Provider};
use crate::openid::provider::StateStore;
use crate::openid::{Error, Result};

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
