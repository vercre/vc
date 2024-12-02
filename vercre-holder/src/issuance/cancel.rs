//! # Cancel Issuance Endpoint
//!
//! Enables the holder to cancel an issuance flow.
//!
//! The converse of this endpoint is the `save` endpoint.
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{NotificationEvent, NotificationRequest};

use super::IssuanceState;
use crate::provider::{HolderProvider, Issuer, StateStore};

/// Cancel request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CancelRequest {
    /// Issuance flow identifier.
    pub issuance_id: String,
}

/// Cancels the issuance flow.
///
/// Notifies the issuer if configured to do so and clears state.
///
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn cancel(
    provider: impl HolderProvider, request: &CancelRequest,
) -> anyhow::Result<String> {
    tracing::debug!("Endpoint::cancel");

    let issuance: IssuanceState =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::cancel", ?e);
            e
        })?;

    let access_token = match issuance.token {
        Some(token) => token.access_token.clone(),
        None => String::new(),
    };

    // Notify issuer if we have been given a notification ID.
    if let Some(notification_id) = issuance.notification_id {
        let Some(issuer) = &issuance.issuer else {
            let e = anyhow!("no issuer metadata");
            tracing::error!(target: "Endpoint::cancel", ?e);
            return Err(e);
        };
        if let Err(e) = Issuer::notification(
            &provider,
            NotificationRequest {
                credential_issuer: issuer.credential_issuer.clone(),
                access_token,
                notification_id,
                event: NotificationEvent::CredentialDeleted,
                event_description: Some("Issuance cancelled".into()),
            },
        )
        .await
        {
            tracing::error!(target: "Endpoint::cancel", ?e);
            return Err(e);
        }
    }

    // Purge state.
    if let Err(e) = StateStore::purge(&provider, &request.issuance_id).await {
        tracing::error!(target: "Endpoint::cancel", ?e);
        return Err(e);
    };

    Ok(issuance.id)
}
