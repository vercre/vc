//! # Save Endpoint
//!
//! Enables the holder to save the credentials returned from the issuer to
//! persistent storage.
//!
//! The converse of this endpoint is the `cancel` endpoint.
use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{NotificationEvent, NotificationRequest};

use super::IssuanceState;
use crate::provider::{CredentialStorer, HolderProvider, Issuer, StateStore};

/// Save request.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct SaveRequest {
    /// Issuance flow identifier.
    pub issuance_id: String,
}

/// Saves the credentials buffered in the issuance flow to persistent storage.
///
/// Notifies the issuer if configured to do so and clears state.
///
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn save(provider: impl HolderProvider, request: &SaveRequest) -> anyhow::Result<String> {
    tracing::debug!("Endpoint::save");

    let mut issuance: IssuanceState =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::save", ?e);
            e
        })?;
    let access_token = match issuance.token {
        Some(token) => token.access_token.clone(),
        None => String::new(),
    };
    let Some(issuer) = &issuance.issuer else {
        let e = anyhow!("no issuer metadata");
        tracing::error!(target: "Endpoint::save", ?e);
        return Err(e);
    };

    for credential in &issuance.credentials {
        match CredentialStorer::save(&provider, credential).await {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(target: "Endpoint::save", ?e);
                // Notify issuer of failure if possible. If notification fails, do
                // nothing except trace and return the original error.
                if let Some(notification_id) = issuance.notification_id {
                    async {
                        if let Err(err) = Issuer::notification(
                            &provider,
                            NotificationRequest {
                                credential_issuer: issuer.credential_issuer.clone(),
                                access_token: access_token.clone(),
                                notification_id,
                                event: NotificationEvent::CredentialFailure,
                                event_description: Some("Failed to save credential".into()),
                            },
                        )
                        .await
                        {
                            tracing::error!(target: "Endpoint::save", ?err);
                        }
                    }
                    .await;
                }
                return Err(e);
            }
        }
    }
    issuance.credentials.clear();

    // Notify issuer if we have been given a notification ID.
    if let Some(notification_id) = issuance.notification_id {
        if let Err(e) = Issuer::notification(
            &provider,
            NotificationRequest {
                credential_issuer: issuer.credential_issuer.clone(),
                access_token,
                notification_id,
                event: NotificationEvent::CredentialAccepted,
                event_description: Some("Issuance completed".into()),
            },
        )
        .await
        {
            tracing::error!(target: "Endpoint::save", ?e);
            return Err(e);
        }
    }

    // Purge state if there are no deferred credentials left to process.
    if issuance.deferred_deprecated.is_empty() {
        if let Err(e) = StateStore::purge(&provider, &request.issuance_id).await {
            tracing::error!(target: "Endpoint::save", ?e);
            return Err(e);
        }
        return Ok(request.issuance_id.clone());
    }

    Ok(request.issuance_id.clone())
}
