//! # Cancel Issuance Endpoint
//!
//! Enables the holder to cancel an issuance flow.

use tracing::instrument;

use super::Issuance;
use crate::provider::{HolderProvider, StateStore};

/// Cancels the issuance flow.
///
/// Notifies the issuer if configured to do so and clears state.
///
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn cancel(provider: impl HolderProvider, issuance_id: &str) -> anyhow::Result<String> {
    tracing::debug!("Endpoint::cancel");

    let issuance: Issuance = StateStore::get(&provider, issuance_id).await.map_err(|e| {
        tracing::error!(target: "Endpoint::cancel", ?e);
        e
    })?;

    // TODO: Issuer notification endpoint.

    // Purge state.
    if let Err(e) = StateStore::purge(&provider, issuance_id).await {
        tracing::error!(target: "Endpoint::cancel", ?e);
        return Err(e);
    };

    Ok(issuance.id)
}
