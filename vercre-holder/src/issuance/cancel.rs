use tracing::instrument;

use super::Issuance;
use crate::provider::{HolderProvider, StateStore};

/// Cancels the issuance flow.
/// 
/// Notifies the issuer if configured to do so and clears state.
#[instrument(level = "debug", skip(provider))]
pub async fn cancel(provider: impl HolderProvider, issuance_id: &str) -> anyhow::Result<()> {
    tracing::debug!("Endpoint::cancel");

    let _issuance: Issuance = match StateStore::get(&provider, issuance_id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::cancel", ?e);
            return Err(e);
        }
    };

    // TODO: Issuer notification endpoint.

    // Purge state.
    if let Err(e) = StateStore::purge(&provider, issuance_id).await {
        tracing::error!(target: "Endpoint::cancel", ?e);
        return Err(e);
    };

    Ok(())
}
