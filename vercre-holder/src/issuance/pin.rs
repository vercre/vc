//! # Issuance Offer Set PIN
//!
//! The `pin` endpoint is used to set a PIN for use in the token request as part of the issuance
//! flow.

use std::fmt::Debug;

use anyhow::anyhow;
use tracing::instrument;

use super::{Issuance, Status};
use crate::provider::HolderProvider;

/// A `PinRequest` is a request to set a PIN for use in the issuance flow.
#[derive(Clone, Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct PinRequest {
    /// The issuance flow ID.
    pub id: String,
    /// The PIN to set.
    pub pin: String,
}

/// Progresses the issuance flow triggered by a holder setting a PIN.
/// The request is the issuance flow ID.
#[instrument(level = "debug", skip(provider))]
pub async fn pin(provider: impl HolderProvider, request: &PinRequest) -> anyhow::Result<Issuance> {
    tracing::debug!("Endpoint::pin");

    let mut issuance = match super::get_issuance(provider.clone(), &request.id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::pin", ?e);
            return Err(e);
        }
    };
    if issuance.status != Status::PendingPin {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::pin", ?e);
        return Err(e);
    };

    // Update the state of the flow to indicate the PIN has been set.
    issuance.pin = Some(request.pin.clone());
    issuance.status = Status::Accepted;

    // Stash the state for the next step.
    if let Err(e) = super::put_issuance(provider, &issuance).await {
        tracing::error!(target: "Endpoint::pin", ?e);
        return Err(e);
    };

    Ok(issuance)
}
