//! # Issuance Offer Acceptance
//!
//! The `accept` endpoint is used to register acceptance of a credential
//! issuance offer with the issuance flow. If a PIN is required, this endpoint
//! will simply update the state to indicate that, otherwise it will proceed
//! with the token request and credential requests.

use anyhow::anyhow;
use chrono::{DateTime, Utc};use serde::{Deserialize, Serialize};
use tracing::instrument;

use super::{Issuance, Status};
use crate::provider::{HolderProvider, StateStore};

/// `AcceptRequest` is the request to the `accept` endpoint to accept a
/// credential issuance offer.
///
/// The flow ID is the issuance flow identifier and
/// the list of credential configuration IDs are the credentials the holder
/// wishes to accept.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AcceptRequest {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The list of credential configuration IDs to accept.
    ///
    /// None implies the holder wants all credentials and all claims on offer.
    ///
    /// Use the cancel endpoint to abandon the issuance and accept no
    /// credentials on offer.
    pub credential_configuration_ids: Vec<String>,
}

/// Progresses the issuance flow triggered by a holder accepting a credential
/// offer.
#[instrument(level = "debug", skip(provider))]
pub async fn accept(
    provider: impl HolderProvider, request: &AcceptRequest,
) -> anyhow::Result<Status> {
    tracing::debug!("Endpoint::accept");

    // Abandon the issuance if no credentials are accepted.
    if request.credential_configuration_ids.is_empty() {
        tracing::debug!(target: "Endpoint::accept", "no credentials accepted");
        return Ok(Status::Inactive);
    }

    let mut issuance: Issuance = match StateStore::get(&provider, &request.issuance_id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        }
    };

    if issuance.status != Status::Ready {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    }
    let Some(grants) = &issuance.offer.grants else {
        let e = anyhow!("no grants");
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };
    let Some(pre_auth_code) = &grants.pre_authorized_code else {
        let e = anyhow!("no pre-authorized code");
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };
    issuance.accepted = None;

    if pre_auth_code.tx_code.is_some() {
        issuance.status = Status::PendingPin;
    } else {
        issuance.status = Status::Accepted;
    }

    // Stash the state for the next step.
    if let Err(e) = StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await {
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };

    Ok(issuance.status)
}
