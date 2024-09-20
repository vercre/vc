//! # Issuance Offer Acceptance
//!
//! The `accept` endpoint is used to register acceptance of a credential
//! issuance offer with the issuance flow. If a PIN is required, this endpoint
//! will simply update the state to indicate that, otherwise it will proceed
//! with the token request and credential requests.
//! 
//! The holder is not obligated to accept all credentials offered. Use the
//! `accept` field to limit the scope of the acceptance. This will be used
//! downstream in the flow to specialize the access token and credential
//! requests which are honored by the respective `vercre-issuer` endpoints.

use anyhow::anyhow;
use chrono::{DateTime, Utc};use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::AuthorizationDetail;

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

    /// The list of credentials to accept out of the ones offered.
    ///
    /// The structure allows the holder to narrow the scope of the credentials
    /// and also the claims contained in the credential. Send `None` to imply
    /// the holder wants all credentials and all claims on offer.
    ///
    /// Use the cancel endpoint to abandon the issuance and accept no
    /// credentials on offer.
    pub accept: Option<Vec<AuthorizationDetail>>,
}

/// Progresses the issuance flow triggered by a holder accepting a credential
/// offer.
#[instrument(level = "debug", skip(provider))]
pub async fn accept(
    provider: impl HolderProvider, request: &AcceptRequest,
) -> anyhow::Result<Status> {
    tracing::debug!("Endpoint::accept");

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
    if let Some(accepted) = &request.accept {
        if accepted.is_empty() {
            let e = anyhow!("if accept is provided it cannot be empty");
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        }
    };

    issuance.accepted.clone_from(&request.accept);

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
