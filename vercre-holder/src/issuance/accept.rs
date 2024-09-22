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
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{AuthorizationDetail, AuthorizationSpec, ConfigurationId};

use super::{Issuance, Status};
use crate::provider::{HolderProvider, StateStore};

/// `AcceptRequest` is the request to the `accept` endpoint to accept a
/// credential issuance offer.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AcceptRequest {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The list of credentials to accept out of the ones offered.
    ///
    /// Send `None` to imply the holder wants all credentials and all claims on
    /// offer.
    pub accept: Option<Vec<ConfigurationId>>,
}

/// Progresses the issuance flow triggered by a holder accepting a credential
/// offer.
/// 
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn accept(
    provider: impl HolderProvider, request: &AcceptRequest,
) -> anyhow::Result<String> {
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

    issuance.accepted = narrow_scope(&request.accept);

    if pre_auth_code.tx_code.is_some() {
        issuance.status = Status::PendingPin;
    } else {
        issuance.status = Status::Accepted;
    }

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };

    Ok(issuance.id)
}

fn narrow_scope(accept: &Option<Vec<ConfigurationId>>) -> Option<Vec<AuthorizationDetail>> {
    let accept = accept.clone()?;
    let mut auth_details = Vec::new();
    for config in accept {
        let detail = AuthorizationDetail {
            specification: AuthorizationSpec::ConfigurationId(config),
            ..Default::default()
        };
        auth_details.push(detail);
    }

    Some(auth_details)
}
