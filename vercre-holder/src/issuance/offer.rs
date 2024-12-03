//! # Issuance Offer Endpoint
//!
//! The offer endpoint processes an issuance offer request where the offer
//! originates with an issuer. The endpoint uses the holder client to get
//! metadata and present the offer details for acceptance/rejection by the
//! holder.

use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_openid::issuer::{CredentialConfiguration, CredentialOffer, Grants};

use super::{IssuanceState, Status};
use crate::issuance::FlowType;
use crate::provider::{HolderProvider, StateStore};

/// `OfferRequest` is the request to the `offer` endpoint to initiate an
/// issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub struct OfferRequest {
    /// Wallet client identifier. This is used by the issuance service to issue
    /// an access token so should be unique to the holder's agent. Care
    /// should be taken to ensure this is not shared across holders in the
    /// case of headless, multi-tenant agents.
    pub client_id: String,

    /// Holder's identifer.
    pub subject_id: String,

    /// The credential offer from the issuer.
    pub offer: CredentialOffer,
}

/// `OfferResponse` is the response from the `offer` endpoint.
///
/// The agent application can use this to present the offer to the holder for
/// acceptance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub struct OfferResponse {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The identifer of the credential issuer.
    pub issuer: String,

    /// The name of the credential issuer.
    pub issuer_name: String,

    /// The credentials offered from the issuer to the holder, keyed by
    /// credential configuration ID.
    pub offered: HashMap<String, CredentialConfiguration>,

    /// Authorization requirements.
    pub grants: Option<Grants>,
}

/// Initiates the issuance flow triggered by a new credential offer
/// ("issuer-initiated issuance").
///
/// Returns a set of credential configurations that allow a display to the
/// holder for acceptance or rejection of some or all of the offered
/// credentials.
#[instrument(level = "debug", skip(provider))]
pub async fn offer(
    provider: impl HolderProvider, request: &OfferRequest,
) -> anyhow::Result<OfferResponse> {
    tracing::debug!("Endpoint::offer");

    if request.offer.credential_configuration_ids.is_empty() {
        let e = anyhow!("no credential IDs");
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    }

    // Establish a new issuance flow state
    let flow_type = request.offer.grants.as_ref().map_or(FlowType::IssuerAuthorized, |grants| {
        if grants.pre_authorized_code.is_some() {
            FlowType::IssuerPreAuthorized
        } else {
            FlowType::IssuerAuthorized
        }
    });
    let mut issuance = IssuanceState::new(flow_type, &request.client_id, &request.subject_id);
    issuance.subject_id.clone_from(&request.subject_id);
    issuance.status = Status::Offered;

    // Set up a credential configuration for each credential offered.
    issuance.offer = Some(request.offer.clone());
    issuance.set_issuer(&provider, &request.offer.credential_issuer).await.map_err(|e| {
        tracing::error!(target: "Endpoint::offer", ?e);
        e
    })?;

    issuance.status = Status::Offered;

    // Trim the supported credentials to just those on offer so that the holder
    // can decide which to accept.
    let Some(issuer) = &issuance.issuer else {
        let e = anyhow!("no issuer metadata");
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    };
    let mut offered = HashMap::<String, CredentialConfiguration>::new();
    let creds_supported = &issuer.credential_configurations_supported;
    for cfg_id in &request.offer.credential_configuration_ids {
        // find supported credential in metadata and copy to state object.
        let Some(found) = creds_supported.get(cfg_id) else {
            let e = anyhow!("unsupported credential type in offer");
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        };
        offered.insert(cfg_id.clone(), found.clone());
    }

    // TODO: Locale support.
    let issuer_name = issuer.display_name(None).unwrap_or_default();

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    };

    let res = OfferResponse {
        issuance_id: issuance.id,
        issuer: request.offer.credential_issuer.clone(),
        issuer_name,
        offered,
        grants: request.offer.grants.clone(),
    };

    Ok(res)
}

impl IssuanceState {
    /// Update the issuance state with the issuer's offer information.
    ///
    /// Requires issuer and oauth server metadata to be set.
    ///
    /// # Errors
    /// Will return an error if the state is not in the correct state to apply
    /// an offer.
    pub fn offer(
        &mut self, offer: &CredentialOffer,
    ) -> anyhow::Result<HashMap<String, CredentialConfiguration>> {
        // Check current state is valid for this operation.
        if self.status != Status::AuthServerSet {
            let e = anyhow!("invalid state to apply an offer");
            tracing::error!(target: "IssuanceState::offer", ?e);
            return Err(e);
        }

        self.offer = Some(offer.clone());

        // Explicitly extract the credential configurations from the issuer
        // metadata that match the credentials on offer to make it easier to
        // present to the holder.
        let Some(issuer) = &self.issuer else {
            let e = anyhow!("issuer metadata has not been set on flow state");
            tracing::error!(target: "IssuanceState::offer", ?e);
            return Err(e);
        };
        let mut offered = HashMap::<String, CredentialConfiguration>::new();
        let creds_supported = &issuer.credential_configurations_supported;
        for cfg_id in &offer.credential_configuration_ids {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                let e = anyhow!("unsupported credential type in offer");
                tracing::error!(target: "IssuanceState::offer", ?e);
                return Err(e);
            };
            offered.insert(cfg_id.clone(), found.clone());
        }

        self.status = Status::Offered;
        Ok(offered)
    }
}
