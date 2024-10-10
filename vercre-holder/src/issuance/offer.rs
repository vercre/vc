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

use super::{Issuance, Status};
use crate::provider::{HolderProvider, StateStore};

/// `OfferRequest` is the request to the `offer` endpoint to initiate an
/// issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
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
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct OfferResponse {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The identifer of the credential issuer.
    pub issuer: String,

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
    let mut issuance = Issuance::new(&request.client_id);
    issuance.subject_id.clone_from(&request.subject_id);
    issuance.status = Status::Offered;

    // Set up a credential configuration for each credential offered.
    issuance.offer = request.offer.clone();
    issuance.set_issuer(&provider, &request.offer.credential_issuer).await.map_err(|e| {
        tracing::error!(target: "Endpoint::offer", ?e);
        e
    })?;

    // Either the offer has grants supported or the OAuth server does. If not,
    // we can't proceed.
    // let grants = if let Some(grants) = request.offer.grants.clone() {
    //     grants
    // } else {
    //     let Some(grant_types) =
    // issuance.authorization_server.oauth.grant_types_supported.clone()
    //     else {
    //         let e = anyhow!("no grants in offer is not supported");
    //         tracing::error!(target: "Endpoint::offer", ?e);
    //         return Err(e);
    //     };
    //     let authorization_code = if
    // grant_types.contains(&GrantType::AuthorizationCode) {
    //         Some(AuthorizationCodeGrant::default())
    //     } else {
    //         None
    //     };
    //     let pre_authorized_code = if
    // grant_types.contains(&GrantType::PreAuthorizedCode) {
    //         Some(PreAuthorizedCodeGrant::default())
    //     } else {
    //         None
    //     };
    //     Grants {
    //         authorization_code,
    //         pre_authorized_code,
    //     }
    // };

    issuance.status = Status::Ready;

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    };

    // Trim the supported credentials to just those on offer so that the holder
    // can decide which to accept.
    let mut offered = HashMap::<String, CredentialConfiguration>::new();
    let creds_supported = &issuance.issuer.credential_configurations_supported;
    for cfg_id in &request.offer.credential_configuration_ids {
        // find supported credential in metadata and copy to state object.
        let Some(found) = creds_supported.get(cfg_id) else {
            let e = anyhow!("unsupported credential type in offer");
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        };
        offered.insert(cfg_id.clone(), found.clone());
    }

    let res = OfferResponse {
        issuance_id: issuance.id,
        issuer: request.offer.credential_issuer.clone(),
        offered,
        grants: request.offer.grants.clone(),
    };

    Ok(res)
}
