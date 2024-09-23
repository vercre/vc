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
use vercre_openid::issuer::{CredentialConfiguration, CredentialOffer, MetadataRequest, TxCode};

use super::{Issuance, Status};
use crate::provider::{HolderProvider, Issuer, StateStore};

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

    /// Details of any PIN required by the holder to accept the offer.
    pub tx_code: Option<TxCode>,
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
    let Some(grants) = &request.offer.grants else {
        let e = anyhow!("no grants");
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    };
    let Some(pre_authorized_code) = &grants.pre_authorized_code else {
        let e = anyhow!("no pre-authorized code");
        tracing::error!(target: "Endpoint::offer", ?e);
        return Err(e);
    };

    // Establish a new issuance flow state
    let mut issuance = Issuance::new(&request.client_id);
    issuance.status = Status::Offered;

    // Set up a credential configuration for each credential offered.
    issuance.offer = request.offer.clone();

    // Process the offer and establish a metadata request, passing that to the
    // provider to use.
    let md_request = MetadataRequest {
        credential_issuer: request.offer.credential_issuer.clone(),
        languages: None, // The wallet client should provide any specific languages required.
    };

    // The wallet client's provider makes the metadata request to the issuer.
    let md_response = match Issuer::get_metadata(&provider, &issuance.id, md_request).await {
        Ok(md) => md,
        Err(e) => {
            tracing::error!(target: "Endpoint::offer", ?e);
            return Err(e);
        }
    };
    // Update the flow state with issuer's metadata.
    issuance.issuer = md_response.credential_issuer.clone();    
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
    let creds_supported = &md_response.credential_issuer.credential_configurations_supported;
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
        tx_code: pre_authorized_code.tx_code.clone(),
    };

    Ok(res)
}
