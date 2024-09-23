//! # Token Endpoint
//!
//! The token endpoint is used to request a token from the issuer. The token
//! response will contain the access token and a list of credential identifiers
//! that the holder can request from the issuer.

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{TokenGrantType, TokenRequest};

use super::{Issuance, Status};
use crate::provider::{HolderProvider, Issuer, StateStore};

/// `AvailableIdentifiers` is the response from the `token` endpoint.
///
/// The agent application can use this to present the available credential
/// identifiers to the holder for selection.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AvailableIdentifiers {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The list of credential identifiers that the holder can request.
    pub credential_identifiers: Vec<String>,
}

/// Progresses the issuance flow by getting an access token.
///
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn token(provider: impl HolderProvider, issuance_id: &str) -> anyhow::Result<String> {
    tracing::debug!("Endpoint::token");

    let mut issuance: Issuance = match StateStore::get(&provider, issuance_id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::token", ?e);
            return Err(e);
        }
    };
    if issuance.status != Status::Accepted {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::token", ?e);
        return Err(e);
    }

    // Request an access token from the issuer.
    let token_request = token_request(&issuance);
    issuance.token = match Issuer::get_token(&provider, &issuance.id, token_request).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
    };
    issuance.status = Status::TokenReceived;

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };

    Ok(issuance.id)
}

/// Construct a token request.
fn token_request(issuance: &Issuance) -> TokenRequest {
    // Get pre-authorized code. Unwraps are OK since verification should be called
    // on outer endpoint to check existence.
    let grants = issuance.offer.grants.as_ref().expect("grants exist on offer");
    let pre_auth_code =
        grants.pre_authorized_code.as_ref().expect("pre-authorized code exists on offer");

    TokenRequest {
        credential_issuer: issuance.offer.credential_issuer.clone(),
        client_id: Some(issuance.client_id.clone()),
        grant_type: TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_code.pre_authorized_code.clone(),
            tx_code: issuance.pin.clone(),
        },
        authorization_details: issuance.accepted.clone(),
        client_assertion: None,
    }
}
