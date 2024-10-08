//! # Token Endpoint
//!
//! The token endpoint is used to request a token from the issuer. The token
//! response will contain the access token and a list of credential identifiers
//! that the holder can request from the issuer.

use std::collections::HashMap;

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{
    AuthorizedDetail, CredentialAuthorization, TokenGrantType, TokenRequest,
};

use super::{Issuance, Status};
use crate::provider::{HolderProvider, Issuer, StateStore};

/// `AuthorizedCredentials` is the response from the `token` endpoint.
///
/// The agent application can use this to present the available credential
/// identifiers to the holder for selection.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AuthorizedCredentials {
    /// The issuance flow identifier.
    pub issuance_id: String,

    /// The list of credential identifiers the holder is authorized to request,
    /// keyed by credential configuration ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorized: Option<HashMap<String, Vec<String>>>,
}

/// Progresses the issuance flow by getting an access token for a pre-authorized
/// issuance flow.
///
/// Returns the issuance flow identifier.
///
/// This function should only be called by the holder's agent (wallet) for
/// pre-authorized issuance flows. For authorization flows, the `authorize`
/// endpoint should be used that endpoint will make the token request after
/// receiving the authorization response from the issuer.
#[instrument(level = "debug", skip(provider))]
pub async fn token(
    provider: impl HolderProvider, issuance_id: &str,
) -> anyhow::Result<AuthorizedCredentials> {
    tracing::debug!("Endpoint::token");

    let mut issuance: Issuance = match StateStore::get(&provider, issuance_id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::token", ?e);
            return Err(e);
        }
    };

    // The flow must be pre-authorized and accepted.
    let pre_authed = if let Some(grants) = issuance.offer.grants.clone() {
        grants.pre_authorized_code.is_some()
    } else {
        false
    };
    if !pre_authed || issuance.status != Status::Accepted {
        let e = anyhow!("invalid issuance state. Must be pre-authorized and accepted");
        tracing::error!(target: "Endpoint::token", ?e);
        return Err(e);
    }

    // Request an access token from the issuer.
    let token_request = token_request(&issuance).map_err(|e| {
        tracing::error!(target: "Endpoint::token", ?e);
        e
    })?;
    issuance.token = Issuer::token(&provider, token_request).await.map_err(|e| {
        tracing::error!(target: "Endpoint::token", ?e);
        e
    })?;
    issuance.status = Status::TokenReceived;

    let mut response = AuthorizedCredentials {
        issuance_id: issuance.id.clone(),
        authorized: None,
    };
    if let Some(auth_details) = issuance.token.authorization_details.clone() {
        let authorized = authorized_credentials(&auth_details, &issuance).map_err(|e| {
            tracing::error!(target: "Endpoint::token", ?e);
            e
        })?;
        response.authorized = Some(authorized);
    }

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };

    Ok(response)
}

/// Construct a token request.
fn token_request(issuance: &Issuance) -> anyhow::Result<TokenRequest> {
    let Some(grants) = issuance.offer.grants.as_ref() else {
        bail!("no grants in offer is not supported");
    };
    let Some(pre_auth_code) = grants.pre_authorized_code.as_ref() else {
        bail!("no pre-authorized code in offer is not supported");
    };

    Ok(TokenRequest {
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        client_id: Some(issuance.client_id.clone()),
        grant_type: TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_code.pre_authorized_code.clone(),
            tx_code: issuance.pin.clone(),
        },
        authorization_details: issuance.accepted.clone(),
        // TODO: support this
        client_assertion: None,
    })
}

/// Construct authorized credential idenifiers from authorization details.
///
/// Uses issuer metadata in the case of a format specification to resolve to
/// credential configuration IDs.
pub fn authorized_credentials(
    details: &[AuthorizedDetail], issuance: &Issuance,
) -> anyhow::Result<HashMap<String, Vec<String>>> {
    let mut authorized = HashMap::new();
    for auth in details {
        let cfg_id = match &auth.authorization_detail.credential {
            CredentialAuthorization::ConfigurationId {
                credential_configuration_id,
                ..
            } => credential_configuration_id,
            CredentialAuthorization::Format(cfmt) => {
                issuance.issuer.credential_configuration_id(cfmt)?
            }
        };
        authorized.insert(cfg_id.into(), auth.credential_identifiers.clone());
    }
    Ok(authorized)
}
