//! # Token Endpoint
//!
//! The token endpoint is used to request a token from the issuer. The token
//! response will contain the access token and a list of credential identifiers
//! that the holder can request from the issuer.

use std::collections::HashMap;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{CredentialAuthorization, TokenGrantType, TokenRequest};

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
    pub authorized: Option<HashMap<String, Vec<String>>>,
}

/// Progresses the issuance flow by getting an access token.
///
/// Returns the issuance flow identifier.
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

    // Can't make a token request for an unauthorized issuance. The flow must
    // be pre-authorized and accepted or an authorization must have occurred.
    //
    // TODO: The wallet is supposed to handle the case where there are no
    // grants by using issuer metadata to determine the required grants. However,
    // the metata specification does not currently include this information. Until
    // it does, we return an error here.
    let Some(grants) = issuance.offer.grants.clone() else {
        let e = anyhow!("no grants in offer is not supported");
        tracing::error!(target: "Endpoint::token", ?e);
        return Err(e);
    };
    if !(issuance.status == Status::Authorized
        || (grants.pre_authorized_code.is_some() && issuance.status == Status::Accepted))
    {
        let e =
            anyhow!("invalid issuance state. Must be pre-authorized and accepted or authorized");
        tracing::error!(target: "Endpoint::token", ?e);
        return Err(e);
    }

    // Request an access token from the issuer.
    let token_request = token_request(&issuance);
    issuance.token = match Issuer::get_token(&provider, &issuance.id, token_request).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(target: "Endpoint::token", ?e);
            return Err(e);
        }
    };
    issuance.status = Status::TokenReceived;

    let mut response = AuthorizedCredentials {
        issuance_id: issuance.id.clone(),
        authorized: None,
    };
    if let Some(auth_details) = issuance.token.authorization_details.clone() {
        let mut authorized = HashMap::new();
        for auth in auth_details {
            let cfg_id = match auth.authorization_detail.credential {
                CredentialAuthorization::ConfigurationId {
                    credential_configuration_id,
                    ..
                } => credential_configuration_id,
                CredentialAuthorization::Format(cfmt) => {
                    match issuance.issuer.credential_configuration_id(&cfmt) {
                        Ok(cfg_id) => cfg_id,
                        Err(e) => {
                            tracing::error!(target: "Endpoint::token", ?e);
                            return Err(e);
                        }
                    }
                    .to_string()
                }
            };
            authorized.insert(cfg_id, auth.credential_identifiers.clone());
        }

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
