//! # Deferred Credentials Endpoint
//!
//! Use a previously issued transaction ID to retrieve a credential.

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::DeferredCredentialRequest;

use super::{IssuanceState, Status};
use crate::issuance::credentials::{process_credential_response, CredentialsResponse};
use crate::provider::{HolderProvider, Issuer, StateStore};

/// Deferred credential request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::module_name_repetitions)]
pub struct DeferredRequest {
    /// Issuance flow identifier.
    pub issuance_id: String,

    /// Transaction ID of the deferred credential.
    pub transaction_id: String,

    /// Credential configuration ID for the deferred credential.
    pub credential_configuration_id: String,
}

/// Progresses the issuance flow by requesting a credential where a previous
/// transaction ID was issued in lieu of a credential.
///
/// Returns the issuance flow identifier and a deferred transaction ID if the
/// credential is not yet available.
#[instrument(level = "debug", skip(provider))]
pub async fn deferred(
    provider: impl HolderProvider, request: &DeferredRequest,
) -> anyhow::Result<CredentialsResponse> {
    tracing::debug!("Endpoint::credentials {:?}", request);

    let mut issuance: IssuanceState =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::deferred", ?e);
            e
        })?;
    if issuance.status != Status::TokenReceived {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    }
    let Some(token_response) = &issuance.token else {
        let e = anyhow!("token not found in issuance state");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    };
    let Some(issuer) = &issuance.issuer else {
        let e = anyhow!("no issuer metadata on issuance state");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    };

    issuance.deferred.remove(&request.transaction_id);

    let def_cred_request = DeferredCredentialRequest {
        transaction_id: request.transaction_id.clone(),
        credential_issuer: issuer.credential_issuer.clone(),
        access_token: token_response.access_token.clone(),
    };
    let deferred_response = Issuer::deferred(&provider, def_cred_request).await.map_err(|e| {
        tracing::error!(target: "Endpoint::deferred", ?e);
        e
    })?;

    let Some(config) =
        issuer.credential_configurations_supported.get(&request.credential_configuration_id)
    else {
        let e = anyhow!("credential configuration not found in issuer metadata");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    };

    match process_credential_response(
        provider.clone(),
        config,
        &deferred_response.credential_response,
        issuer,
    )
    .await
    {
        Ok((credentials, transaction_id)) => {
            if let Some(credentials) = credentials {
                issuance.credentials.extend(credentials);
            }
            if let Some(id) = transaction_id {
                issuance.deferred.insert(id, request.credential_configuration_id.clone());
            }
        }
        Err(e) => {
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
    };

    // Release issuance state if no more deferred credentials and no
    // credentials to save, otherwise stash the state.
    if issuance.deferred.is_empty() && issuance.credentials.is_empty() {
        StateStore::purge(&provider, &issuance.id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::credentials", ?e);
            anyhow!("issue purging state: {e}")
        })?;
    } else if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    };

    let deferred =
        if issuance.deferred.is_empty() { None } else { Some(issuance.deferred.clone()) };

    Ok(CredentialsResponse {
        issuance_id: issuance.id,
        deferred,
    })
}

impl IssuanceState {
    /// Construct a deferred credential request.
    ///
    /// # Errors
    /// Will return an error if the issuance state is not consistent with
    /// constructing such a request.
    pub fn deferred_request(&self, transaction_id: &str) -> anyhow::Result<DeferredCredentialRequest> {
        if self.status != Status::TokenReceived {
            bail!("invalid issuance state status");
        }
        let Some(token_response) = &self.token else {
            bail!("token not found in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata on issuance state");
        };
        let def_cred_request = DeferredCredentialRequest {
            transaction_id: transaction_id.into(),
            credential_issuer: issuer.credential_issuer.clone(),
            access_token: token_response.access_token.clone(),
        };
        Ok(def_cred_request)
    }

    /// Add a deferred transaction ID to the issuance state.
    pub fn add_deferred(&mut self, tx_id: &String, cfg_id: &String) {
        self.deferred.insert(tx_id.into(), cfg_id.into());
    }

    /// Remove a pending deferred credential transaction from state.
    pub fn remove_deferred(&mut self, transaction_id: &str) {
        self.deferred.remove(transaction_id);
    }
}
