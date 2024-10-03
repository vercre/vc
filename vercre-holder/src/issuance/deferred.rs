//! # Deferred Credentials Endpoint
//!
//! Use a previously issued transaction ID to retrieve a credential.

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{CredentialResponseType, DeferredCredentialRequest};

use super::{Issuance, Status};
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

    let mut issuance: Issuance =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::deferred", ?e);
            e
        })?;
    if issuance.status != Status::TokenReceived {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    }

    let mut deferred = issuance.deferred.unwrap_or_default();
    deferred.remove(&request.transaction_id);

    let def_cred_request = DeferredCredentialRequest {
        transaction_id: request.transaction_id.clone(),
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        access_token: issuance.token.access_token.clone(),
    };
    let deferred_response = Issuer::deferred(&provider, def_cred_request).await.map_err(|e| {
        tracing::error!(target: "Endpoint::deferred", ?e);
        e
    })?;

    let Some(config) = issuance
        .issuer
        .credential_configurations_supported
        .get(&request.credential_configuration_id)
    else {
        let e = anyhow!("credential configuration not found in issuer metadata");
        tracing::error!(target: "Endpoint::deferred", ?e);
        return Err(e);
    };

    match process_credential_response(
        provider.clone(),
        config,
        &deferred_response.credential_response,
    )
    .await
    {
        Ok(()) => {
            if let CredentialResponseType::TransactionId(id) =
                &deferred_response.credential_response.response
            {
                deferred.insert(id.clone(), request.credential_configuration_id.clone());
            }
        }
        Err(e) => {
            tracing::error!(target: "Endpoint::deferred", ?e);
            return Err(e);
        }
    };

    // Release issuance state if no more deferred credentials.
    let deferred = if deferred.is_empty() {
        StateStore::purge(&provider, &issuance.id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::credentials", ?e);
            anyhow!("issue purging state: {e}")
        })?;
        None
    } else {
        issuance.deferred = Some(deferred.clone());
        Some(deferred)
    };

    Ok(CredentialsResponse {
        issuance_id: issuance.id,
        deferred,
    })
}
