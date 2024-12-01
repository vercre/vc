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

use std::collections::HashMap;

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{
    AuthorizationDetail, Claim, CredentialAuthorization, CredentialConfiguration,
    CredentialDefinition, Format, ProfileClaims,
};

use super::{IssuanceState, Status};
use crate::provider::{HolderProvider, StateStore};

/// A configuration ID and a list of claims that can be used by the holder to
/// narrow the scope of the acceptance from the full set on offer.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AuthorizationSpec {
    /// The credential configuration ID to include.
    pub credential_configuration_id: String,

    /// The list of claims to include.
    ///
    /// If `None`, all claims are included.
    pub claims: Option<HashMap<String, Claim>>,
}

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
    pub accept: Option<Vec<AuthorizationSpec>>,
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

    let mut issuance: IssuanceState =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::accept", ?e);
            e
        })?;

    if issuance.status != Status::Ready {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    }
    if let Some(accepted) = &request.accept {
        if accepted.is_empty() {
            let e = anyhow!("if accept is provided it cannot be empty");
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        }
    };

    issuance.accepted =
        narrow_scope(&issuance.issuer.credential_configurations_supported, request.accept.as_ref())
            .map_err(|e| {
                tracing::error!(target: "Endpoint::accept", ?e);
                e
            })?;

    issuance.status = Status::Accepted;

    if let Some(grants) = &issuance.offer.grants {
        if let Some(pre_auth_code) = &grants.pre_authorized_code {
            if pre_auth_code.tx_code.is_some() {
                issuance.status = Status::PendingPin;
            }
        }
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

fn narrow_scope(
    offered: &HashMap<String, CredentialConfiguration>, accept: Option<&Vec<AuthorizationSpec>>,
) -> anyhow::Result<Option<Vec<AuthorizationDetail>>> {
    // Just return None if the holder wants all credential configurations.
    let Some(accept) = accept else {
        return Ok(None);
    };
    let mut auth_details = Vec::new();
    for auth_spec in accept {
        let claims: Option<ProfileClaims> = match &auth_spec.claims {
            Some(claims) => {
                let Some(credential_configuration) =
                    offered.get(&auth_spec.credential_configuration_id)
                else {
                    bail!("credential configuration accepted not found in offer");
                };

                let profile = match &credential_configuration.format {
                    Format::JwtVcJson(_) | Format::JwtVcJsonLd(_) | Format::LdpVc(_) => {
                        ProfileClaims::W3c(CredentialDefinition {
                            credential_subject: Some(claims.clone()),
                            ..CredentialDefinition::default()
                        })
                    }
                    Format::IsoMdl(_) | Format::VcSdJwt(_) => ProfileClaims::Claims(claims.clone()),
                };
                Some(profile)
            }
            None => None,
        };

        // TODO: Support CredentialAuthorization::Format
        let detail = AuthorizationDetail {
            credential: CredentialAuthorization::ConfigurationId {
                credential_configuration_id: auth_spec.credential_configuration_id.clone(),
                claims,
            },
            ..Default::default()
        };
        auth_details.push(detail);
    }

    Ok(Some(auth_details))
}
