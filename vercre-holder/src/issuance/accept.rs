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

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_issuer::{
    AuthorizationDetail, ClaimEntry, CredentialAuthorization, CredentialConfiguration,
    CredentialDefinition, FormatProfile,
};

use super::{Issuance, Status};
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
    pub claims: Option<HashMap<String, ClaimEntry>>,
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

    issuance.accepted =
        match narrow_scope(&issuance.issuer.credential_configurations_supported, &request.accept) {
            Ok(accepted) => accepted,
            Err(e) => {
                tracing::error!(target: "Endpoint::accept", ?e);
                return Err(e);
            }
        };

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

fn narrow_scope(
    offered: &HashMap<String, CredentialConfiguration>, accept: &Option<Vec<AuthorizationSpec>>,
) -> anyhow::Result<Option<Vec<AuthorizationDetail>>> {
    // Just return None if the holder wants all credential configurations.
    let Some(accept) = accept.clone() else {
        return Ok(None);
    };
    let mut auth_details = Vec::new();
    for auth_spec in accept {
        let format_profile: Option<FormatProfile> = match auth_spec.claims {
            Some(claims) => {
                let Some(offered_config) = offered.get(&auth_spec.credential_configuration_id)
                else {
                    return Err(anyhow!("credential configuration accepted not found in offer"));
                };
                let profile = match &offered_config.profile {
                    FormatProfile::W3c {
                        credential_definition,
                    } => FormatProfile::W3c {
                        credential_definition: CredentialDefinition {
                            context: credential_definition.context.clone(),
                            type_: credential_definition.type_.clone(),
                            credential_subject: Some(claims),
                        },
                    },
                    FormatProfile::IsoMdl { doctype, .. } => FormatProfile::IsoMdl {
                        doctype: doctype.clone(),
                        claims: Some(claims),
                    },
                    FormatProfile::SdJwt { vct, .. } => FormatProfile::SdJwt {
                        vct: vct.clone(),
                        claims: Some(claims),
                    },
                };
                Some(profile)
            }
            None => None,
        };

        // TODO: Support CredentialAuthorization::Format
        let detail = AuthorizationDetail {
            credential: CredentialAuthorization::ConfigurationId {
                credential_configuration_id: auth_spec.credential_configuration_id,
                claims: format_profile,
            },
            ..Default::default()
        };
        auth_details.push(detail);
    }

    Ok(Some(auth_details))
}
