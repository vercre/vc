//! # Credentials Endpoint
//!
//! Use an access token to get the credentials accepted by the holder.

use std::collections::HashMap;

use anyhow::{anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_core::{Kind, Quota};
use vercre_infosec::jose::jws::{self, Type};
use vercre_issuer::{CredentialAuthorization, CredentialIssuance, Format, SingleProof};
use vercre_macros::credential_request;
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialResponseType, Proof,
    ProofClaims,
};
use vercre_w3c_vc::model::VerifiableCredential;
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{HolderProvider, Issuer, StateStore};

/// `CredentialsRequest` provides the issuance flow ID and an optional set of
/// credential identifiers to the `credentials` endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialsRequest {
    /// Issuance flow identifier.
    pub issuance_id: String,

    /// Credential identifiers to request.
    ///
    /// `None` implies the holder wants all credentials authorized by the token.
    /// Must be `None` if the issuance flow is scope-based.
    pub credential_identifiers: Option<Vec<String>>,

    /// Format of the credential.
    ///
    /// Must be provided if the issuance flow is scope-based, otherwise must be
    /// `None`.
    ///
    /// If provided, the format must be one supported by the issuer (as
    /// described in the issuer metadata).
    pub format: Option<Format>,
}

/// `CredentialsResponse` provides the issuance flow ID and any deferred
/// transactions IDs returned by the issuer's credential issuance endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialsResponse {
    /// Issuance flow identifier.
    pub issuance_id: String,

    /// Deferred transaction IDs (key) and corresponding credential
    /// configuration IDs (value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred: Option<HashMap<String, String>>,
}

/// Progresses the issuance flow by requesting the credentials from the issuer.
///
/// Returns the issuance flow identifier and any deferred transaction IDs.
///
/// # Errors
/// Will return an error if the request is invalid for the current state and
/// type of issuance flow, or if requesting the credentials fails.
#[instrument(level = "debug", skip(provider))]
pub async fn credentials(
    provider: impl HolderProvider, request: &CredentialsRequest,
) -> anyhow::Result<CredentialsResponse> {
    tracing::debug!("Endpoint::credentials {:?}", request);

    let mut issuance: Issuance =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::credentials", ?e);
            e
        })?;
    if issuance.status != Status::TokenReceived {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    }

    // Construct a proof to be used in the credential requests.
    let claims = ProofClaims {
        iss: Some(issuance.client_id.clone()),
        aud: issuance.offer.credential_issuer.clone(),
        iat: chrono::Utc::now().timestamp(),
        nonce: issuance.token.c_nonce.clone(),
    };
    let jwt = jws::encode(Type::Openid4VciProofJwt, &claims, &provider).await.map_err(|e| {
        tracing::error!(target: "Endpoint::credentials", ?e);
        e
    })?;

    // If the flow is scope-based then we can't examine authorization details
    // but proceed instead to request credentials by format.
    if issuance.scope.is_some() {
        credential_by_format(provider.clone(), &mut issuance, request, &jwt).await.map_err(
            |e| {
                tracing::error!(target: "Endpoint::credentials", ?e);
                e
            },
        )?;
    }
    // Otherwise the flow is definition or format based and we make a request
    // for each authorized credential identifier.
    else {
        credential_by_identifier(provider.clone(), &mut issuance, request, &jwt).await.map_err(
            |e| {
                tracing::error!(target: "Endpoint::credentials", ?e);
                e
            },
        )?;
    }

    // Stash the state for the next step (save or cancel or deferred).
    if let Err(e) =
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

// Make a credential request by format based on the flow being by scope.
async fn credential_by_format(
    provider: impl HolderProvider, issuance: &mut Issuance, request: &CredentialsRequest, jwt: &str,
) -> anyhow::Result<()> {
    if request.credential_identifiers.is_some() {
        bail!("credential identifiers must be `None` for scope-based issuance");
    }
    let Some(format) = &request.format else {
        bail!("format must be provided for scope-based issuance");
    };
    let config = issuance
        .issuer
        .credential_configurations_supported
        .iter()
        .find(|(_, cfg)| cfg.scope == issuance.scope && cfg.format == *format);
    let Some((cfg_id, config)) = config else {
        bail!("credential configuration not found for scope and format");
    };
    let request = CredentialRequest {
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        access_token: issuance.token.access_token.clone(),
        credential: CredentialIssuance::Format(config.format.clone()),
        proof: Some(Proof::Single {
            proof_type: SingleProof::Jwt { jwt: jwt.into() },
        }),
        ..Default::default()
    };
    let cred_res = Issuer::credential(&provider, request).await.map_err(|e| {
        tracing::error!(target: "Endpoint::credentials", ?e);
        e
    })?;
    match process_credential_response(provider.clone(), config, &cred_res).await {
        Ok((credentials, transaction_id)) => {
            if let Some(credentials) = credentials {
                issuance.credentials.extend(credentials);
            }
            if let Some(id) = transaction_id {
                issuance.deferred.insert(id, cfg_id.to_string());
            }
        }
        Err(e) => {
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
    };
    Ok(())
}

// Make a credential request by identifier.
async fn credential_by_identifier(
    provider: impl HolderProvider, issuance: &mut Issuance, request: &CredentialsRequest, jwt: &str,
) -> anyhow::Result<()> {
    let Some(authorized) = &issuance.token.authorization_details else {
        bail!("no authorization details in token response");
    };

    for auth in authorized {
        let cfg_id = match &auth.authorization_detail.credential {
            CredentialAuthorization::ConfigurationId {
                credential_configuration_id,
                ..
            } => credential_configuration_id,
            CredentialAuthorization::Format(format_identifier) => {
                match issuance.issuer.credential_configuration_id(format_identifier) {
                    Ok(cfg_id) => cfg_id,
                    Err(e) => {
                        tracing::error!(target: "Endpoint::credentials", ?e);
                        return Err(e);
                    }
                }
            }
        };
        let Some(config) = issuance.issuer.credential_configurations_supported.get(cfg_id) else {
            bail!("authorized credential configuration not found in issuer metadata");
        };
        for cred_id in &auth.credential_identifiers {
            // Check the holder wants this credential.
            if let Some(ref ids) = request.credential_identifiers {
                if !ids.contains(cred_id) {
                    continue;
                }
            }
            let request = credential_request!({
                "credential_issuer": issuance.issuer.credential_issuer.clone(),
                "access_token": issuance.token.access_token.clone(),
                "credential_identifier": cred_id.to_string(),
                "proof": {
                    "proof_type": "jwt",
                    "jwt": jwt.to_string()
                }
            });
            let cred_res = Issuer::credential(&provider, request).await?;
            match process_credential_response(provider.clone(), config, &cred_res).await {
                Ok((credentials, transaction_id)) => {
                    if let Some(credentials) = credentials {
                        issuance.credentials.extend(credentials);
                    }
                    if let Some(id) = transaction_id {
                        issuance.deferred.insert(id, cfg_id.to_string());
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            };
            if cred_res.c_nonce.is_some() {
                issuance.token.c_nonce.clone_from(&cred_res.c_nonce);
            }
            if cred_res.c_nonce_expires_in.is_some() {
                issuance.token.c_nonce_expires_in.clone_from(&cred_res.c_nonce_expires_in);
            }
        }
    }
    Ok(())
}

/// Process the credential response.
///
/// Unpacks the response and, if one or more credentials are present will
/// convert into a convenient wallet format and use the provider to store.
/// If a deferred transaction ID has been returned, this will be immediately
/// returned instead.
pub async fn process_credential_response(
    provider: impl HolderProvider, config: &CredentialConfiguration, resp: &CredentialResponse,
) -> anyhow::Result<(Option<Vec<Credential>>, Option<String>)> {
    let mut credentials = Vec::new();
    match &resp.response {
        CredentialResponseType::Credential(vc_kind) => {
            // Create a credential in a useful wallet format and save.
            let credential = credential(&provider, config, vc_kind).await?;
            credentials.push(credential);
            Ok((Some(credentials), None))
        }
        CredentialResponseType::Credentials(creds) => {
            for vc_kind in creds {
                let credential = credential(&provider, config, vc_kind).await?;
                credentials.push(credential);
            }
            Ok((Some(credentials), None))
        }
        CredentialResponseType::TransactionId(id) => Ok((None, Some(id.clone()))),
    }
}

/// Construct a credential from a credential response.
async fn credential(
    provider: &impl HolderProvider, config: &CredentialConfiguration,
    vc_kind: &Kind<VerifiableCredential>,
) -> anyhow::Result<Credential> {
    let Payload::Vc { vc, issued_at } = vercre_w3c_vc::proof::verify(Verify::Vc(vc_kind), provider)
        .await
        .map_err(|e| anyhow!("issue parsing credential: {e}"))?
    else {
        bail!("expected VerifiableCredential");
    };
    let Some(issuance_date) = DateTime::from_timestamp(issued_at, 0) else {
        bail!("invalid issuance date");
    };

    let issuer_id = match &vc.issuer {
        Kind::String(id) => id,
        Kind::Object(issuer) => &issuer.id,
    };

    // TODO: add support for embedded proof
    let Kind::String(token) = vc_kind else {
        bail!("credential is not a JWT");
    };

    // Turn a Quota of Strings into a Vec of Strings for the type of credential.
    let mut type_ = Vec::new();
    match &vc.type_ {
        Quota::One(t) => type_.push(t.clone()),
        Quota::Many(vc_types) => type_.extend(vc_types.clone()),
    }

    // Turn a Quota of credential subjects into a Vec of credential subjects.
    let mut credential_subject = Vec::new();
    match &vc.credential_subject {
        Quota::One(cs) => credential_subject.push(cs.clone()),
        Quota::Many(vc_claims) => credential_subject.extend(vc_claims.clone()),
    }

    let mut storable_credential = Credential {
        id: vc.id.clone().unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        issuer: issuer_id.clone(),
        type_,
        format: config.format.to_string(),
        credential_subject,
        issued: token.into(),
        issuance_date,
        valid_from: vc.valid_from,
        valid_until: vc.valid_until,
        display: config.display.clone(),
        logo: None,
        background: None,
    };

    // Base64-encoded logo and background image if possible.
    if let Some(display) = &config.display {
        // TODO: Locale?
        if let Some(logo_info) = &display[0].logo {
            if let Some(uri) = &logo_info.uri {
                if let Ok(logo) = Issuer::image(provider, uri).await {
                    storable_credential.logo = Some(logo);
                }
            }
        }
        if let Some(background_info) = &display[0].background_image {
            if let Some(uri) = &background_info.uri {
                if let Ok(background) = Issuer::image(provider, uri).await {
                    storable_credential.background = Some(background);
                }
            }
        }
    }

    Ok(storable_credential)
}
