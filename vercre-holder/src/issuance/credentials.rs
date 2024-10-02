//! # Credentials Endpoint
//!
//! Use an access token to get the credentials accepted by the holder.

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_core::Kind;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::{CredentialAuthorization, CredentialIssuance, FormatIdentifier, SingleProof};
use vercre_macros::credential_request;
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialResponseType, Proof,
    ProofClaims,
};
use vercre_w3c_vc::model::VerifiableCredential;
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, HolderProvider, Issuer, StateStore};

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
    pub format: Option<FormatIdentifier>,
}

/// `CredentialsResponse` provides the issuance flow ID and any deferred
/// transactions IDs returned by the issuer's credential issuance endpoint.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct CredentialsResponse {
    /// Issuance flow identifier.
    pub issuance_id: String,

    /// Deferred transaction IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deferred: Option<Vec<String>>,
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

    let mut issuance: Issuance = match StateStore::get(&provider, &request.issuance_id).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
    };
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
    let jwt = match jws::encode(Type::Proof, &claims, provider.clone()).await {
        Ok(jwt) => jwt,
        Err(e) => {
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
    };

    let mut deferred = Vec::new();

    // If the flow is scope-based then we can't examine authorization details
    // but proceed instead to request credentials by format.
    if issuance.scope.is_some() {
        if request.credential_identifiers.is_some() {
            let e = anyhow!("credential identifiers must be `None` for scope-based issuance");
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        }
        let Some(format) = &request.format else {
            let e = anyhow!("format must be provided for scope-based issuance");
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        };
        match get_credentials_by_format(provider.clone(), &issuance, format, &jwt).await {
            Ok(cred_res) => {
                if let CredentialResponseType::TransactionId(id) = &cred_res.response {
                    deferred.push(id.to_string());
                }
                cred_res
            }
            Err(e) => {
                tracing::error!(target: "Endpoint::credentials", ?e);
                return Err(e);
            }
        };
    }
    // Otherwise the flow is definition or format based and we make a request
    // for each authorized credential identifier.
    else {
        let Some(authorized) = &issuance.token.authorization_details else {
            let e = anyhow!("no authorization details in token response");
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
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
            let Some(cfg) = issuance.issuer.credential_configurations_supported.get(cfg_id) else {
                let e = anyhow!("authorized credential configuration not found in issuer metadata");
                tracing::error!(target: "Endpoint::credentials", ?e);
                return Err(e);
            };
            for cred_id in &auth.credential_identifiers {
                // Check the holder wants this credential.
                if let Some(ref ids) = request.credential_identifiers {
                    if !ids.contains(cred_id) {
                        continue;
                    }
                }

                let cred_res = match get_credential_by_identifier(
                    provider.clone(),
                    &issuance,
                    cfg,
                    cred_id,
                    &jwt,
                )
                .await
                {
                    Ok(cred_res) => {
                        if let CredentialResponseType::TransactionId(id) = &cred_res.response {
                            deferred.push(id.to_string());
                        }
                        cred_res
                    }
                    Err(e) => {
                        tracing::error!(target: "Endpoint::credentials", ?e);
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
    }
    // Release issuance state if no deferred transactions.
    let deferred = if deferred.is_empty() {
        StateStore::purge(&provider, &issuance.id).await?;
        None
    } else {
        Some(deferred)
    };

    Ok(CredentialsResponse {
        issuance_id: issuance.id,
        deferred,
    })
}

/// Process the credential response.
///
/// Unpacks the response and, if one or more credentials are present will
/// convert into a convenient wallet format and use the provider to store.
/// If a deferred transaction ID has been returned, this will be immediately
/// returned instead.
async fn process_credential_response(
    provider: impl HolderProvider, config: &CredentialConfiguration, resp: &CredentialResponse,
) -> anyhow::Result<Option<String>> {
    match &resp.response {
        CredentialResponseType::Credential(vc_kind) => {
            // Create a credential in a useful wallet format and save.
            let credential = credential(&provider, config, vc_kind).await?;
            CredentialStorer::save(&provider, &credential).await?;
            Ok(None)
        }
        CredentialResponseType::Credentials(credentials) => {
            for vc_kind in credentials {
                let credential = credential(&provider, config, vc_kind).await?;
                CredentialStorer::save(&provider, &credential).await?;
            }
            Ok(None)
        }
        CredentialResponseType::TransactionId(id) => Ok(Some(id.clone())),
    }
}

/// Get credentials by format.
async fn get_credentials_by_format(
    provider: impl HolderProvider, issuance: &Issuance, format: &FormatIdentifier, jwt: &str,
) -> anyhow::Result<CredentialResponse> {
    let config = issuance
        .issuer
        .credential_configurations_supported
        .iter()
        .find(|(_, cfg)| cfg.scope == issuance.scope && cfg.format == *format);
    let Some((_cfg_id, config)) = config else {
        let e = anyhow!("credential configuration not found for scope and format");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    };

    let request = CredentialRequest {
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        access_token: issuance.token.access_token.clone(),
        credential: CredentialIssuance::Format(format.clone()),
        proof: Some(Proof::Single {
            proof_type: SingleProof::Jwt { jwt: jwt.into() },
        }),
        ..Default::default()
    };
    let cred_res = Issuer::credential(&provider, request).await?;
    process_credential_response(provider, config, &cred_res).await?;
    Ok(cred_res)
}

/// Get a credential by credential identifier.
async fn get_credential_by_identifier(
    provider: impl HolderProvider, issuance: &Issuance, config: &CredentialConfiguration,
    cred_id: &str, jwt: &str,
) -> anyhow::Result<CredentialResponse> {
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
    process_credential_response(provider, config, &cred_res).await?;
    Ok(cred_res)
}

/// Construct a credential from a credential response.
async fn credential(
    provider: &impl HolderProvider, config: &CredentialConfiguration,
    vc_kind: &Kind<VerifiableCredential>,
) -> anyhow::Result<Credential> {
    let Payload::Vc(vc) = vercre_w3c_vc::proof::verify(Verify::Vc(vc_kind), provider)
        .await
        .map_err(|e| anyhow!("issue parsing credential: {e}"))?
    else {
        bail!("expected VerifiableCredential");
    };

    let issuer_id = match &vc.issuer {
        Kind::String(id) => id,
        Kind::Object(issuer) => &issuer.id,
    };

    // TODO: add support embedded proof
    let Kind::String(token) = vc_kind else {
        bail!("credential is not a JWT");
    };

    let mut storable_credential = Credential {
        id: vc.id.clone(),
        issuer: issuer_id.clone(),
        metadata: config.clone(),
        vc: vc.clone(),
        issued: token.into(),

        ..Credential::default()
    };

    // Base64-encoded logo if possible.
    if let Some(display) = &config.display {
        // TODO: Locale?
        if let Some(logo_info) = &display[0].logo {
            if let Some(uri) = &logo_info.uri {
                if let Ok(logo) = Issuer::logo(provider, uri).await {
                    storable_credential.logo = Some(logo);
                }
            }
        }
    }

    Ok(storable_credential)
}
