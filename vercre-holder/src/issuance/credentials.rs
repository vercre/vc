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
use vercre_issuer::{
    CredentialAuthorization, CredentialIssuance, Format, SingleProof, TokenResponse,
};
use vercre_macros::credential_request;
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialResponseType,
    Issuer as IssuerMetadata, Proof, ProofClaims,
};
use vercre_w3c_vc::model::VerifiableCredential;
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{CredentialRequestType, IssuanceState, Status};
use crate::credential::Credential;
use crate::issuance::FlowType;
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

    let mut issuance: IssuanceState =
        StateStore::get(&provider, &request.issuance_id).await.map_err(|e| {
            tracing::error!(target: "Endpoint::credentials", ?e);
            e
        })?;
    if issuance.status != Status::TokenReceived {
        let e = anyhow!("invalid issuance state");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    }
    let Some(token_response) = &issuance.token else {
        let e = anyhow!("no token response in issuance state");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    };
    let Some(issuer) = &issuance.issuer else {
        let e = anyhow!("no issuer metadata in issuance state");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    };

    // Construct a proof to be used in the credential requests.
    let claims = ProofClaims {
        iss: Some(issuance.client_id.clone()),
        aud: issuer.credential_issuer.clone(),
        iat: chrono::Utc::now().timestamp(),
        nonce: token_response.c_nonce.clone(),
    };
    let jwt = jws::encode(Type::Openid4VciProofJwt, &claims, &provider).await.map_err(|e| {
        tracing::error!(target: "Endpoint::credentials", ?e);
        e
    })?;

    // If the flow is scope-based then we can't examine authorization details
    // but proceed instead to request credentials by format.
    let scope = match issuance.flow_type.clone() {
        FlowType::HolderInitiated { scope, .. } => scope,
        _ => None,
    };
    if scope.is_some() {
        credential_by_format(provider.clone(), &mut issuance, scope.as_deref(), request, &jwt)
            .await
            .map_err(|e| {
                tracing::error!(target: "Endpoint::credentials", ?e);
                e
            })?;
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

    let deferred = if issuance.deferred_deprecated.is_empty() {
        None
    } else {
        Some(issuance.deferred_deprecated.clone())
    };

    Ok(CredentialsResponse {
        issuance_id: issuance.id,
        deferred,
    })
}

// Make a credential request by format based on the flow being by scope.
async fn credential_by_format(
    provider: impl HolderProvider, issuance: &mut IssuanceState, scope: Option<&str>,
    request: &CredentialsRequest, jwt: &str,
) -> anyhow::Result<()> {
    if request.credential_identifiers.is_some() {
        bail!("credential identifiers must be `None` for scope-based issuance");
    }
    let Some(format) = &request.format else {
        bail!("format must be provided for scope-based issuance");
    };
    let Some(issuer) = &issuance.issuer else {
        bail!("no issuer metadata in issuance state");
    };
    let config = issuer
        .credential_configurations_supported
        .iter()
        .find(|(_, cfg)| cfg.scope.as_deref() == scope && cfg.format == *format);
    let Some((cfg_id, config)) = config else {
        bail!("credential configuration not found for scope and format");
    };
    let Some(token_response) = &issuance.token else {
        bail!("no token response in issuance state");
    };
    let request = CredentialRequest {
        credential_issuer: issuer.credential_issuer.clone(),
        access_token: token_response.access_token.clone(),
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
    match process_credential_response(provider.clone(), config, &cred_res, issuer).await {
        Ok((credentials, transaction_id)) => {
            if let Some(credentials) = credentials {
                issuance.credentials.extend(credentials);
            }
            if let Some(id) = transaction_id {
                issuance.deferred_deprecated.insert(id, cfg_id.to_string());
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
    provider: impl HolderProvider, issuance: &mut IssuanceState, request: &CredentialsRequest,
    jwt: &str,
) -> anyhow::Result<()> {
    let Some(mut token_response) = issuance.token.clone() else {
        bail!("no token response in issuance state");
    };
    let Some(authorized) = &token_response.authorization_details else {
        bail!("no authorization details in token response");
    };
    let Some(issuer) = &issuance.issuer else {
        bail!("no issuer metadata in issuance state");
    };

    for auth in authorized {
        let cfg_id = match &auth.authorization_detail.credential {
            CredentialAuthorization::ConfigurationId {
                credential_configuration_id,
                ..
            } => credential_configuration_id,
            CredentialAuthorization::Format(format_identifier) => {
                match issuer.credential_configuration_id(format_identifier) {
                    Ok(cfg_id) => cfg_id,
                    Err(e) => {
                        tracing::error!(target: "Endpoint::credentials", ?e);
                        return Err(e);
                    }
                }
            }
        };
        let Some(config) = issuer.credential_configurations_supported.get(cfg_id) else {
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
                "credential_issuer": issuer.credential_issuer.clone(),
                "access_token": token_response.access_token.clone(),
                "credential_identifier": cred_id.to_string(),
                "proof": {
                    "proof_type": "jwt",
                    "jwt": jwt.to_string()
                }
            });
            let cred_res = Issuer::credential(&provider, request).await?;
            match process_credential_response(provider.clone(), config, &cred_res, issuer).await {
                Ok((credentials, transaction_id)) => {
                    if let Some(credentials) = credentials {
                        issuance.credentials.extend(credentials);
                    }
                    if let Some(id) = transaction_id {
                        issuance.deferred_deprecated.insert(id, cfg_id.to_string());
                    }
                }
                Err(e) => {
                    return Err(e);
                }
            };
            if cred_res.c_nonce.is_some() {
                token_response.c_nonce.clone_from(&cred_res.c_nonce);
                issuance.token = Some(token_response.clone());
            }
            if cred_res.c_nonce_expires_in.is_some() {
                token_response.c_nonce_expires_in.clone_from(&cred_res.c_nonce_expires_in);
                issuance.token = Some(token_response.clone());
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
    issuer: &vercre_openid::issuer::Issuer,
) -> anyhow::Result<(Option<Vec<Credential>>, Option<String>)> {
    let mut credentials = Vec::new();
    match &resp.response {
        CredentialResponseType::Credential(vc_kind) => {
            let credential = credential(provider.clone(), config, vc_kind, issuer).await?;
            credentials.push(credential);
            Ok((Some(credentials), None))
        }
        CredentialResponseType::Credentials(creds) => {
            for vc_kind in creds {
                let credential = credential(provider.clone(), config, vc_kind, issuer).await?;
                credentials.push(credential);
            }
            Ok((Some(credentials), None))
        }
        CredentialResponseType::TransactionId(id) => Ok((None, Some(id.clone()))),
    }
}

/// Construct a wallet-style credential from the format provided by the issuer.
async fn credential(
    provider: impl HolderProvider, config: &CredentialConfiguration,
    vc_kind: &Kind<VerifiableCredential>, issuer: &vercre_openid::issuer::Issuer,
) -> anyhow::Result<Credential> {
    let Payload::Vc { vc, issued_at } =
        vercre_w3c_vc::proof::verify(Verify::Vc(vc_kind), provider.clone())
            .await
            .map_err(|e| anyhow!("issue parsing credential: {e}"))?
    else {
        bail!("expected VerifiableCredential");
    };
    let Some(issuance_date) = DateTime::from_timestamp(issued_at, 0) else {
        bail!("invalid issuance date");
    };

    let issuer_id = issuer.credential_issuer.clone();
    // TODO: Locale support.
    let issuer_name = {
        if let Some(display) = issuer.display.clone() {
            display.name
        } else {
            issuer_id.clone()
        }
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

    // Turn a Quota of credential subjects into a Vec of claim sets.
    let mut subject_claims = Vec::new();
    match vc.credential_subject {
        Quota::One(cs) => subject_claims.push(cs.into()),
        Quota::Many(vc_claims) => {
            for cs in vc_claims {
                subject_claims.push(cs.into());
            }
        }
    }

    let mut storable_credential = Credential {
        id: vc.id.clone().unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        issuer: issuer_id.clone(),
        issuer_name,
        type_,
        format: config.format.to_string(),
        subject_claims,
        claim_definitions: config.format.claims(),
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
                if let Ok(logo) = Issuer::image(provider.clone(), uri).await {
                    storable_credential.logo = Some(logo);
                }
            }
        }
        if let Some(background_info) = &display[0].background_image {
            if let Some(uri) = &background_info.uri {
                if let Ok(background) = Issuer::image(provider.clone(), uri).await {
                    storable_credential.background = Some(background);
                }
            }
        }
    }

    Ok(storable_credential)
}

impl IssuanceState {
    /// Construct a proof to be used in the credential requests.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with constructing
    /// credential requests.
    pub fn proof(&self) -> anyhow::Result<ProofClaims> {
        let Some(token_response) = &self.token else {
            bail!("no token response in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };
        let claims = ProofClaims {
            iss: Some(self.client_id.clone()),
            aud: issuer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: token_response.c_nonce.clone(),
        };
        Ok(claims)
    }

    /// Construct a set of credential requests from authorization details and
    /// specified scope.
    ///
    /// The tuple contains the credential configuration ID for ease of lookup in
    /// issuer metadata as well as the credential request itself.
    ///
    /// # Errors
    /// Will return an error if the flow state is inconsistent with constructing
    /// credential requests.
    pub fn credential_requests(
        &self, request_type: CredentialRequestType, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        if self.status != Status::TokenReceived {
            bail!("invalid issuance state status");
        }
        let Some(token_response) = &self.token else {
            bail!("no token response in issuance state");
        };
        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };

        // Shell out to a scope or identifier based request builder.
        match request_type {
            CredentialRequestType::Format(format) => {
                let Some(scope) = (match self.flow_type.clone() {
                    FlowType::HolderInitiated { scope, .. } => scope,
                    _ => {
                        bail!("can only make format-based requests for holder-initiated, scope-based issuance");
                    }
                }) else {
                    bail!("issuance is holder-initiated but has no scope");
                };

                Self::credential_requests_by_format(&format, &scope, issuer, token_response, jwt)
            }
            CredentialRequestType::CredentialIdentifiers(identifiers) => {
                Self::credential_requests_by_identifier(&identifiers, issuer, token_response, jwt)
            }
        }
    }

    /// Construct a set of credential requests by format.
    ///
    /// # Errors
    /// Will return an error if the issuer metadata contains no credential
    /// configuration with the specified format and scope.
    fn credential_requests_by_format(
        format: &Format, scope: &str, issuer: &IssuerMetadata, token: &TokenResponse, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        let config = issuer
            .credential_configurations_supported
            .iter()
            .find(|(_, cfg)| cfg.scope.as_deref() == Some(scope) && cfg.format == *format);
        let Some((cfg_id, config)) = config else {
            bail!("credential configuration not found for scope and format");
        };
        let request = CredentialRequest {
            credential_issuer: issuer.credential_issuer.clone(),
            access_token: token.access_token.clone(),
            credential: CredentialIssuance::Format(config.format.clone()),
            proof: Some(Proof::Single {
                proof_type: SingleProof::Jwt { jwt: jwt.into() },
            }),
            ..Default::default()
        };
        Ok(vec![(cfg_id.to_string(), request)])
    }

    /// Construct a set of credential requests by credential identifier.
    ///
    /// # Errors
    /// Will return an error if the issuer metadata does not contain one of the
    /// requested credential identifiers or if the authorization details are
    /// inconsistent with issuer metadata.
    fn credential_requests_by_identifier(
        identifiers: &[String], issuer: &IssuerMetadata, token: &TokenResponse, jwt: &str,
    ) -> anyhow::Result<Vec<(String, CredentialRequest)>> {
        let Some(authorized) = &token.authorization_details else {
            bail!("no authorization details in token response");
        };
        let mut requests = Vec::new();
        for auth in authorized {
            let cfg_id = match &auth.authorization_detail.credential {
                CredentialAuthorization::ConfigurationId {
                    credential_configuration_id,
                    ..
                } => credential_configuration_id,
                CredentialAuthorization::Format(format_identifier) => {
                    match issuer.credential_configuration_id(format_identifier) {
                        Ok(cfg_id) => cfg_id,
                        Err(e) => {
                            tracing::error!(target: "Endpoint::credentials", ?e);
                            return Err(e);
                        }
                    }
                }
            };
            // Check the issuer supports this credential configuration. This will only fail if the
            // wallet has messed with state outside of the intended mutation methods.
            let Some(_) = issuer.credential_configurations_supported.get(cfg_id) else {
                bail!("authorized credential configuration not found in issuer metadata");
            };
            for cred_id in &auth.credential_identifiers {
                // Check the holder wants this credential.
                if !identifiers.to_vec().contains(cred_id) {
                    continue;
                }
                let request = credential_request!({
                    "credential_issuer": issuer.credential_issuer.clone(),
                    "access_token": token.access_token.clone(),
                    "credential_identifier": cred_id.to_string(),
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": jwt.to_string()
                    }
                });
                requests.push((cfg_id.to_string(), request));
            }
        }
        Ok(requests)
    }

    /// Add a deferred transaction ID to the issuance state.
    pub fn add_deferred(&mut self, id: &String) {
        self.deferred.push(id.into());
    }

    /// Add a credential to the issuance state, converting the W3C format to a
    /// convenient wallet format.
    ///
    /// # Errors
    /// Will return an error if the current state does not contain the metadata
    /// required to combine with the provided VC.
    pub fn add_credential(
        &mut self, vc: &VerifiableCredential, encoded: &Kind<VerifiableCredential>,
        issued_at: &i64, config_id: &str,
    ) -> anyhow::Result<()> {
        let Some(issuance_date) = DateTime::from_timestamp(*issued_at, 0) else {
            bail!("invalid issuance date");
        };

        let Some(issuer) = &self.issuer else {
            bail!("no issuer metadata in issuance state");
        };
        let issuer_id = issuer.credential_issuer.clone();

        // TODO: Locale support.
        let issuer_name = {
            if let Some(display) = issuer.display.clone() {
                display.name
            } else {
                issuer_id.clone()
            }
        };

        let Some(config) = issuer.credential_configurations_supported.get(config_id) else {
            bail!("credential configuration not found in issuer metadata");
        };

        // TODO: add support for embedded proof
        let Kind::String(token) = encoded else {
            bail!("credential is not a JWT");
        };

        // Turn a Quota of Strings into a Vec of Strings for the type of credential.
        let mut type_ = Vec::new();
        match &vc.type_ {
            Quota::One(t) => type_.push(t.clone()),
            Quota::Many(vc_types) => type_.extend(vc_types.clone()),
        }

        // Turn a Quota of credential subjects into a Vec of claim sets.
        let mut subject_claims = Vec::new();
        match vc.credential_subject.clone() {
            Quota::One(cs) => subject_claims.push(cs.into()),
            Quota::Many(vc_claims) => {
                for cs in vc_claims {
                    subject_claims.push(cs.into());
                }
            }
        }

        let storable_credential = Credential {
            id: vc.id.clone().unwrap_or_else(|| format!("urn:uuid:{}", uuid::Uuid::new_v4())),
            issuer: issuer_id,
            issuer_name,
            type_,
            format: config.format.to_string(),
            subject_claims,
            claim_definitions: config.format.claims(),
            issued: token.into(),
            issuance_date,
            valid_from: vc.valid_from,
            valid_until: vc.valid_until,
            display: config.display.clone(),
            logo: None,
            background: None,
        };

        self.credentials.push(storable_credential);
        Ok(())
    }
}
