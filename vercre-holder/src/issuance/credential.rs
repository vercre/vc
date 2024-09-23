//! # Credentials Endpoint
//!
//! Use an access token to get the credentials accepted by the holder.

use anyhow::{anyhow, bail};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_core::Kind;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::CredentialAuthorization;
use vercre_macros::credential_request;
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialResponse, CredentialResponseType, ProofClaims,
};
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, DidResolver, HolderProvider, Issuer, StateStore};

/// `CredentialsRequest` provides the issuance flow ID and an optional set of
/// credential identifiers to the `credentials` endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CredentialsRequest {
    /// The issuance flow identifier.
    pub issuance_id: String,
    /// The credential identifiers to request.
    ///
    /// None implies the holder wants all credentials authorized by the token.
    pub credential_identifiers: Option<Vec<String>>,
}

/// Progresses the issuance flow by requesting the credentials from the issuer.
///
/// Returns the issuance flow identifier.
#[instrument(level = "debug", skip(provider))]
pub async fn credentials(
    provider: impl HolderProvider, request: &CredentialsRequest,
) -> anyhow::Result<String> {
    tracing::debug!("Endpoint::credentials");

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
    let Some(authorized) = &issuance.token.authorization_details else {
        let e = anyhow!("no authorization details in token response");
        tracing::error!(target: "Endpoint::credentials", ?e);
        return Err(e);
    };

    // Request each credential accepted. This will be reflected back to us in
    // the token response so we don't need to re-construct from state.
    // TODO: Is it possible/desirable to do concurrent requests?
    for auth in authorized {
        let cfg_id = match &auth.authorization_detail.credential {
            CredentialAuthorization::ConfigurationId {
                credential_configuration_id,
                ..
            } => credential_configuration_id,
            CredentialAuthorization::Format(_) => {
                // TODO: Implement this
                let e = anyhow!("unsupported credential configuration format");
                tracing::error!(target: "Endpoint::credentials", ?e);
                return Err(e);
            }
        };
        let Some(cfg) = issuance.offered.get(cfg_id) else {
            let e = anyhow!("authorized credential configuration not found in offer");
            tracing::error!(target: "Endpoint::credentials", ?e);
            return Err(e);
        };

        // Construct a proof to be used in the credential request.
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

        for cred_id in &auth.credential_identifiers {
            // Check the holder wants this credential.
            if let Some(ref ids) = request.credential_identifiers {
                if !ids.contains(cred_id) {
                    continue;
                }
            }

            // Construct a credential request.
            let request = credential_request!({
                "credential_issuer": issuance.offer.credential_issuer.clone(),
                "access_token": issuance.token.access_token.clone(),
                "credential_identifier": cred_id.clone(),
                "proof": {
                    "proof_type": "jwt",
                    "jwt": jwt.clone()
                }
            });

            let cred_res = match Issuer::get_credential(&provider, &issuance.id, request).await {
                Ok(cred_res) => cred_res,
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

            // Create a credential in a useful wallet format.
            let mut credential = match credential(cfg, &cred_res, &provider).await {
                Ok(credential) => credential,
                Err(e) => {
                    tracing::error!(target: "Endpoint::credentials", ?e);
                    return Err(e);
                }
            };

            // Base64-encoded logo if possible.
            if let Some(display) = &cfg.display {
                // TODO: Locale?
                if let Some(logo_info) = &display[0].logo {
                    if let Some(uri) = &logo_info.uri {
                        if let Ok(logo) = Issuer::get_logo(&provider, &issuance.id, uri).await {
                            credential.logo = Some(logo);
                        }
                    }
                }
            }
            match CredentialStorer::save(&provider, &credential).await {
                Ok(()) => (),
                Err(e) => {
                    tracing::error!(target: "Endpoint::credentials", ?e);
                    return Err(e);
                }
            };
        }
    }

    // Release issuance state.
    StateStore::purge(&provider, &issuance.id).await?;

    Ok(issuance.id)
}

/// Construct a credential from a credential response.
async fn credential(
    credential_configuration: &CredentialConfiguration, resp: &CredentialResponse,
    resolver: &impl DidResolver,
) -> anyhow::Result<Credential> {
    // TODO: Handle response types other than single credential.
    let vc_kind = match &resp.response {
        CredentialResponseType::Credential(vc_kind) => vc_kind,
        CredentialResponseType::Credentials(_) | CredentialResponseType::TransactionId(_) => {
            bail!("expected credential in response");
        }
    };

    let Payload::Vc(vc) = vercre_w3c_vc::proof::verify(Verify::Vc(vc_kind), resolver)
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

    Ok(Credential {
        id: vc.id.clone(),
        issuer: issuer_id.clone(),
        metadata: credential_configuration.clone(),
        vc,
        issued: token.into(),

        ..Credential::default()
    })
}
