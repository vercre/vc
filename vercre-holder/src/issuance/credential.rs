//! # Get Credentials Endpoint
//!
//! Get an access token and then use that to get the credential on offer.

use anyhow::{anyhow, bail};
use tracing::instrument;
use vercre_core_utils::Kind;
use vercre_datasec::jose::jws::{self, Type};
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialType, GrantType,
    Proof, ProofClaims, ProofType, TokenRequest,
};
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, HolderProvider, IssuerClient, StateManager, Verifier};

/// Progresses the issuance flow by getting an access token then using that to get the
/// credentials contained in the offer.
#[instrument(level = "debug", skip(provider))]
pub async fn get_credentials(provider: impl HolderProvider, request: String) -> anyhow::Result<Status> {
    tracing::debug!("Endpoint::get_credentials");

    let mut issuance = match super::get_issuance(provider.clone(), &request).await {
        Ok(issuance) => issuance,
        Err(e) => {
            tracing::error!(target: "Endpoint::get_credentials", ?e);
            return Err(e);
        }
    };

    // Request an access token from the issuer.
    let token_request = token_request(&issuance);
    issuance.token = match IssuerClient::get_token(&provider, &issuance.id, &token_request).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(target: "Endpoint::get_credentials", ?e);
            return Err(e);
        }
    };

    // Request each credential offered.
    // TODO: concurrent requests. Would that be possible if wallet is WASM/WASI?
    for (id, cfg) in &issuance.offered {
        // Construct a proof to be used in credential requests.
        let claims = ProofClaims {
            iss: Some(issuance.client_id.clone()),
            aud: issuance.offer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: issuance.token.c_nonce.clone(),
        };
        let jwt = match jws::encode(Type::Proof, &claims, provider.clone()).await {
            Ok(jwt) => jwt,
            Err(e) => {
                tracing::error!(target: "Endpoint::get_credentials", ?e);
                return Err(e);
            }
        };
        let proof = Proof {
            proof_type: "jwt".into(),
            proof: ProofType::Jwt(jwt),
        };

        let request = credential_request(&issuance, id, cfg, &proof);

        let cred_res = match IssuerClient::get_credential(&provider, &issuance.id, &request).await {
            Ok(cred_res) => cred_res,
            Err(e) => {
                tracing::error!(target: "Endpoint::get_credentials", ?e);
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
                tracing::error!(target: "Endpoint::get_credentials", ?e);
                return Err(e);
            }
        };

        // Base64-encoded logo if possible.
        if let Some(display) = &cfg.display {
            // TODO: Locale?
            if let Some(logo_info) = &display[0].logo {
                if let Some(uri) = &logo_info.uri {
                    if let Ok(logo) = IssuerClient::get_logo(&provider, &issuance.id, uri).await {
                        credential.logo = Some(logo);
                    }
                }
            }
        }
        match CredentialStorer::save(&provider, &credential).await {
            Ok(()) => (),
            Err(e) => {
                tracing::error!(target: "Endpoint::get_credentials", ?e);
                return Err(e);
            }
        };
    }

    // Release issuance state.
    StateManager::purge(&provider, &issuance.id).await?;

    Ok(Status::Requested)
}

/// Construct a token request.
fn token_request(issuance: &Issuance) -> TokenRequest {
    // Get pre-authorized code. Unwraps are OK since verification should be called on outer endpoint
    // to check existence.
    let grants = issuance.offer.grants.as_ref().expect("grants exist on offer");
    let pre_auth_code =
        grants.pre_authorized_code.as_ref().expect("pre-authorized code exists on offer");

    TokenRequest {
        credential_issuer: issuance.offer.credential_issuer.clone(),
        client_id: issuance.client_id.clone(),
        grant_type: GrantType::PreAuthorizedCode,
        pre_authorized_code: Some(pre_auth_code.pre_authorized_code.clone()),
        user_code: issuance.pin.clone(),
        ..Default::default()
    }
}

/// Construct a credential request from an offered credential configuration.
fn credential_request(
    issuance: &Issuance, _id: &str, cfg: &CredentialConfiguration, proof: &Proof,
) -> CredentialRequest {
    CredentialRequest {
        credential_issuer: issuance.offer.credential_issuer.clone(),
        access_token: issuance.token.access_token.clone(),
        credential_type: CredentialType::Format(cfg.format.clone()),
        credential_definition: Some(cfg.credential_definition.clone()),
        proof: Some(proof.clone()),
        credential_response_encryption: None,
    }
}

/// Construct a credential from a credential response.
async fn credential(
    credential_configuration: &CredentialConfiguration, res: &CredentialResponse,
    verifier: &impl Verifier,
) -> anyhow::Result<Credential> {
    let Some(value) = res.credential.as_ref() else {
        bail!("no credential in response");
    };

    let Payload::Vc(vc) = vercre_w3c_vc::proof::verify(Verify::Vc(value), verifier)
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
    let Kind::String(token) = value else {
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
