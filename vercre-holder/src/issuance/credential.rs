//! # Get Credentials Endpoint
//!
//! Get an access token and then use that to get the credential on offer.

use anyhow::{anyhow, bail};
use tracing::instrument;
use vercre_core::{Kind, Quota};
use vercre_datasec::jose::jws::{self, Type};
use vercre_openid::issuer::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, CredentialSpec, Proof,
    ProofClaims, SingleProof, TokenGrantType, TokenRequest,
};
use vercre_w3c_vc::proof::{Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, DidResolver, HolderProvider, Issuer, StateStore};

/// Progresses the issuance flow by getting an access token then using that to get the
/// credentials contained in the offer.
#[instrument(level = "debug", skip(provider))]
pub async fn get_credentials(
    provider: impl HolderProvider, request: String,
) -> anyhow::Result<Status> {
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
    issuance.token = match Issuer::get_token(&provider, &issuance.id, &token_request).await {
        Ok(token) => token,
        Err(e) => {
            tracing::error!(target: "Endpoint::get_credentials", ?e);
            return Err(e);
        }
    };

    let Some(authorized) = &issuance.token.authorization_details else {
        bail!("no authorization details in token response");
    };
    let auth = authorized[0].clone();

    // Request each credential offered.
    // TODO: concurrent requests. Would that be possible if wallet is WASM/WASI?
    for cfg in issuance.offered.values() {
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
        let proof = Proof::Single {
            proof_type: SingleProof::Jwt { jwt },
        };

        let request = CredentialRequest {
            credential_issuer: issuance.offer.credential_issuer.clone(),
            access_token: issuance.token.access_token.clone(),
            specification: CredentialSpec::Identifier {
                credential_identifier: auth.credential_identifiers[0].clone(),
            },
            proof: Some(proof.clone()),
            credential_response_encryption: None,
        };

        let cred_res = match Issuer::get_credential(&provider, &issuance.id, &request).await {
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
                    if let Ok(logo) = Issuer::get_logo(&provider, &issuance.id, uri).await {
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
    StateStore::purge(&provider, &issuance.id).await?;

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
        client_id: Some(issuance.client_id.clone()),
        grant_type: TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_code.pre_authorized_code.clone(),
            tx_code: issuance.pin.clone(),
        },
        ..TokenRequest::default()
    }
}

/// Construct a credential from a credential response.
async fn credential(
    credential_configuration: &CredentialConfiguration, resp: &CredentialResponse,
    resolver: &impl DidResolver,
) -> anyhow::Result<Credential> {
    let vc_quota = resp.credential.as_ref().expect("no credential in response");
    let vc_kind = match vc_quota {
        Quota::One(vc_kind) => vc_kind,
        Quota::Many(_) => bail!("expected one credential"),
    };

    // TODO: support multiple credentials in response

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
