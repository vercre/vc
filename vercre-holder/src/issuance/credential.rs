//! # Get Credentials Endpoint
//!
//! Get an access token and then use that to get the credential on offer.

use std::fmt::Debug;

use anyhow::bail;
use core_utils::jws::{self, Type};
use openid4vc::issuance::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, GrantType, Proof, ProofClaims,
    TokenRequest,
};
use tracing::instrument;
use vercre_vc::model::StrObj;
use vercre_vc::proof::{self, Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{CredentialStorer, IssuerClient, Signer, StateManager, Verifier};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: CredentialStorer + IssuerClient + Signer + Verifier + StateManager + Clone + Debug,
{
    /// Progresses the issuance flow by getting an access token then using that to get the
    /// credentials contained in the offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn get_credentials(&self, request: String) -> anyhow::Result<()> {
        tracing::debug!("Endpoint::get_credentials");

        let mut issuance = match self.get_issuance(&request).await {
            Ok(issuance) => issuance,
            Err(e) => {
                tracing::error!(target: "Endpoint::get_credentials", ?e);
                return Err(e);
            }
        };

        // Request an access token from the issuer.
        let token_request = token_request(&issuance);
        issuance.token = match self.provider.get_token(&issuance.id, &token_request).await {
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
            let jwt = match jws::encode(Type::Proof, &claims, self.provider.clone()).await {
                Ok(jwt) => jwt,
                Err(e) => {
                    tracing::error!(target: "Endpoint::get_credentials", ?e);
                    return Err(e);
                }
            };
            let proof = Proof {
                proof_type: "jwt".into(),
                jwt: Some(jwt),
                cwt: None,
            };

            let request = credential_request(&issuance, id, cfg, &proof);
            issuance.status = Status::Requested;

            let cred_res = match self.provider.get_credential(&issuance.id, &request).await {
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
            let mut credential = match credential(cfg, &cred_res, &self.provider).await {
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
                        if let Ok(logo) = self.provider.get_logo(&issuance.id, uri).await {
                            credential.logo = Some(logo);
                        }
                    }
                }
            }
            match self.provider.save(&credential).await {
                Ok(()) => (),
                Err(e) => {
                    tracing::error!(target: "Endpoint::get_credentials", ?e);
                    return Err(e);
                }
            };
        }

        Ok(())
    }
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
        format: Some(cfg.format.clone()),
        proof: Some(proof.clone()),
        // credential_identifier: Some(id.into()),
        credential_identifier: None,
        credential_definition: Some(cfg.credential_definition.clone()),
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
    let Some(token) = value.as_str() else {
        bail!("credential is not a string");
    };
    let Ok(Payload::Vc(vc)) = proof::verify(token, Verify::Vc, verifier).await else {
        bail!("could not parse credential");
    };

    let issuer_id = match &vc.issuer {
        StrObj::String(id) => id,
        StrObj::Object(issuer) => &issuer.id,
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
