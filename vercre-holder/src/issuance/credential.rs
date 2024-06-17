//! # Get Credentials Endpoint
//!
//! Get an access token and then use that to get the credential on offer.

use std::fmt::Debug;

use core_utils::jws::{self, Type};
use openid4vc::error::Err;
use openid4vc::issuance::{
    CredentialConfiguration, CredentialRequest, CredentialResponse, GrantType, Proof, ProofClaims,
    TokenRequest,
};
use openid4vc::{err, Result};
use tracing::instrument;
use vercre_vc::proof::{self, Payload, Verify};

use super::{Issuance, Status};
use crate::credential::Credential;
use crate::provider::{Callback, CredentialStorer, IssuerClient, Signer, StateManager};
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: Callback + CredentialStorer + IssuerClient + Signer + StateManager + Clone + Debug,
{
    /// Progresses the issuance flow by getting an access token then using that to get the
    /// credentials contained in the offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn get_credentials(&self, request: String) -> Result<()> {
        let ctx = Context {
            issuance: Issuance::default(),
            _p: std::marker::PhantomData,
        };
        core_utils::Endpoint::handle_request(self, &request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    issuance: Issuance,
    _p: std::marker::PhantomData<P>,
}

impl<P> core_utils::Context for Context<P>
where
    P: CredentialStorer + IssuerClient + StateManager + Signer + Clone + Debug,
{
    type Provider = P;
    type Request = String;
    type Response = ();

    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        println!("verifying get_credentials request");

        // Get current state of flow and check internals for consistency with request.
        let current_state = provider.get(req).await?;
        let Ok(issuance) = serde_json::from_slice::<Issuance>(&current_state) else {
            err!(Err::InvalidRequest, "unable to decode issuance state");
        };

        if issuance.status != Status::Accepted {
            err!(Err::InvalidRequest, "Invalid issuance state");
        };

        println!("restored issuance from state {issuance:?}");

        self.issuance = issuance;
        Ok(self)
    }

    async fn process(&self, provider: &P, _req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        let mut issuance = self.issuance.clone();

        // Request an access token from the issuer.
        let token_request = token_request(&issuance);

        println!("requesting token {token_request:?}");

        issuance.token = provider.get_token(&issuance.id, &token_request).await?;

        println!("issance with token {issuance:?}");

        // Request each credential offered.
        // TODO: concurrent requests. Possible if wallet is WASM?
        for (id, cfg) in &issuance.offered {
            // Construct a proof to be used in credential requests.
            let claims = ProofClaims {
                iss: Some(issuance.client_id.clone()),
                aud: issuance.offer.credential_issuer.clone(),
                iat: chrono::Utc::now().timestamp(),
                nonce: issuance.token.c_nonce.clone(),
            };

            let jwt = jws::encode(Type::Proof, &claims, provider.clone()).await?;

            let proof = Proof {
                proof_type: "jwt".into(),
                jwt: Some(jwt),
                cwt: None,
            };

            let request = credential_request(&issuance, id, cfg, &proof);
            issuance.status = Status::Requested;
            let cred_res = provider.get_credential(&issuance.id, &request).await?;
            if cred_res.c_nonce.is_some() {
                issuance.token.c_nonce.clone_from(&cred_res.c_nonce);
            }
            if cred_res.c_nonce_expires_in.is_some() {
                issuance.token.c_nonce_expires_in.clone_from(&cred_res.c_nonce_expires_in);
            }

            // Create a credential in a useful wallet format.
            let mut credential = credential(&issuance, cfg, &cred_res).await?;

            // Base64-encoded logo if possible.
            if let Some(display) = &cfg.display {
                // TODO: Locale?
                if let Some(logo_info) = &display[0].logo {
                    if let Some(uri) = &logo_info.uri {
                        if let Ok(logo) = provider.get_logo(&issuance.id, uri).await {
                            credential.logo = Some(logo);
                        }
                    }
                }
            }
            provider.save(&credential).await?;
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
    issuance: &Issuance, id: &str, cfg: &CredentialConfiguration, proof: &Proof,
) -> CredentialRequest {
    CredentialRequest {
        credential_issuer: issuance.offer.credential_issuer.clone(),
        access_token: issuance.token.access_token.clone(),
        format: Some(cfg.format.clone()),
        proof: Some(proof.clone()),
        credential_identifier: Some(id.into()),
        credential_definition: Some(cfg.credential_definition.clone()),
        credential_response_encryption: None,
    }
}

/// Construct a credential from a credential response.
async fn credential(
    issuance: &Issuance, credential_configuration: &CredentialConfiguration,
    res: &CredentialResponse,
) -> Result<Credential> {
    let Some(value) = res.credential.as_ref() else {
        err!(Err::InvalidRequest, "no credential in response");
    };
    let Some(token) = value.as_str() else {
        err!(Err::InvalidRequest, "credential is not a string");
    };
    let Ok(Payload::Vc(vc)) = proof::verify(token, Verify::Vc).await else {
        err!(Err::InvalidRequest, "could not parse credential");
    };

    Ok(Credential {
        id: vc.id.clone(),
        issuer: issuance.offer.credential_issuer.clone(),
        metadata: credential_configuration.clone(),
        vc,
        issued: token.into(),

        ..Credential::default()
    })
}
