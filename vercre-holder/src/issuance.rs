//! # Issuance
//!
//! The Issuance endpoint implements the vercre-wallet's credential issuance flow.
use std::collections::HashMap;
use std::fmt::Debug;

use providers::wallet;
use serde::{Deserialize, Serialize};
use tracing::instrument;
use uuid::Uuid;
use vercre_core::error::Err;
use vercre_core::metadata::CredentialConfiguration;
use vercre_core::vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, GrantType, MetadataRequest,
    MetadataResponse, Proof, ProofClaims, TokenRequest, TokenResponse,
};
use vercre_core::{err, Result};
use vercre_vc::proof::jose;

use crate::credential::Credential;
use crate::provider::{
    Callback, CredentialStorer, IssuanceInput, IssuanceListener, IssuerClient, Signer,
};
use crate::Endpoint;

/// `Issuance` maintains app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// The current status of the issuance flow.
    pub status: Status,

    /// The `CredentialOffer` received from the issuer.
    pub offer: CredentialOffer,

    /// A list of `CredentialConfiguration`s, one for each credential offered.
    pub offered: HashMap<String, CredentialConfiguration>,

    /// The user's pin, as set from the shell.
    pub pin: Option<String>,

    /// The `TokenResponse` received from the issuer.
    pub token: TokenResponse,
}

/// Issuance Status values.
#[derive(Default, Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
#[serde(rename = "IssuanceStatus")]
pub enum Status {
    /// No credential offer is being processed.
    #[default]
    Inactive,

    /// A new credential offer has been received.
    Offered,

    /// Metadata has been retrieved and the offer is ready to be viewed.
    Ready,

    /// The offer requires a user pin to progress.
    PendingPin,

    /// The offer has been accepted and the credential is being issued.
    Accepted,

    /// A credential has been requested.
    Requested,

    /// The credential offer has failed, with an error message.
    Failed(String),
}

/// The `ReceiveOfferRequest` is the input to the `receive_offer` endpoint.
#[derive(Clone, Debug, Default)]
pub struct ReceiveOfferRequest {
    /// Wallet client identifier. This is used by the issuance service to issue an access token so
    /// should be unique to the holder's agent. Care should be taken to ensure this is not shared
    /// across holders in the case of headless, multi-tenant agents.
    pub client_id: String,
    /// The credential offer from the issuer.
    pub offer: CredentialOffer,
}

impl<P> Endpoint<P>
where
    P: Callback
        + CredentialStorer
        + IssuanceInput
        + IssuanceListener
        + IssuerClient
        + Signer
        + Clone
        + Debug,
{
    /// Orchestrates the issuance flow triggered by a new credential offer.
    #[instrument(level = "debug", skip(self))]
    pub async fn receive_offer(&self, request: &ReceiveOfferRequest) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: CredentialStorer + IssuanceInput + IssuanceListener + IssuerClient + Signer + Debug,
{
    type Provider = P;
    type Request = ReceiveOfferRequest;
    type Response = ();

    async fn verify(&mut self, _provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        if req.offer.credential_configuration_ids.is_empty() {
            err!(Err::InvalidRequest, "no credential IDs");
        }
        let Some(grants) = &req.offer.grants else {
            err!(Err::InvalidRequest, "no grants");
        };
        if grants.pre_authorized_code.is_none() {
            err!(Err::InvalidRequest, "no pre-authorized code");
        }

        Ok(self)
    }

    #[allow(clippy::too_many_lines)]
    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Establish a new issuance flow state
        let mut issuance = Issuance {
            id: Uuid::new_v4().to_string(),
            status: Status::Offered,
            ..Default::default()
        };
        provider.notify(&issuance.id, Status::Offered);

        // Process the offer and establish a metadata request, passing that to the provider to
        // use.
        let metadata_request = offer(&mut issuance, &req.offer);
        let metadata_response = match provider.get_metadata(&issuance.id, &metadata_request).await {
            Ok(resp) => resp,
            Err(e) => {
                provider.notify(&issuance.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };

        // Update the flow state with issuer's metadata.
        if let Err(e) = metadata(&mut issuance, &metadata_response) {
            provider.notify(&issuance.id, Status::Failed(e.to_string()));
            return Ok(());
        };
        issuance.status = Status::Ready;
        provider.notify(&issuance.id, Status::Ready);

        // Ask the holder's agent to confirm acceptance of the offer.
        // TODO: Should this be wholesale rejection of the offer or credential-by-credential?
        if !provider.accept(&issuance.id, &issuance.offered).await {
            return Ok(());
        }

        // Get PIN if required. Unwraps are OK since verify was called to check existence.
        let grants = req.offer.grants.as_ref().expect("grants exist on offer");
        let pre_auth_code =
            grants.pre_authorized_code.as_ref().expect("pre-authorization code exists on offer");
        if let Some(tx_code) = &pre_auth_code.tx_code {
            issuance.status = Status::PendingPin;
            provider.notify(&issuance.id, Status::PendingPin);
            let pin = provider.pin(&issuance.id, tx_code).await;
            issuance.pin = Some(pin);
        };
        issuance.status = Status::Accepted;
        provider.notify(&issuance.id, Status::Accepted);

        // Request an access token from the issuer.
        let token_request =
            token_request(&req.client_id, &issuance, &pre_auth_code.pre_authorized_code);
        let token_response = match provider.get_token(&issuance.id, &token_request).await {
            Ok(resp) => resp,
            Err(e) => {
                provider.notify(&issuance.id, Status::Failed(e.to_string()));
                return Ok(());
            }
        };
        issuance.token = token_response;

        // Request each credential offered.
        // TODO: concurrent requests. Possible if wallet is WASM?

        for (id, cfg) in &issuance.offered {
            // Construct a proof to be used in credential requests.
            let claims = ProofClaims {
                iss: provider.verification_method(),
                aud: issuance.offer.credential_issuer.clone(),
                iat: chrono::Utc::now().timestamp(),
                nonce: issuance.token.c_nonce.clone().unwrap_or_default(),
            };
            let Ok(jwt) = jose::encode(jose::Typ::WalletProof, &claims, wallet::Provider).await
            else {
                provider.notify(&issuance.id, Status::Failed("could not encode proof".into()));
                return Ok(());
            };

            let proof = Proof {
                proof_type: "jwt".into(),
                jwt: Some(jwt),
                cwt: None,
            };

            let request = credential_request(&issuance, id, cfg, &proof);
            issuance.status = Status::Requested;
            provider.notify(&issuance.id, Status::Requested);
            let cred_res = match provider.get_credential(&issuance.id, &request).await {
                Ok(r) => r,
                Err(e) => {
                    provider.notify(&issuance.id, Status::Failed(e.to_string()));
                    return Ok(());
                }
            };
            if cred_res.c_nonce.is_some() {
                issuance.token.c_nonce.clone_from(&cred_res.c_nonce);
            }
            if cred_res.c_nonce_expires_in.is_some() {
                issuance.token.c_nonce_expires_in.clone_from(&cred_res.c_nonce_expires_in);
            }

            // Create a credential in a useful wallet format.
            let mut credential = match credential(&issuance, cfg, &cred_res) {
                Ok(c) => c,
                Err(e) => {
                    provider.notify(&issuance.id, Status::Failed(e.to_string()));
                    return Ok(());
                }
            };
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
            match provider.save(&credential).await {
                Ok(()) => (),
                Err(e) => {
                    provider.notify(&issuance.id, Status::Failed(e.to_string()));
                    return Ok(());
                }
            };
        }
        provider.notify(&issuance.id, Status::Inactive);

        Ok(())
    }
}

/// Convert a `CredentialOffer` into a `MetadataRequest` and update flow state.
fn offer(issuance: &mut Issuance, req: &CredentialOffer) -> MetadataRequest {
    issuance.offer = req.clone();

    // Set up a credential configuration for each credential offered
    for id in &req.credential_configuration_ids {
        issuance.offered.insert(id.into(), CredentialConfiguration::default());
    }

    MetadataRequest {
        credential_issuer: req.credential_issuer.clone(),
        languages: None, // The wallet client should provide any specific languages required.
    }
}

/// Update the flow state with the issuer's metadata.
fn metadata(issuance: &mut Issuance, md: &MetadataResponse) -> Result<()> {
    let creds_supported = &md.credential_issuer.credential_configurations_supported;

    for (cfg_id, cred_cfg) in &mut issuance.offered {
        // find supported credential in metadata and copy to state object.
        let Some(found) = creds_supported.get(cfg_id) else {
            issuance.status = Status::Failed(String::from("Unsupported credential type in offer"));
            err!(Err::InvalidRequest, "unsupported credential type in offer");
        };
        *cred_cfg = found.clone();
    }
    issuance.status = Status::Ready;
    Ok(())
}

/// Construct a token request.
fn token_request(client_id: &str, issuance: &Issuance, pre_authorized_code: &str) -> TokenRequest {
    TokenRequest {
        credential_issuer: issuance.offer.credential_issuer.clone(),
        client_id: client_id.into(),
        grant_type: GrantType::PreAuthorizedCode,
        pre_authorized_code: Some(pre_authorized_code.to_string()),
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
fn credential(
    issuance: &Issuance, credential_configuration: &CredentialConfiguration,
    res: &CredentialResponse,
) -> Result<Credential> {
    let Some(value) = res.credential.as_ref() else {
        err!(Err::InvalidRequest, "no credential in response");
    };
    let Some(token) = value.as_str() else {
        err!(Err::InvalidRequest, "credential is not a string");
    };
    let Ok(jwt) = jose::decode::<jose::VcClaims>(token) else {
        err!(Err::InvalidRequest, "could not parse credential");
    };

    Ok(Credential {
        id: jwt.claims.vc.id.clone(),
        issuer: issuance.offer.credential_issuer.clone(),
        metadata: credential_configuration.clone(),
        vc: jwt.claims.vc,
        issued: token.into(),

        ..Credential::default()
    })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use providers::wallet;
    use vercre_core::vci::{Grants, PreAuthorizedCodeGrant, TxCode};

    use super::*;

    fn sample_offer() -> CredentialOffer {
        CredentialOffer {
            credential_issuer: "http://vercre.io".into(),
            credential_configuration_ids: vec!["EmployeeID_JWT".into()],
            grants: Some(Grants {
                authorization_code: None,
                pre_authorized_code: Some(PreAuthorizedCodeGrant {
                    pre_authorized_code: "cVJ9o7fKUOxLbyQAEbHx3TPkTbvjTHHH".into(),
                    tx_code: Some(TxCode {
                        input_mode: Some("numeric".into()),
                        length: Some(4),
                        description: None,
                    }),
                    ..Default::default()
                }),
            }),
        }
    }

    #[test]
    fn offer_test() {
        let mut issuance = Issuance {
            id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
            status: Status::Offered,
            ..Default::default()
        };
        let received_offer = sample_offer();
        let mdr = offer(&mut issuance, &received_offer);
        assert_eq!(mdr.credential_issuer, "http://vercre.io");
        assert!(issuance.offered.contains_key("EmployeeID_JWT"));
    }

    #[test]
    fn metadata_test() {
        let mut issuance = Issuance {
            id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
            status: Status::Offered,
            offer: sample_offer(),
            offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
            ..Default::default()
        };
        let meta_res = MetadataResponse {
            credential_issuer: vercre_core::metadata::Issuer::sample(),
        };
        metadata(&mut issuance, &meta_res).expect("metadata should update flow");
        assert_snapshot!(
            "issuance",
            &issuance,
            { ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction() }
        );
    }

    #[test]
    fn token_request_test() {
        let mut issuance = Issuance {
            id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
            status: Status::Accepted,
            offer: sample_offer(),
            offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
            pin: Some("1234".into()),
            ..Default::default()
        };
        let meta_res = MetadataResponse {
            credential_issuer: vercre_core::metadata::Issuer::sample(),
        };
        metadata(&mut issuance, &meta_res).expect("metadata should update flow");
        let token_req = token_request(
            "96bfb9cb-0513-7d64-5532-bed74c48f9ab",
            &issuance,
            "cVJ9o7fKUOxLbyQAEbHx3TPkTbvjTHHH",
        );
        assert_snapshot!("token_request", &token_req);
    }

    #[tokio::test]
    async fn proof_test() {
        let mut issuance = Issuance {
            id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
            status: Status::Accepted,
            offer: sample_offer(),
            offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
            pin: Some("1234".into()),

            ..Issuance::default()
        };

        let meta_res = MetadataResponse {
            credential_issuer: vercre_core::metadata::Issuer::sample(),
        };
        metadata(&mut issuance, &meta_res).expect("metadata should update flow");

        let claims = ProofClaims {
            iss: wallet::did(),
            aud: issuance.offer.credential_issuer.clone(),
            iat: chrono::Utc::now().timestamp(),
            nonce: issuance.token.c_nonce.clone().unwrap_or_default(),
        };

        let token = jose::encode(jose::Typ::WalletProof, &claims, wallet::Provider)
            .await
            .expect("should encode");

        let jwt: jose::Jwt<ProofClaims> = jose::decode(&token).expect("should decode");

        assert_eq!(jwt.claims.aud, "http://vercre.io");
        assert_snapshot!("proof_jwt", &jwt, { ".claims.iat" => "[timestamp]" });
    }

    #[tokio::test]
    async fn credential_request_test() {
        let mut issuance = Issuance {
            id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
            status: Status::Accepted,
            offer: sample_offer(),
            offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
            pin: Some("1234".into()),
            ..Default::default()
        };
        let meta_res = MetadataResponse {
            credential_issuer: vercre_core::metadata::Issuer::sample(),
        };
        metadata(&mut issuance, &meta_res).expect("metadata should update flow");
        let id = issuance.offered.keys().next().expect("should have an offered configuration key");
        let cfg = issuance.offered.get(id).expect("should have an offered configuration");
        
        let claims = ProofClaims {
            iss: wallet::did(),
            aud: "http://vercre.io".into(),
            iat: 1717546167,
            nonce: "".into(),
        };

        let token = jose::encode(jose::Typ::WalletProof, &claims, wallet::Provider)
            .await
            .expect("should encode");
        let proof = Proof {
            proof_type: "jwt".into(),
            jwt: Some(token),
            cwt: None,
        };

        let request = credential_request(&issuance, id, cfg, &proof);
        assert_snapshot!(
            "credential_request",
            &request,
            { ".credential_definition.credentialSubject" => insta::sorted_redaction() }
        );
    }

    // TODO: Test conversion of credential response to wallet-friendly credential. It is not
    // easy to do this without a real response from the issuance endpoint, which would mean
    // executing the entire flow. This is covered in end-to-end tests already. May need to
    // use a temporary output in that test flow to construct this test set-up.
}
