//! # Issuance
//!
//! The Issuance endpoints implement the vercre-wallet's credential issuance flow.

mod accept;
mod credential;
mod offer;
mod pin;

use std::collections::HashMap;
use std::fmt::Debug;

pub use offer::OfferRequest;
pub use openid4vc::issuance::{
    CredentialConfiguration, CredentialOffer, CredentialRequest, CredentialResponse, GrantType,
    Issuer, MetadataRequest, MetadataResponse, Proof, ProofClaims, TokenRequest, TokenResponse,
    TxCode,
};
pub use pin::PinRequest;
use serde::{Deserialize, Serialize};

/// `Issuance` represents app state across the steps of the issuance flow.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Issuance {
    /// The unique identifier for the issuance flow. Not used internally but passed to providers
    /// so that wallet clients can track interactions with specific flows.
    pub id: String,

    /// Client ID of the holder's agent (eg. wallet)
    pub client_id: String,

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

// /// Convert a `CredentialOffer` into a `MetadataRequest` and update flow state.
// fn offer(issuance: &mut Issuance, req: &CredentialOffer) -> MetadataRequest {
//     issuance.offer = req.clone();

//     // Set up a credential configuration for each credential offered
//     for id in &req.credential_configuration_ids {
//         issuance.offered.insert(id.into(), CredentialConfiguration::default());
//     }

//     MetadataRequest {
//         credential_issuer: req.credential_issuer.clone(),
//         languages: None, // The wallet client should provide any specific languages required.
//     }
// }

// /// Update the flow state with the issuer's metadata.
// fn metadata(issuance: &mut Issuance, md: &MetadataResponse) -> Result<()> {
//     let creds_supported = &md.credential_issuer.credential_configurations_supported;

//     for (cfg_id, cred_cfg) in &mut issuance.offered {
//         // find supported credential in metadata and copy to state object.
//         let Some(found) = creds_supported.get(cfg_id) else {
//             issuance.status = Status::Failed(String::from("Unsupported credential type in offer"));
//             err!(Err::InvalidRequest, "unsupported credential type in offer");
//         };
//         *cred_cfg = found.clone();
//     }
//     issuance.status = Status::Ready;
//     Ok(())
// }

// /// Construct a token request.
// fn token_request(issuance: &Issuance) -> TokenRequest {
//     // Get pre-authorized code. Unwraps are OK since verification should be called on outer endpoint
//     // to check existence.
//     let grants = issuance.offer.grants.as_ref().expect("grants exist on offer");
//     let pre_auth_code =
//         grants.pre_authorized_code.as_ref().expect("pre-authorized code exists on offer");

//     TokenRequest {
//         credential_issuer: issuance.offer.credential_issuer.clone(),
//         client_id: issuance.client_id.clone(),
//         grant_type: GrantType::PreAuthorizedCode,
//         pre_authorized_code: Some(pre_auth_code.pre_authorized_code.clone()),
//         user_code: issuance.pin.clone(),
//         ..Default::default()
//     }
// }

// /// Construct a credential request from an offered credential configuration.
// fn credential_request(
//     issuance: &Issuance, id: &str, cfg: &CredentialConfiguration, proof: &Proof,
// ) -> CredentialRequest {
//     CredentialRequest {
//         credential_issuer: issuance.offer.credential_issuer.clone(),
//         access_token: issuance.token.access_token.clone(),
//         format: Some(cfg.format.clone()),
//         proof: Some(proof.clone()),
//         credential_identifier: Some(id.into()),
//         credential_definition: Some(cfg.credential_definition.clone()),
//         credential_response_encryption: None,
//     }
// }

// /// Construct a credential from a credential response.
// async fn credential(
//     credential_configuration: &CredentialConfiguration, res: &CredentialResponse,
//     verifier: &impl Verifier,
// ) -> Result<Credential> {
//     let Some(value) = res.credential.as_ref() else {
//         err!(Err::InvalidRequest, "no credential in response");
//     };
//     let Some(token) = value.as_str() else {
//         err!(Err::InvalidRequest, "credential is not a JWT");
//     };
//     let Ok(Payload::Vc(vc)) = proof::verify(token, Verify::Vc, verifier).await else {
//         err!(Err::InvalidRequest, "could not parse credential");
//     };

//     Ok(Credential {
//         id: vc.id.clone(),
//         issuer: vc.issuer.id.clone(),
//         metadata: credential_configuration.clone(),
//         vc,
//         issued: token.into(),

//         ..Credential::default()
//     })
// }

// #[cfg(test)]
// mod tests {
//     use insta::assert_yaml_snapshot as assert_snapshot;
//     use openid4vc::issuance::{Grants, PreAuthorizedCodeGrant, TxCode};
//     use providers::{issuance, wallet};

//     use super::*;

//     fn sample_offer() -> CredentialOffer {
//         CredentialOffer {
//             credential_issuer: "http://vercre.io".into(),
//             credential_configuration_ids: vec!["EmployeeID_JWT".into()],
//             grants: Some(Grants {
//                 authorization_code: None,
//                 pre_authorized_code: Some(PreAuthorizedCodeGrant {
//                     pre_authorized_code: "cVJ9o7fKUOxLbyQAEbHx3TPkTbvjTHHH".into(),
//                     tx_code: Some(TxCode {
//                         input_mode: Some("numeric".into()),
//                         length: Some(4),
//                         description: None,
//                     }),
//                     ..Default::default()
//                 }),
//             }),
//         }
//     }

//     #[test]
//     fn offer_test() {
//         let mut issuance = Issuance {
//             id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
//             status: Status::Offered,
//             ..Default::default()
//         };
//         let received_offer = sample_offer();
//         let mdr = offer(&mut issuance, &received_offer);
//         assert_eq!(mdr.credential_issuer, "http://vercre.io");
//         assert!(issuance.offered.contains_key("EmployeeID_JWT"));
//     }

//     #[test]
//     fn metadata_test() {
//         let mut issuance = Issuance {
//             id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
//             status: Status::Offered,
//             offer: sample_offer(),
//             offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
//             ..Default::default()
//         };
//         let meta_res = MetadataResponse {
//             credential_issuer: Issuer::sample(),
//         };
//         metadata(&mut issuance, &meta_res).expect("metadata should update flow");
//         assert_snapshot!("issuance", &issuance, {
//             ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction()
//         });
//     }

//     #[test]
//     fn token_request_test() {
//         let mut issuance = Issuance {
//             id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
//             client_id: wallet::CLIENT_ID.into(),
//             status: Status::Accepted,
//             offer: sample_offer(),
//             offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
//             pin: Some("1234".into()),
//             ..Default::default()
//         };
//         let meta_res = MetadataResponse {
//             credential_issuer: Issuer::sample(),
//         };
//         metadata(&mut issuance, &meta_res).expect("metadata should update flow");
//         let token_req = token_request(&issuance);
//         assert_snapshot!("token_request", &token_req);
//     }

//     #[tokio::test]
//     async fn proof_test() {
//         let mut issuance = Issuance {
//             id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
//             status: Status::Accepted,
//             offer: sample_offer(),
//             offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
//             pin: Some("1234".into()),

//             ..Issuance::default()
//         };

//         let meta_res = MetadataResponse {
//             credential_issuer: Issuer::sample(),
//         };
//         metadata(&mut issuance, &meta_res).expect("metadata should update flow");

//         let claims = ProofClaims {
//             iss: Some(wallet::CLIENT_ID.into()),
//             aud: issuance.offer.credential_issuer.clone(),
//             iat: chrono::Utc::now().timestamp(),
//             nonce: issuance.token.c_nonce.clone(),
//         };

//         let token = jws::encode(Type::Proof, &claims, wallet::Provider::new())
//             .await
//             .expect("should encode");

//         let jwt: jws::Jwt<ProofClaims> =
//             jws::decode(&token, &issuance::Provider::new()).expect("should decode");

//         assert_eq!(jwt.claims.aud, "http://vercre.io");
//         assert_snapshot!("proof_jwt", &jwt, { ".claims.iat" => "[timestamp]" });
//     }

//     #[tokio::test]
//     async fn credential_request_test() {
//         let mut issuance = Issuance {
//             id: "1fdb69d1-8bcb-4cc9-9749-750ca285124f".into(),
//             status: Status::Accepted,
//             offer: sample_offer(),
//             offered: HashMap::from([("EmployeeID_JWT".into(), CredentialConfiguration::default())]),
//             pin: Some("1234".into()),
//             ..Default::default()
//         };
//         let meta_res = MetadataResponse {
//             credential_issuer: Issuer::sample(),
//         };
//         metadata(&mut issuance, &meta_res).expect("metadata should update flow");
//         let id = issuance.offered.keys().next().expect("should have an offered configuration key");
//         let cfg = issuance.offered.get(id).expect("should have an offered configuration");

//         let claims = ProofClaims {
//             iss: Some(wallet::CLIENT_ID.into()),
//             aud: "http://vercre.io".into(),
//             iat: 1717546167,
//             nonce: None,
//         };

//         let token = jws::encode(Type::Proof, &claims, wallet::Provider::new())
//             .await
//             .expect("should encode");
//         let proof = Proof {
//             proof_type: "jwt".into(),
//             jwt: Some(token),
//             cwt: None,
//         };

//         let request = credential_request(&issuance, id, cfg, &proof);
//         assert_snapshot!(
//             "credential_request",
//             &request,
//             { ".credential_definition.credentialSubject" => insta::sorted_redaction() }
//         );
//     }

//     // TODO: Test conversion of credential response to wallet-friendly credential. It is not
//     // easy to do this without a real response from the issuance endpoint, which would mean
//     // executing the entire flow. This is covered in end-to-end tests already. May need to
//     // use a temporary output in that test flow to construct this test set-up.
// }
