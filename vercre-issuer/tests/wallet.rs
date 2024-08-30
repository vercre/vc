#![allow(dead_code)]

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use vercre_core::Quota;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::{
    AuthorizationResponse, CredentialOfferRequest, CredentialResponse, DeferredCredentialRequest,
    DeferredCredentialResponse, OfferType, ProofClaims, TokenGrantType, TokenRequest,
    TokenResponse,
};
use vercre_openid::{Error, FormatProfile, Result};
use vercre_test_utils::holder;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_w3c_vc::proof::{self, Payload, Verify};

pub const CODE_VERIFIER: &str = "ABCDEF12345";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";

#[derive(Default)]
pub struct Wallet {
    pub provider: issuer::Provider,
    pub format: FormatProfile,
    pub tx_code: Option<String>,
}

impl Wallet {
    pub async fn self_initiated(&self) -> Result<()> {
        let auth = self.authorize(None).await?;

        let grant_type = TokenGrantType::AuthorizationCode {
            code: auth.code,
            code_verifier: Some(CODE_VERIFIER.to_string()),
            redirect_uri: Some(REDIRECT_URI.into()),
        };

        let token = self.token(grant_type).await?;
        self.credential(token).await
    }

    pub async fn issuer_initiated(&self, offer_type: OfferType) -> Result<()> {
        let offer = match offer_type {
            OfferType::Object(offer) => offer,
            OfferType::Uri(uri) => {
                let path = format!("{CREDENTIAL_ISSUER}/credential_offer/");
                let Some(id) = uri.strip_prefix(&path) else {
                    panic!("should have prefix");
                };
                let request = CredentialOfferRequest {
                    credential_issuer: CREDENTIAL_ISSUER.into(),
                    id: id.to_string(),
                };

                let offer_resp =
                    vercre_issuer::credential_offer(self.provider.clone(), &request).await?;
                offer_resp.credential_offer
            }
        };

        let grants = &offer.grants.unwrap_or_default();

        let grant_type = if let Some(grant) = &grants.pre_authorized_code {
            TokenGrantType::PreAuthorizedCode {
                pre_authorized_code: grant.pre_authorized_code.clone(),
                tx_code: self.tx_code.clone(),
            }
        } else {
            let issuer_state = if let Some(grant) = &grants.authorization_code {
                grant.issuer_state.clone()
            } else {
                None
            };
            let auth = self.authorize(issuer_state).await?;

            TokenGrantType::AuthorizationCode {
                code: auth.code,
                redirect_uri: Some(auth.redirect_uri),
                code_verifier: Some(CODE_VERIFIER.to_string()),
            }
        };

        let token = self.token(grant_type).await?;
        self.credential(token).await
    }

    // Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
    // make credential offer to Wallet.
    pub async fn authorize(&self, state: Option<String>) -> Result<AuthorizationResponse> {
        let req_json = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": state.unwrap_or("1234".to_string()),
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": json!([{
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ],
                    "credentialSubject": {
                        "givenName": {},
                        "familyName": {},
                        "email": {}
                    }
                }
            }]).to_string(),
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        });
        let request =
            serde_json::from_value(req_json).map_err(|e| Error::ServerError(format!("{e}")))?;
        vercre_issuer::authorize(self.provider.clone(), &request).await
    }

    async fn token(&self, grant_type: TokenGrantType) -> Result<TokenResponse> {
        let token_req = TokenRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            client_id: Some(CLIENT_ID.into()),
            grant_type,
            ..TokenRequest::default()
        };

        vercre_issuer::token(self.provider.clone(), &token_req).await
    }

    async fn credential(&self, token_resp: TokenResponse) -> Result<()> {
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: token_resp.c_nonce.clone(),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider)
            .await
            .map_err(|e| Error::ServerError(format!("{e}")))?;

        // ------------------------------------------------------------
        // HACK: get this working
        // ------------------------------------------------------------
        // FIXME: two paths: credential_identifier or format/type
        let Some(auth_dets) = &token_resp.authorization_details else {
            panic!("authorization_details should be set");
        };
        let credential_identifier = &auth_dets[0].credential_identifiers[0];
        // ------------------------------------------------------------

        let req_json = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": token_resp.access_token,
            "credential_identifier": credential_identifier,
            // "format": self.format,
            // "credential_definition": {
            //     "type": [
            //         "VerifiableCredential",
            //         "EmployeeIDCredential"
            //     ]
            // },
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request =
            serde_json::from_value(req_json).map_err(|e| Error::ServerError(format!("{e}")))?;
        let mut response = vercre_issuer::credential(self.provider.clone(), &request).await?;

        // get credential if response is deferred (has transaction_id)
        if response.transaction_id.is_some() {
            let deferred_resp = self.deferred(token_resp.clone(), response.clone()).await?;
            response = deferred_resp.credential_response;
        }

        let Some(credential) = &response.credential else {
            panic!("credential should be set");
        };

        // TODO: verify signature

        // verify the credential is as expected
        let Quota::One(vc_kind) = credential else {
            panic!("expected one credential");
        };

        let Ok(Payload::Vc(vc)) = proof::verify(Verify::Vc(&vc_kind), &self.provider).await else {
            panic!("should be VC");
        };

        assert_snapshot!("credential", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // TODO: verify format is the one specified in request

        Ok(())
    }

    async fn deferred(
        &self, tkn_resp: TokenResponse, cred_resp: CredentialResponse,
    ) -> Result<DeferredCredentialResponse> {
        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: tkn_resp.access_token,
            transaction_id: cred_resp.transaction_id.expect("should have transaction_id"),
        };
        vercre_issuer::deferred(self.provider.clone(), &request).await
    }
}
