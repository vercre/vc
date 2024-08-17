#![allow(dead_code)]

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use vercre_core::Quota;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::{
    AuthorizationRequest, AuthorizationResponse, CredentialOffer, CredentialResponse,
    DeferredCredentialRequest, DeferredCredentialResponse, ProofClaims, TokenGrantType,
    TokenRequest, TokenResponse,
};
use vercre_openid::Result;
use vercre_test_utils::holder;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_w3c_vc::proof::{self, Payload, Verify};

pub const CODE_VERIFIER: &str = "ABCDEF12345";
pub const REDIRECT_URI: &str = "http://localhost:3000/callback";

pub struct Wallet {
    pub snapshot: String,
    pub provider: issuer::Provider,
    pub tx_code: Option<String>,
}

impl Wallet {
    pub async fn self_initiated(&self) -> Result<()> {
        let authzn = self.authorize().await.expect("should authorize");

        let grant_type = TokenGrantType::AuthorizationCode {
            code: authzn.code,
            code_verifier: Some(CODE_VERIFIER.to_string()),
            redirect_uri: Some(REDIRECT_URI.into()),
        };

        let token = self.token(grant_type).await.expect("should get token");
        self.credential(token).await
    }

    pub async fn issuer_initiated(&self, offer: CredentialOffer) -> Result<()> {
        let Some(grants) = &offer.grants else {
            panic!("grants should be set");
        };
        let Some(grant) = &grants.pre_authorized_code else {
            panic!("pre_authorized_code should be set");
        };
        let grant_type = TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: grant.pre_authorized_code.clone(),
            tx_code: self.tx_code.clone(),
        };

        let token = self.token(grant_type).await.expect("should get token");
        self.credential(token).await
    }

    // Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
    // make credential offer to Wallet.
    pub async fn authorize(&self) -> Result<AuthorizationResponse> {
        // create request
        let body = json!({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
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
        let mut request =
            serde_json::from_value::<AuthorizationRequest>(body).expect("should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();

        vercre_issuer::authorize(self.provider.clone(), &request).await
    }

    async fn token(&self, grant_type: TokenGrantType) -> Result<TokenResponse> {
        let token_req = TokenRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            client_id: CLIENT_ID.into(),
            grant_type,
            ..TokenRequest::default()
        };

        vercre_issuer::token(self.provider.clone(), &token_req).await
    }

    async fn credential(&self, token_resp: TokenResponse) -> Result<()> {
        // credential request
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: token_resp.c_nonce.clone(),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": token_resp.access_token,
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            },
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request = serde_json::from_value(body).expect("should deserialize");
        let mut response = vercre_issuer::credential(self.provider.clone(), &request)
            .await
            .expect("should get credential");

        if response.transaction_id.is_some() {
            assert_snapshot!(format!("{}:response", self.snapshot), &response, {
                ".transaction_id" => "[transaction_id]",
                ".c_nonce" => "[c_nonce]",
                ".c_nonce_expires_in" => "[c_nonce_expires_in]"
            });

            let deferred_resp =
                self.deferred(token_resp.clone(), response.clone()).await.expect("Ok");
            response = deferred_resp.credential_response;
        }

        if let Some(credential) = &response.credential {
            // verify the credential is as expected
            let Quota::One(vc_kind) = credential else {
                panic!("expected one credential");
            };

            let Payload::Vc(vc) =
                proof::verify(Verify::Vc(&vc_kind), &self.provider).await.expect("should decode")
            else {
                panic!("should be VC");
            };

            assert_snapshot!(format!("{}:credential", self.snapshot), vc, {
                ".issuanceDate" => "[issuanceDate]",
                ".credentialSubject" => insta::sorted_redaction()
            });
        }

        Ok(())
    }

    async fn deferred(
        &self, tkn: TokenResponse, cred_resp: CredentialResponse,
    ) -> Result<DeferredCredentialResponse> {
        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: tkn.access_token,
            transaction_id: cred_resp.transaction_id.expect("should have transaction_id"),
        };
        vercre_issuer::deferred(self.provider.clone(), &request).await
    }
}
