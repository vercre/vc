use assert_let_bind::assert_let;
use chrono::Utc;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use vercre_core::Quota;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::{CredentialOffer, CredentialRequest, ProofClaims, TokenRequest};
use vercre_openid::Result;
use vercre_test_utils::holder;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER};
use vercre_w3c_vc::proof::{self, Payload, Verify};

pub struct Wallet {
    pub provider: issuer::Provider,
    pub tx_code: Option<String>,
}


impl Wallet {
    pub async fn credential_offer(&self, offer: &CredentialOffer) -> Result<()> {
        assert_let!(Some(grants), &offer.grants);
        assert_let!(Some(pre_authorized_code), &grants.pre_authorized_code);

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
            "tx_code": self.tx_code.as_ref().expect("user pin should be set"),
        });

        let mut request = serde_json::from_value::<TokenRequest>(body).expect("should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();

        let token_resp =
            vercre_issuer::token(self.provider.clone(), &request).await.expect("should get token");

        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: token_resp.c_nonce,
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
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

        let mut request =
            serde_json::from_value::<CredentialRequest>(body).expect("should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.into();
        request.access_token = token_resp.access_token;

        let cred_resp = vercre_issuer::credential(self.provider.clone(), &request)
            .await
            .expect("should get credential");

        // verify the credential is as expected
        let vc_quota = cred_resp.credential.expect("no credential in response");
        let Quota::One(vc_kind) = vc_quota else {
            panic!("expected one credential");
        };

        let Payload::Vc(vc) =
            proof::verify(Verify::Vc(&vc_kind), &self.provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        Ok(())
    }
}
