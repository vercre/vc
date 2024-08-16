use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use vercre_core::Quota;
use vercre_datasec::jose::jws::{self, Type};
use vercre_issuer::{
    AuthorizationCredential, AuthorizationRequest, AuthorizationResponse, CredentialRequest,
    CredentialResponse, ProofClaims, TokenRequest, TokenResponse,
};
use vercre_openid::Result;
use vercre_test_utils::holder;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_w3c_vc::proof::{self, Payload, Verify};

static PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);

// Run through entire authorization code flow.
#[tokio::test]
async fn auth_code_flow() {
    vercre_test_utils::init_tracer();

    // go through the auth code flow
    let resp = authorize().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let vc_quota = resp.credential.expect("no credential in response");
    let Quota::One(vc_kind) = vc_quota else {
        panic!("expected one credential");
    };

    let provider = PROVIDER.clone();
    let Payload::Vc(vc) =
        proof::verify(Verify::Vc(&vc_kind), &provider).await.expect("should decode")
    else {
        panic!("should be VC");
    };

    // check credential response is correct
    assert_snapshot!("vc", vc, {
        ".issuanceDate" => "[issuanceDate]",
        ".credentialSubject" => insta::sorted_redaction()
    });
}

// Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
// make credential offer to Wallet.
async fn authorize() -> Result<AuthorizationResponse> {
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

    vercre_issuer::authorize(PROVIDER.clone(), &request).await
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: AuthorizationResponse) -> Result<TokenResponse> {
    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": &input.code,
        "code_verifier": "ABCDEF12345",
        "redirect_uri": "http://localhost:3000/callback",
    });

    let mut request = serde_json::from_value::<TokenRequest>(body).expect("should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();

    let response =
        vercre_issuer::token(PROVIDER.clone(), &request).await.expect("should get token");

    assert_snapshot!("token", &response, {
        ".access_token" => "[access_token]",
        ".c_nonce" => "[c_nonce]",
        ".authorization_details[].credential_definition.credentialSubject" => insta::sorted_redaction()

    });

    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    // HACK: get credential identifier
    let Some(auth_dets) = input.authorization_details else {
        panic!("No authorization details");
    };
    let auth_det = auth_dets[0].authorization_detail.clone();

    // TODO: get identifier from token
    let AuthorizationCredential::Format(format) = auth_det.credential_identifier.clone() else {
        panic!("unexpected credential type");
    };

    let claims = ProofClaims {
        iss: Some(CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.to_string(),
        iat: Utc::now().timestamp(),
        nonce: input.c_nonce,
    };
    let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

    let body = json!({
        "format": format,
        "credential_definition": auth_det.credential_definition,
        "proof":{
            "proof_type": "jwt",
            "jwt": jwt
        }
    });

    let mut request =
        serde_json::from_value::<CredentialRequest>(body).expect("should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();
    request.access_token = input.access_token;

    vercre_issuer::credential(PROVIDER.clone(), &request).await
}
