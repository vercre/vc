use std::sync::LazyLock;

use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use providers::issuance::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
use providers::wallet;
use serde_json::json;
use sha2::{Digest, Sha256};
use vercre_core::jwt;
use vercre_issuer::authorize::{AuthorizationRequest, AuthorizationResponse};
use vercre_issuer::credential::{CredentialRequest, CredentialResponse};
use vercre_issuer::token::{TokenRequest, TokenResponse};
use vercre_issuer::{Endpoint, ProofClaims};
use vercre_vc::proof::{self, Payload, Verify};

static PROVIDER: LazyLock<Provider> = LazyLock::new(|| Provider::new());

// Run through entire authorization code flow.
#[tokio::test]
async fn auth_code_flow() {
    test_utils::init_tracer();

    // go through the auth code flow
    let resp = authorize().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let vc_val = resp.credential.expect("VC is present");
    let token = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");

    let Payload::Vc(vc) = proof::verify(&token, Verify::Vc).await.expect("should decode") else {
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
    // authorize request
    let auth_dets = json!([{
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
            "credential_subject": {}
        }
    }])
    .to_string();

    let verifier_hash = Sha256::digest("ABCDEF12345");

    // create request
    let body = json!({
        "response_type": "code",
        "client_id": wallet::CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
        "code_challenge_method": "S256",
        "authorization_details": auth_dets,
        "holder_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER,
        "callback_id": "1234"
    });
    let mut request = serde_json::from_value::<AuthorizationRequest>(body)?;
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.authorize(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: AuthorizationResponse) -> Result<TokenResponse> {
    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": wallet::CLIENT_ID,
        "grant_type": "authorization_code",
        "code": &input.code,
        "code_verifier": "ABCDEF12345",
        "redirect_uri": "http://localhost:3000/callback",
    });

    let mut request = serde_json::from_value::<TokenRequest>(body)?;
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.token(&request).await?;

    assert_snapshot!("token", &response, {
        ".access_token" => "[access_token]",
        ".c_nonce" => "[c_nonce]"
    });

    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    // create CredentialRequest to 'send' to the app
    let claims = ProofClaims {
        iss: Some(wallet::CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.to_string(),
        iat: Utc::now().timestamp(),
        nonce: input.c_nonce,
    };
    let jwt = jwt::encode(jwt::Payload::Proof, &claims, wallet::Provider::new())
        .await
        .expect("should encode");

    // HACK: get credential identifier
    let Some(auth_dets) = input.authorization_details else {
        panic!("No authorization details");
    };
    // let Some(identifiers) = &auth_dets[0].credential_identifiers else {
    //     panic!("No credential identifiers");
    // };

    let auth_det = auth_dets[0].authorization_detail.clone();

    // TODO: get identifier from token
    let body = json!({
        "format": auth_det.format.unwrap(),
        "credential_definition": auth_det.credential_definition,
        "proof":{
            "proof_type": "jwt",
            "jwt": jwt
        }
    });

    let mut request = serde_json::from_value::<CredentialRequest>(body)?;
    request.credential_issuer = CREDENTIAL_ISSUER.to_string();
    request.access_token = input.access_token;

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.credential(&request).await?;
    Ok(response)
}
