use std::str::FromStr;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use lazy_static::lazy_static;
use serde_json::json;
use sha2::{Digest, Sha256};
use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
use test_utils::wallet;
use vercre_core::jwt::{self, Jwt};
use vercre_core::vci::ProofClaims;
use vercre_core::w3c::vc::VcClaims;
use vercre_core::Result;
use vercre_vci::{
    AuthorizationRequest, AuthorizationResponse, CredentialRequest, CredentialResponse, Endpoint,
    TokenRequest, TokenResponse,
};

lazy_static! {
    static ref PROVIDER: Provider = Provider::new();
}

// Run through entire authorization code flow.
#[tokio::test]
async fn auth_code_flow() {
    test_utils::init_tracer();

    // go through the auth code flow
    let resp = authorize().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let vc_val = resp.credential.expect("VC is present");
    let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");

    // check credential response JWT

    assert_snapshot!("vc_jwt", vc_jwt, {
        ".claims.iat" => "[iat]",
        ".claims.nbf" => "[nbf]",
        ".claims.vc.issuanceDate" => "[issuanceDate]",
        ".claims.vc.credentialSubject" => insta::sorted_redaction()
    });
}

// Simulate Issuer request to '/invoke' endpoint to get credential offer to use to
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
        "client_id": wallet::did(),
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
        "code_challenge_method": "S256",
        "authorization_details": auth_dets,
        "holder_id": NORMAL_USER,
        "wallet_issuer": ISSUER,
        "callback_id": "1234"
    });
    let mut request = serde_json::from_value::<AuthorizationRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.authorize(request).await?;
    Ok(response)
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: AuthorizationResponse) -> Result<TokenResponse> {
    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": wallet::did(),
        "grant_type": "authorization_code",
        "code": &input.code,
        "code_verifier": "ABCDEF12345",
        "redirect_uri": "http://localhost:3000/callback",
    });

    let mut request = serde_json::from_value::<TokenRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.token(request).await?;

    assert_snapshot!("token", response, {
        ".access_token" => "[access_token]",
        ".c_nonce" => "[c_nonce]"
    });

    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    // create CredentialRequest to 'send' to the app
    let jwt_enc = Jwt {
        header: jwt::Header {
            typ: "vercre-vci-proof+jwt".to_string(),
            alg: wallet::alg(),
            kid: wallet::kid(),
        },
        claims: ProofClaims {
            iss: wallet::did(),
            aud: ISSUER.to_string(),
            iat: Utc::now().timestamp(),
            nonce: input.c_nonce.unwrap_or_default(),
        },
    }
    .to_string();
    let sig = wallet::sign(jwt_enc.as_bytes());
    let sig_enc = Base64UrlUnpadded::encode_string(&sig);
    let signed_jwt = format!("{jwt_enc}.{sig_enc}");

    // HACK: get credential identifier
    let Some(auth_dets) = input.authorization_details else {
        panic!("No authorization details");
    };
    let Some(identifiers) = &auth_dets[0].credential_identifiers else {
        panic!("No credential identifiers");
    };

    // TODO: get identifier from token
    let body = json!({
        "credential_identifier": identifiers[0],
        "proof":{
            "proof_type": "jwt",
            "jwt": signed_jwt
        }
    });

    let mut request = serde_json::from_value::<CredentialRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();
    request.access_token = input.access_token;

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.credential(request).await?;
    Ok(response)
}
