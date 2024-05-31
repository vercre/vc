use std::str::FromStr;

use anyhow::Result;
use assert_let_bind::assert_let;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use lazy_static::lazy_static;
use serde_json::json;
use providers::issuance::{Provider, ISSUER, NORMAL_USER};
use test_utils::wallet;
use vercre_vci::create_offer::{CreateOfferRequest, CreateOfferResponse};
use vercre_vci::credential::{CredentialRequest, CredentialResponse};
use vercre_vci::jwt::{self, Jwt};
use vercre_vci::token::{TokenRequest, TokenResponse};
use vercre_vci::{Endpoint, ProofClaims, VcClaims};

lazy_static! {
    static ref PROVIDER: Provider = Provider::new();
}

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn pre_auth_flow() {
    test_utils::init_tracer();

    // go through the pre-auth code flow
    let resp = get_offer().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let vc_val = resp.credential.expect("VC is present");
    let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");

    assert_snapshot!("vc_jwt", vc_jwt, {
        ".claims.iat" => "[iat]",
        ".claims.nbf" => "[nbf]",
        ".claims.vc.issuanceDate" => "[issuanceDate]",
        ".claims.vc.credentialSubject" => insta::sorted_redaction()
    });
}

// Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
// make credential offer to Wallet.
async fn get_offer() -> Result<CreateOfferResponse> {
    // offer request
    let body = json!({
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "holder_id": NORMAL_USER,
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    });

    let mut request = serde_json::from_value::<CreateOfferRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.create_offer(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: CreateOfferResponse) -> Result<TokenResponse> {
    assert_let!(Some(offer), &input.credential_offer);
    assert_let!(Some(grants), &offer.grants);
    assert_let!(Some(pre_authorized_code), &grants.pre_authorized_code);

    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": wallet::did(),
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
        "user_code": input.user_code.as_ref().expect("user pin should be set"),
    });

    let mut request = serde_json::from_value::<TokenRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.token(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    // create CredentialRequest to 'send' to the app
    let jwt_enc = Jwt {
        header: jwt::Header {
            typ: "vercre-vci-proof+jwt".into(),
            alg: wallet::alg(),
            kid: wallet::kid(),
        },
        claims: ProofClaims {
            iss: wallet::did().to_string(),
            aud: ISSUER.to_string(),
            iat: Utc::now().timestamp(),
            nonce: input.c_nonce.expect("nonce should be set"),
        },
    }
    .to_string();
    let sig = wallet::sign(jwt_enc.as_bytes());
    let sig_enc = Base64UrlUnpadded::encode_string(&sig);
    let signed_jwt = format!("{jwt_enc}.{sig_enc}");

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
            "jwt": signed_jwt
        }
    });

    let mut request = serde_json::from_value::<CredentialRequest>(body)?;
    request.credential_issuer = ISSUER.to_string();
    request.access_token = input.access_token;

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.credential(&request).await?;
    Ok(response)
}
