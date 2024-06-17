use std::sync::LazyLock;

use anyhow::Result;
use assert_let_bind::assert_let;
use chrono::Utc;
use core_utils::jws::{self, Type};
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use providers::issuance::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
use providers::wallet;
use serde_json::json;
use vercre_issuer::create_offer::{CreateOfferRequest, CreateOfferResponse};
use vercre_issuer::credential::{CredentialRequest, CredentialResponse};
use vercre_issuer::token::{TokenRequest, TokenResponse};
use vercre_issuer::{Endpoint, ProofClaims};
use vercre_vc::proof::{self, Payload, Verify};

static PROVIDER: LazyLock<Provider> = LazyLock::new(|| Provider::new());

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn pre_auth_flow() {
    test_utils::init_tracer();

    // go through the pre-auth code flow
    let resp = get_offer().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let vc_val = resp.credential.expect("VC is present");
    let token = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
    let Payload::Vc(vc) = proof::verify(&token, Verify::Vc).await.expect("should decode") else {
        panic!("should be VC");
    };

    assert_snapshot!("vc", vc, {
        ".issuanceDate" => "[issuanceDate]",
        ".credentialSubject" => insta::sorted_redaction()
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
    request.credential_issuer = CREDENTIAL_ISSUER.into();

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
        "client_id": wallet::CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
        "user_code": input.user_code.as_ref().expect("user pin should be set"),
    });

    let mut request = serde_json::from_value::<TokenRequest>(body)?;
    request.credential_issuer = CREDENTIAL_ISSUER.into();

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.token(&request).await?;
    Ok(response)
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> Result<CredentialResponse> {
    let claims = ProofClaims {
        iss: Some(wallet::CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.into(),
        iat: Utc::now().timestamp(),
        nonce: input.c_nonce,
    };
    let jwt = jws::encode(Type::Proof, &claims, wallet::Provider::new())
        .await
        .expect("should encode");

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

    let mut request = serde_json::from_value::<CredentialRequest>(body)?;
    request.credential_issuer = CREDENTIAL_ISSUER.into();
    request.access_token = input.access_token;

    let endpoint = Endpoint::new(PROVIDER.to_owned());
    let response = endpoint.credential(&request).await?;
    Ok(response)
}
