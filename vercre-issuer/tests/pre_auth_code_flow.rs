use std::sync::LazyLock;

use assert_let_bind::assert_let;
use chrono::Utc;
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use vercre_datasec::jose::jws::{self, Type};
use vercre_datasec::DataSec;
use vercre_issuer::{
    CreateOfferRequest, CreateOfferResponse, CredentialOfferType, CredentialRequest,
    CredentialResponse, ProofClaims, TokenRequest, TokenResponse,
};
use vercre_test_utils::holder;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_w3c_vc::proof::{Payload, Verify};

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn pre_auth_flow() {
    vercre_test_utils::init_tracer();

    // go through the pre-auth code flow
    let resp = get_offer().and_then(get_token).and_then(get_credential).await.expect("Ok");

    let Some(vc_kind) = &resp.credential else {
        panic!("VC is not present");
    };

    let provider = ISSUER_PROVIDER.clone();
    let resolver = DataSec::resolver(&provider, CREDENTIAL_ISSUER).expect("should get resolver");

    let Payload::Vc(vc) =
        vercre_w3c_vc::proof::verify(Verify::Vc(vc_kind), &resolver).await.expect("should decode")
    else {
        panic!("should be VC");
    };

    assert_snapshot!("vc", vc, {
        ".issuanceDate" => "[issuanceDate]",
        ".credentialSubject" => insta::sorted_redaction()
    });
}

// Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
// make credential offer to Wallet.
async fn get_offer() -> vercre_openid::Result<CreateOfferResponse> {
    // offer request
    let body = json!({
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre-authorize": true,
        "tx_code_required": true,
        "callback_id": "1234"
    });

    let mut request =
        serde_json::from_value::<CreateOfferRequest>(body).expect("should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.into();

    vercre_issuer::create_offer(ISSUER_PROVIDER.clone(), &request).await
}

// Simulate Wallet request to '/token' endpoint with pre-authorized code to get
// access token
async fn get_token(input: CreateOfferResponse) -> vercre_openid::Result<TokenResponse> {
    assert_let!(CredentialOfferType::Object(offer), &input.credential_offer);
    assert_let!(Some(grants), &offer.grants);
    assert_let!(Some(pre_authorized_code), &grants.pre_authorized_code);

    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
        "user_code": input.user_code.as_ref().expect("user pin should be set"),
    });

    let mut request = serde_json::from_value::<TokenRequest>(body).expect("should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.into();

    vercre_issuer::token(ISSUER_PROVIDER.clone(), &request).await
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> vercre_openid::Result<CredentialResponse> {
    let claims = ProofClaims {
        iss: Some(CLIENT_ID.into()),
        aud: CREDENTIAL_ISSUER.into(),
        iat: Utc::now().timestamp(),
        nonce: input.c_nonce,
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
    request.access_token = input.access_token;

    vercre_issuer::credential(ISSUER_PROVIDER.clone(), &request).await
}
