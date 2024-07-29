use std::sync::LazyLock;

use assert_let_bind::assert_let;
use chrono::Utc;
use datasec::jose::jws::{self, Type};
use futures::future::TryFutureExt;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_utils::holder;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, PENDING_USER};
use vercre_issuer::{
    CreateOfferRequest, CreateOfferResponse, CredentialOfferType, CredentialRequest,
    CredentialResponse, DeferredCredentialRequest, DeferredCredentialResponse, ProofClaims,
    TokenRequest, TokenResponse,
};

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn deferred_flow() {
    test_utils::init_tracer();

    // go through the pre-auth flow to token endpoint
    let token_resp = get_offer().and_then(get_token).await.expect("Ok");
    let credential_resp = get_credential(token_resp.clone()).await.expect("Ok");

    assert_snapshot!("credential-response", &credential_resp, {
        ".transaction_id" => "[transaction_id]",
        ".c_nonce" => "[c_nonce]",
        ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    });

    let deferred_resp = get_deferred(token_resp, credential_resp.clone()).await.expect("Ok");

    assert_snapshot!("deferred-response", deferred_resp, {
        ".credential" => "[credential]",
        ".c_nonce" => "[c_nonce]",
        ".c_nonce_expires_in" => "[c_nonce_expires_in]"
    });
}

// Simulate Issuer request to '/create_offer' endpoint to get credential offer to use to
// make credential offer to Wallet.
async fn get_offer() -> openid::Result<CreateOfferResponse> {
    // offer request
    let body = json!({
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": PENDING_USER,
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
async fn get_token(input: CreateOfferResponse) -> openid::Result<TokenResponse> {
    assert_let!(CredentialOfferType::Object(offer), &input.credential_offer);

    assert_let!(Some(grants), &offer.grants);
    assert_let!(Some(pre_authorized_code), &grants.pre_authorized_code);

    // create TokenRequest to 'send' to the app
    let body = json!({
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": &pre_authorized_code.pre_authorized_code,
        "user_code": input.user_code.unwrap_or_default(),
    });

    let mut request = serde_json::from_value::<TokenRequest>(body).expect("should deserialize");
    request.credential_issuer = CREDENTIAL_ISSUER.into();

    vercre_issuer::token(ISSUER_PROVIDER.clone(), &request).await
}

// Simulate Wallet request to '/credential' endpoint with access token to get credential.
async fn get_credential(input: TokenResponse) -> openid::Result<CredentialResponse> {
    // create CredentialRequest to 'send' to the app
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

async fn get_deferred(
    tkn: TokenResponse, cred_resp: CredentialResponse,
) -> openid::Result<DeferredCredentialResponse> {
    let request = DeferredCredentialRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        access_token: tkn.access_token,
        transaction_id: cred_resp.transaction_id.expect("should have transaction_id"),
    };

    vercre_issuer::deferred(ISSUER_PROVIDER.clone(), &request).await
}
