//! Tests for the `authorize` endpoint.

mod utils;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_vc::oid4vci::client::AuthorizationRequestBuilder;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::State;
use credibil_vc::oid4vci::{
    AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest, CredentialAuthorization,
    Error, endpoint,
};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use sha2::{Digest, Sha256};
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn authorize_configuration_id() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let request = AuthorizationRequestBuilder::new()
        .credential_issuer(CREDENTIAL_ISSUER)
        .client_id(CLIENT_ID)
        .redirect_uri("http://localhost:3000/callback")
        .state("1234")
        .code_challenge(Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")))
        .authorization_details(vec![AuthorizationDetail {
            type_: AuthorizationDetailType::OpenIdCredential,
            credential: CredentialAuthorization::ConfigurationId {
                credential_configuration_id: "EmployeeID_JWT".to_string(),
                claims: None,
            },
            ..AuthorizationDetail::default()
        }])
        .subject_id(NORMAL_USER)
        .build();

    let response = endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("ok");
    assert_snapshot!("authorize:configuration_id:response", &response, {
        ".code" =>"[code]",
    });

    // // check saved state
    // let state = StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
    // assert_snapshot!("authorize:configuration_id:state", state, {
    //     ".expires_at" => "[expires_at]",
    //     ".**.credentialSubject" => insta::sorted_redaction(),
    //     ".**.credentialSubject.address" => insta::sorted_redaction(),
    // });
}

#[tokio::test]
async fn authorize_format() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "authorization_details": [{
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            }
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    // execute request
    let request: AuthorizationRequest = serde_json::from_value(value).expect("should deserialize");
    let response = endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("ok");
    assert_snapshot!("authorize:format:response", &response, {
        ".code" =>"[code]",
    });

    // check saved state
    let state = StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
    assert_snapshot!("authorize:format:state", state, {
        ".expires_at" => "[expires_at]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });
}

#[tokio::test]
async fn authorize_scope() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "scope": "EmployeeIDCredential",
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    // execute request
    let request: AuthorizationRequest = serde_json::from_value(value).expect("should deserialize");
    let response = endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("ok");
    assert_snapshot!("authorize:scope:response", &response, {
        ".code" =>"[code]",
    });

    // check saved state
    let state = StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
    assert_snapshot!("authorize:scope:state", state, {
        ".expires_at" => "[expires_at]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });
}

#[tokio::test]
async fn authorize_claims() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "EmployeeID_JWT",
            "credential_definition": {
                "credentialSubject": {
                    "email": {},
                    "given_name": {},
                    "family_name": {},
                    "address": {
                        "street_address": {},
                        "locality": {}
                    }
                }
            }
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    // execute request
    let request: AuthorizationRequest = serde_json::from_value(value).expect("should deserialize");
    let response = endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("ok");
    assert_snapshot!("authorize:claims:response", &response, {
        ".code" =>"[code]",
    });

    // check saved state
    let state = StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
    assert_snapshot!("authorize:claims:state", state, {
        ".expires_at" => "[expires_at]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });
}

#[tokio::test]
async fn authorize_claims_err() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "authorization_details": [{
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ],
                "credentialSubject": {
                    "given_name": {},
                    "family_name": {},
                    "employee_id": {}
                }
            }
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    // execute request
    let request: AuthorizationRequest = serde_json::from_value(value).expect("should deserialize");
    let Err(Error::InvalidRequest(e)) =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await
    else {
        panic!("no error");
    };

    assert_eq!(e, "email claim is required");
}
