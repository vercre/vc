//! Tests for the `authorize` endpoint.

mod utils;

use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_vc::issuer;
use credibil_vc::issuer::state::State;
use credibil_vc::openid::provider::StateStore;
use insta::assert_yaml_snapshot as assert_snapshot;
use rstest::rstest;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

#[rstest]
#[case::configuration_id("configuration_id", configuration_id)]
#[case::format("format", format_w3c)]
#[case::scope("scope", scope)]
#[case::claims("claims", claims)]
#[should_panic(expected = "ok")]
#[case::claims_err("claims_err", claims_err)]
#[should_panic(expected = "ok")]
#[case::response_type_err("response_type_err", response_type_err)]
async fn authorize_tests(#[case] name: &str, #[case] value: fn() -> Value) {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    // execute request
    let request = serde_json::from_value(value()).expect("should deserialize");
    let response = issuer::authorize(provider.clone(), request).await.expect("ok");
    assert_snapshot!("authorize:configuration_id:response", &response, {
        ".code" =>"[code]",
    });

    // check saved state
    let state = StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
    assert_snapshot!(format!("authorize:{name}:state"), state, {
        ".expires_at" => "[expires_at]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });
}

fn configuration_id() -> Value {
    json!({
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
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    })
}

fn format_w3c() -> Value {
    json!({
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
    })
}

fn scope() -> Value {
    json!({
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
    })
}

fn claims() -> Value {
    json!({
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
    })
}

fn claims_err() -> Value {
    json!({
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
    })
}

fn response_type_err() -> Value {
    json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "response_type": "vp_token",
        "client_id": CLIENT_ID,
        "redirect_uri": "http://localhost:3000/callback",
        "state": "1234",
        "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
        "code_challenge_method": "S256",
        "authorization_details": [{
            "type": "openid_credential",
            "credential_configuration_id": "EmployeeID_JWT",
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    })
}
