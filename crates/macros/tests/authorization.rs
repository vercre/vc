#![allow(missing_docs)]

use base64ct::{Base64UrlUnpadded, Encoding};
use insta::assert_yaml_snapshot as assert_snapshot;
use sha2::{Digest, Sha256};
use vercre_macros::authorization_request;

const CREDENTIAL_ISSUER: &str = "http://vercre.io";
const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
const NORMAL_USER: &str = "normal_user";

#[test]
fn configuration_id() {
    let request = authorization_request!({
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
    });

    assert_snapshot!("configuration_id", &request, {
        ".code_challenge" => "[base64]",
    });
}

#[test]
fn credential_definition() {
    let request = authorization_request!({
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
                    "given_name": {},
                    "family_name": {},
                }
            }
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    assert_snapshot!("credential_definition", &request, {
        ".code_challenge" => "[base64]",
        // ".authorization_details.*.credential_definition.credentialSubject" => insta::sorted_redaction(),
        ".authorization_details" => "[authorization_details]"
    });
}

#[test]
fn format() {
    let request = authorization_request!({
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
                "credentialSubject": {}
            }
        }],
        "subject_id": NORMAL_USER,
        "wallet_issuer": CREDENTIAL_ISSUER
    });

    assert_snapshot!("format", &request, {
        ".code_challenge" => "[base64]",
        ".authorization_details" => "[authorization_details]"
    });
}

#[test]
fn scope() {
    let request = authorization_request!({
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

    assert_snapshot!("scope", &request);
}
