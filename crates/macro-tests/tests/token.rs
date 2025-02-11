#![allow(missing_docs)]

use insta::assert_yaml_snapshot as assert_snapshot;
use macros::token_request;

const CREDENTIAL_ISSUER: &str = "http://vercre.io";
const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

#[test]
fn pre_authorized() {
    let pre_auth_code = "ABCDEF";

    let request = token_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "client_id": CLIENT_ID,
        "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": pre_auth_code,
        "tx_code": "1234"
    });

    assert_snapshot!("pre_authorized", &request);
}

#[test]
fn authorized() {
    let code = "ABCDEF";
    let verifier = "ABCDEF12345";

    let request = token_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
    });

    assert_snapshot!("authorized", &request);
}

#[test]
fn authorization_details() {
    let code = "ABCDEF";
    let verifier = "ABCDEF12345";

    let request = token_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "client_id": CLIENT_ID,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": "https://example.com",
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
    });

    assert_snapshot!("authorization_details", &request);
}
