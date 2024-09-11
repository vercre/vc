#![allow(missing_docs)]

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_macros::credential_request;
// use vercre_openid::issuer::SendType;

#[test]
fn create_offer() {
    const CREDENTIAL_ISSUER: &str = "http://vercre.io";
    let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6Im9wZW5pZDR2Y...";

    let request = credential_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": "access_token",
        "credential_identifier": "PHLEmployeeID",
        "proof": {
            "proof_type": "jwt",
            "jwt": jwt
        }
    });

    assert_snapshot!("identifier-jwt", &request);
}
