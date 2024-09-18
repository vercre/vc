#![allow(missing_docs)]

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_macros::credential_request;

const CREDENTIAL_ISSUER: &str = "http://vercre.io";

#[test]
fn identifier() {
    let access_token = "AVCDEF12345";
    let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6Im9wZW5pZDR2Y...";
    let credential_identifier = "PHLEmployeeID";

    let request = credential_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": access_token,
        "credential_identifier": credential_identifier,
        "proof": {
            "proof_type": "jwt",
            "jwt": jwt
        }
    });

    assert_snapshot!("identifier-jwt", &request);
}

#[test]
fn format() {
    let access_token = "AVCDEF12345";
    let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6Im9wZW5pZDR2Y...";

    let request = credential_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "access_token": access_token,
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
    assert_snapshot!("format-jwt", &request);
}
