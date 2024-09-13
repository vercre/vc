#![allow(missing_docs)]

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_macros::create_offer_request;
use vercre_openid::issuer::SendType;

const CREDENTIAL_ISSUER: &str = "http://vercre.io";

#[test]
fn pre_authorized() {
    let subject_id = "normal_user";

    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": subject_id,
        "pre_authorize": true,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });

    assert_snapshot!("pre-authorized", &request);
}

#[test]
fn default() {
    let request = create_offer_request!({
        "credential_issuer": "http://vercre.io",
        "credential_configuration_ids": ["EmployeeID_JWT"],
    });

    assert_snapshot!("default", &request);
}
