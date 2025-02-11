#![allow(missing_docs)]

use insta::assert_yaml_snapshot as assert_snapshot;
use credibil_vc::issuer::SendType;
use macros::create_offer_request;

const CREDENTIAL_ISSUER: &str = "http://vercre.io";

#[test]
fn pre_authorized() {
    let subject_id = "normal_user";

    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": &subject_id,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
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
