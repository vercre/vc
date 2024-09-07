use vercre_macros::create_offer;
use vercre_openid::issuer::{CreateOfferRequest, SendType};

#[test]
fn create_offer() {
    // const CREDENTIAL_ISSUER: &str = "http://vercre.io";

    let x = create_offer!({
        "credential_issuer":  "http://vercre.io",
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": "normal_user",
        "pre-authorize": true,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });

    println!("{:?}", x);
}
