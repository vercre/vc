use assert_let_bind::assert_let;
use insta::assert_yaml_snapshot as assert_snapshot;
use providers::issuance::{Provider as IssuanceProvider, Provider, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_core::vci::CreateOfferRequest;

// This tests the entire issuance flow end-to-end. See the issuance module for stepwise tests.
#[tokio::test]
async fn issuance_steps() {
    let _provider = Provider::new();

    // Use the issuance endpoint to construct an issuance offer that we can present to the
    // wallet.
    let create_offer_request = CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        credential_configuration_ids: vec!["EmployeeID_JWT".into()],
        holder_id: Some(NORMAL_USER.into()),
        pre_authorize: true,
        tx_code_required: true,
        callback_id: Some("1234".into()),
    };

    let issuance_provider = IssuanceProvider::new();
    let create_offer_response = vercre_issuer::Endpoint::new(issuance_provider)
        .create_offer(&create_offer_request)
        .await
        .expect("issuance endpoint should create offer");
    assert_snapshot!("create_offer", &create_offer_response, {
        ".credential_offer.grants.authorization_code.issuer_state" => "[state]",
        ".credential_offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".user_code" => "[user_code]"
    });
    let offer = create_offer_response
        .credential_offer
        .expect("create offer response should include credential offer");

    // check redacted fields
    assert_let!(Some(grants), &offer.grants);
    assert!(grants.pre_authorized_code.is_some());
}
