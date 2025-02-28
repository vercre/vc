//! Test the `credential_offer` endpoint.

use credibil_vc::issuer::{self, CredentialOfferRequest};
use credibil_vc::openid::issuer::{CreateOfferRequest, OfferType, SendType};
use credibil_vc::openid::oauth::GrantType;
use credibil_vc::snapshot;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_issuer::{CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn request_jwt() {
    // test_utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let create_req = CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
        subject_id: Some(NORMAL_USER.to_string()),
        grant_types: Some(vec![GrantType::PreAuthorizedCode]),
        tx_code_required: true,
        send_type: SendType::ByRef,
    };
    let create_resp =
        issuer::create_offer(provider.clone(), create_req).await.expect("should create offer");

    let OfferType::Uri(uri) = create_resp.offer_type else {
        panic!("no URI found in response");
    };
    let Some(id) = uri.strip_prefix(&format!("{CREDENTIAL_ISSUER}/credential_offer/")) else {
        panic!("should have prefix");
    };

    let offer_req = CredentialOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        id: id.to_string(),
    };
    let offer_resp =
        issuer::credential_offer(provider, offer_req).await.expect("response is valid");

    assert_snapshot!("credential_offer:request_jwt:response", offer_resp,  {
        // ".credential_offer.grants.authorization_code.issuer_state" => "[issuer_state]",
        r#".**["pre-authorized_code"]"# => "[pre-authorized_code]",
    });
}
