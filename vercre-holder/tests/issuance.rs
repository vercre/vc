mod test_provider;

use std::sync::LazyLock;

//use insta::assert_yaml_snapshot as assert_snapshot;
use providers::issuance::{CREDENTIAL_ISSUER, NORMAL_USER};
use test_provider::TestProvider;
use vercre_issuer::create_offer::CreateOfferRequest;

static PROVIDER: LazyLock<TestProvider> = LazyLock::new(|| TestProvider::new());

fn sample_offer_request() -> CreateOfferRequest {
    CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        credential_configuration_ids: vec!["EmployeeID_JWT".into()],
        holder_id: Some(NORMAL_USER.into()),
        pre_authorize: true,
        tx_code_required: true,
        callback_id: Some("1234".into()),
    }
}

#[tokio::test]
async fn e2e_test() {
    // Use the issuance service endpoint to create a sample offer so that we can get a valid
    // pre-auhorized code.
    let _offer = vercre_issuer::Endpoint::new(PROVIDER.clone())
        .create_offer(&sample_offer_request())
        .await
        .expect("should get offer");
}
