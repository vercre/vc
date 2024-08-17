mod wallet;

use serde_json::json;
use vercre_issuer::CredentialOfferType;
use vercre_test_utils::issuer::{self, CREDENTIAL_ISSUER, PENDING_USER};

// static PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);

// Run through entire pre-authorized code flow.
#[tokio::test]
async fn deferred() {
    vercre_test_utils::init_tracer();
    let provider = issuer::Provider::new();

    // create offer
    let req_json = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": PENDING_USER,
        "pre-authorize": true,
        "tx_code_required": true
    });
    let request = serde_json::from_value(req_json).expect("should deserialize");
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    // send offer to wallet
    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        snapshot: "deferred".to_string(),
        provider: provider.clone(),
        tx_code: response.tx_code,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}
