mod wallet;

use vercre_test_utils::issuer;

// Run through entire authorization code flow.
#[tokio::test]
async fn authorization() {
    vercre_test_utils::init_tracer();

    let wallet = wallet::Wallet {
        snapshot: "authorization".to_string(),
        provider: issuer::Provider::new(),
        tx_code: None,
    };

    wallet.self_initiated().await.expect("should get credential");
}
