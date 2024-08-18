//! Authorization Code Flow Tests

mod utils;
mod wallet;

use rstest::rstest;
use vercre_openid::CredentialFormat;
use vercre_test_utils::issuer;

#[rstest]
async fn authorization() {
    vercre_test_utils::init_tracer();
    snapshot!("authorization");

    let wallet = wallet::Wallet {
        provider: issuer::Provider::new(),
        format: CredentialFormat::JwtVcJson,
        ..Default::default()
    };

    wallet.self_initiated().await.expect("should get credential");
}
