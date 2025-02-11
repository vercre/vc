//! Wallet-initiated Tests

mod utils;
mod wallet;

use credibil_vc::issuer::{Format, ProfileW3c};
use credibil_vc::test_utils::issuer::Provider;
use credibil_vc::{snapshot, test_utils};
use rstest::rstest;
use utils::{provider, Issuance};

#[rstest]
#[case(Issuance::Immediate)]
#[case(Issuance::Deferred)]
async fn issuance(provider: Provider, #[case] issue: Issuance) {
    test_utils::init_tracer();
    snapshot!("wallet:{issue}");

    let wallet = wallet::Wallet {
        provider,
        format: Format::JwtVcJson(ProfileW3c::default()),
        ..Default::default()
    };

    wallet.self_initiated().await.expect("should get credential");
}
