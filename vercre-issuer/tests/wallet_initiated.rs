//! Wallet-initiated Tests

mod utils;
mod wallet;

use rstest::rstest;
use utils::{provider, Issuance};
use vercre_openid::issuer::{Format, ProfileW3c};
use test_utils::issuer::Provider;
use test_utils::snapshot;

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
