//! Pre-Authorized Code Flow Tests

mod wallet;

use std::fmt::Display;

use rstest::*;
use serde_json::json;
use vercre_issuer::CredentialOfferType;
use vercre_openid::CredentialFormat;
use vercre_test_utils::issuer::{self, Provider, CREDENTIAL_ISSUER, NORMAL_USER, PENDING_USER};

macro_rules! snapshot{
    ($($expr:expr),*) => {
        let mut settings = insta::Settings::clone_current();
        settings.set_snapshot_suffix(format!($($expr,)*));
        settings.set_prepend_module_to_snapshot(false);
        let _guard = settings.bind_to_scope();
    }
}

#[fixture]
fn provider() -> issuer::Provider {
    issuer::Provider::new()
}

/// Test immediate and deferred issuance variants
#[rstest]
#[case(Issuance::Immediate)]
#[case(Issuance::Deferred)]
async fn issuance(provider: Provider, #[case] issue: Issuance) {
    vercre_test_utils::init_tracer();
    snapshot!("{issue}");

    let subject_id = match issue {
        Issuance::Immediate => NORMAL_USER,
        Issuance::Deferred => PENDING_USER,
    };

    let req_json = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": subject_id,
        "pre-authorize": true,
        "tx_code_required": true
    });
    let request = serde_json::from_value(req_json).expect("should deserialize");

    // create offer
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    // send offer to wallet
    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        snapshot: "pre_authorized".to_string(),
        provider,
        tx_code: response.tx_code,
        format: CredentialFormat::JwtVcJson,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}

/// Test immediate and deferred issuance variants
#[rstest]
#[case(CredentialFormat::JwtVcJson)]
async fn format(provider: Provider, #[case] credential_format: CredentialFormat) {
    vercre_test_utils::init_tracer();
    snapshot!("{credential_format}");

    let req_json = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre-authorize": true,
        "tx_code_required": true
    });
    let request = serde_json::from_value(req_json).expect("should deserialize");

    // create offer
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    // send offer to wallet
    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        snapshot: "pre_authorized".to_string(),
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: credential_format,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}

/// Credential issuance variants
enum Issuance {
    Immediate,
    Deferred,
}

impl Display for Issuance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Issuance::Immediate => write!(f, "immediate"),
            Issuance::Deferred => write!(f, "deferred"),
        }
    }
}
