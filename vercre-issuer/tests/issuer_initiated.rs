#![allow(missing_docs)]

//! Issuer-initiated Tests

mod utils;
mod wallet;

use rstest::rstest;
use serde_json::json;
use utils::{provider, Issuance};
use vercre_issuer::SendType;
use vercre_openid::issuer::{FormatIdentifier, ProfileW3c};
use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER, PENDING_USER};
use vercre_test_utils::snapshot;

/// Immediate and deferred issuance variants
#[rstest]
#[case(Issuance::Immediate)]
#[case(Issuance::Deferred)]
async fn issuance(provider: Provider, #[case] issue: Issuance) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:{issue}");

    let subject_id = match issue {
        Issuance::Immediate => NORMAL_USER,
        Issuance::Deferred => PENDING_USER,
    };

    let value = json! ({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": subject_id,
        "pre-authorize": true,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request = serde_json::from_value(value).expect("request is valid");
    let response =
        vercre_issuer::create_offer(provider.clone(), request).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider,
        tx_code: response.tx_code,
        format: FormatIdentifier::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

/// Credential format variants
#[rstest]
#[case(FormatIdentifier::JwtVcJson(ProfileW3c::default()))]
async fn format(provider: Provider, #[case] credential_format: FormatIdentifier) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:{credential_format}");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre-authorize": true,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request = serde_json::from_value(value).expect("request is valid");
    let response =
        vercre_issuer::create_offer(provider.clone(), request).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: credential_format,
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

// Authorization Code flow
#[rstest]
async fn authorization(provider: Provider) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:authorization");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre-authorize": false,
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request = serde_json::from_value(value).expect("request is valid");
    let response =
        vercre_issuer::create_offer(provider.clone(), request).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: FormatIdentifier::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}

// Send Credential Offer ByRef and ByVal
#[rstest]
#[case(SendType::ByRef)]
#[case(SendType::ByVal)]
async fn offer_type(provider: Provider, #[case] send_type: SendType) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:authorization:{send_type:?}");

    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre-authorize": true,
        "tx_code_required": true,
        "send_type": send_type,
    });
    let request = serde_json::from_value(value).expect("request is valid");
    let response =
        vercre_issuer::create_offer(provider.clone(), request).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: FormatIdentifier::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}
