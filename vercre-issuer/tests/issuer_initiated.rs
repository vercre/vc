//! Issuer-initiated Tests

mod utils;
mod wallet;

use rstest::rstest;
use utils::{provider, Issuance};
use vercre_issuer::{CreateOfferRequest, CredentialOfferType};
use vercre_openid::CredentialFormat;
use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER, PENDING_USER};

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

    let request = CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
        subject_id: Some(subject_id.to_string()),
        pre_authorize: true,
        tx_code_required: true,
    };
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        provider,
        tx_code: response.tx_code,
        format: CredentialFormat::JwtVcJson,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}

/// Credential format variants
#[rstest]
#[case(CredentialFormat::JwtVcJson)]
async fn format(provider: Provider, #[case] credential_format: CredentialFormat) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:{credential_format}");

    let request = CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
        subject_id: Some(NORMAL_USER.to_string()),
        pre_authorize: true,
        tx_code_required: true,
    };
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: credential_format,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}

#[rstest]
async fn authorization(provider: Provider) {
    vercre_test_utils::init_tracer();
    snapshot!("issuer:authorization");

    let request = CreateOfferRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
        subject_id: Some(NORMAL_USER.to_string()),
        pre_authorize: false,
        tx_code_required: true,
    };
    let response =
        vercre_issuer::create_offer(provider.clone(), &request).await.expect("should create offer");

    let CredentialOfferType::Object(offer) = response.credential_offer else {
        panic!("offer should be an object");
    };

    let wallet = wallet::Wallet {
        provider: provider.clone(),
        tx_code: response.tx_code,
        format: CredentialFormat::JwtVcJson,
    };

    wallet.issuer_initiated(offer).await.expect("should get credential");
}
