//! Pre-Authorized Code Flow

mod utils;
mod wallet;

use credibil_vc::oid4vci::{CreateOfferRequest, Format, ProfileW3c, SendType, endpoint};
use serde_json::json;
use test_issuer::{CREDENTIAL_ISSUER, NORMAL_USER, PENDING_USER, ProviderImpl};

#[tokio::test]
async fn offer() {
    let provider = ProviderImpl::new();

    let value = json! ({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response =
        endpoint::handle(CREDENTIAL_ISSUER, request, &provider).await.expect("should create offer");

    let wallet = wallet::Wallet {
        provider,
        tx_code: response.tx_code,
        format: Format::JwtVcJson(ProfileW3c::default()),
    };

    wallet.issuer_initiated(response.offer_type).await.expect("should get credential");
}
