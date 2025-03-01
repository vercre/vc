//! Tests for `create_offer` endpoint.

mod utils;

use assert_let_bind::assert_let;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::{Stage, State};
use credibil_vc::oid4vci::types::{OfferType, SendType};
use credibil_vc::oid4vci::{self, CreateOfferRequest};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_issuer::{CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn pre_authorized() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    // create offer to 'send' to the app
    let value = json!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });
    let request: CreateOfferRequest = serde_json::from_value(value).expect("request is valid");
    let response = oid4vci::endpoint::handle(CREDENTIAL_ISSUER, request, &provider)
        .await
        .expect("response is ok");

    assert_snapshot!("create_offer:pre-authorized:response", &response, {
        ".credential_offer.grants.authorization_code.issuer_state" => "[state]",
        ".credential_offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
        ".tx_code" => "[tx_code]"
    });

    // check redacted fields
    let OfferType::Object(offer) = response.offer_type else {
        panic!("expected CredentialOfferType::Object");
    };
    assert_let!(Some(grants), &offer.grants);
    assert_let!(Some(pre_auth_code), &grants.pre_authorized_code);
    assert!(grants.pre_authorized_code.is_some());

    // compare response with saved state
    let pre_auth_code = &pre_auth_code.pre_authorized_code; //as_ref().expect("has state");
    let state = StateStore::get::<State>(&provider, pre_auth_code).await.expect("state exists");

    assert_snapshot!("create_offer:pre-authorized:state", &state, {
        ".expires_at" => "[expires_at]",
        ".stage.tx_code" => "[tx_code]"
    });

    assert_let!(Stage::Offered(auth_state), &state.stage);
    assert_eq!(auth_state.tx_code, response.tx_code);
}
