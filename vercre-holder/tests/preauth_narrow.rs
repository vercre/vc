#![allow(missing_docs)]

mod provider;

use std::collections::HashMap;
use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
// use vercre_holder::provider::CredentialStorer;
use vercre_holder::{AcceptRequest, AuthorizationSpec, ClaimEntry, OfferRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

use crate::provider as holder;

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(Some(ISSUER_PROVIDER.clone()), None));

// Test end-to-end pre-authorized issuance flow, with acceptance of subset of
// credential configurations on offer, a subset of possible credential
// identifiers, and a subset of claims.
#[tokio::test]
async fn preauth_narrow() {
    // Use the issuance service endpoint to create a sample offer so we can get a
    // valid pre-authorized code.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT", "Developer_JWT"],
        "subject_id": NORMAL_USER,
        "pre_authorize": true,
        "tx_code_required": false, // no user PIN required
        "send_type": SendType::ByVal,
    });

    let offer_resp = vercre_issuer::create_offer(ISSUER_PROVIDER.clone(), request)
        .await
        .expect("should get offer");

    let OfferType::Object(offer) = offer_resp.offer_type else {
        panic!("expected CredentialOfferType::Object");
    };

    // Initiate the pre-authorized code flow
    let offer_req = OfferRequest {
        client_id: CLIENT_ID.into(),
        offer,
    };
    let issuance = vercre_holder::offer(HOLDER_PROVIDER.clone(), &offer_req)
        .await
        .expect("should process offer");

    assert_snapshot!("created", issuance, {
        ".issuance_id" => "[issuance_id]",
        ".offered" => insta::sorted_redaction(),
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
        ".offered.Developer_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Accept only the Developer credential on offer, and only the proficiency
    // claim.
    let accept_req = AcceptRequest {
        issuance_id: issuance.issuance_id.clone(),
        accept: Some(vec![AuthorizationSpec {
            credential_configuration_id: "Developer_JWT".into(),
            claims: Some(HashMap::from([("proficiency".to_string(), ClaimEntry::default())])),
        }]),
    };
    vercre_holder::accept(HOLDER_PROVIDER.clone(), &accept_req).await.expect("should accept offer");

    // Get available credential identifiers.
    let token_response = vercre_holder::token(HOLDER_PROVIDER.clone(), &issuance.issuance_id)
        .await
        .expect("should get token");

    // Check the token response has only the Developer credential and only the
    // proficiency claim.
    assert_snapshot!("token", token_response, {
        ".issuance_id" => "[issuance_id]",
        ".authorized" => insta::sorted_redaction(),
    });
}
