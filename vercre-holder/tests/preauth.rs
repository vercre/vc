#![allow(missing_docs)]

mod provider;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_holder::provider::CredentialStorer;
use vercre_holder::{AcceptRequest, CredentialsRequest, OfferRequest, PinRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

use crate::provider as holder;

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(Some(ISSUER_PROVIDER.clone()), None));

// Test end-to-end pre-authorized issuance flow, with acceptance of all
// credentials on offer.
#[tokio::test]
async fn preauth() {
    // Use the issuance service endpoint to create a sample offer so we can get a
    // valid pre-authorized code.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "pre_authorize": true,
        "tx_code_required": true,
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
        ".offered.EmployeeID_JWT.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Accept all credentials on offer
    let accept_req = AcceptRequest {
        issuance_id: issuance.issuance_id.clone(),
        accept: None,
    };
    vercre_holder::accept(HOLDER_PROVIDER.clone(), &accept_req).await.expect("should accept offer");

    // Enter PIN
    let pin_req = PinRequest {
        issuance_id: issuance.issuance_id.clone(),
        pin: offer_resp.tx_code.expect("should have user code"),
    };
    vercre_holder::pin(HOLDER_PROVIDER.clone(), &pin_req).await.expect("should apply pin");

    // Get available credential identifiers.
    vercre_holder::token(HOLDER_PROVIDER.clone(), &issuance.issuance_id)
        .await
        .expect("should get token");

    // Get (and store) credentials. Accept all on offer.
    let cred_req = CredentialsRequest {
        issuance_id: issuance.issuance_id.clone(),
        credential_identifiers: None,
    };
    vercre_holder::credentials(HOLDER_PROVIDER.clone(), &cred_req)
        .await
        .expect("should get credentials");

    let credentials = CredentialStorer::find(&HOLDER_PROVIDER.clone(), None)
        .await
        .expect("should retrieve all credentials");

    assert_eq!(credentials.len(), 1);

    assert_snapshot!("credentials", credentials, {
        "[0].vc.issuanceDate" => "[issuanceDate]",
        "[0].vc" => insta::sorted_redaction(),
        "[0].vc.credentialSubject" => insta::sorted_redaction(),
        "[0].metadata" => insta::sorted_redaction(),
        "[0].metadata.credential_definition" => insta::sorted_redaction(),
        "[0].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
        "[0].issued" => "[issued]",
    });
}