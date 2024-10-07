//! End to end tests for issuer-initiated issuance flow that requires
//! authorization but where no grant types are specified on the offer and need
//! to be gained from OAuth server metadata.

use std::sync::LazyLock;

mod provider;

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_holder::issuance::{
    AcceptRequest, AuthorizeRequest, CredentialsRequest, Initiator, OfferRequest, SaveRequest,
};
use vercre_holder::provider::CredentialStorer;
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;
use vercre_test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, REDIRECT_URI};

use crate::provider as holder;

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(Some(ISSUER_PROVIDER.clone()), None));

// Test end-to-end issuer-initiated flow that requires authorization but where
// the grant types are not specified on the offer.
#[tokio::test]
async fn issuer_auth_no_grants() {
    // Use the issuance service endpoint to create a sample offer so we can get a
    // valid pre-authorized code.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "tx_code_required": false,
        "send_type": SendType::ByVal,
    });

    let offer_resp = vercre_issuer::create_offer(ISSUER_PROVIDER.clone(), request)
        .await
        .expect("should get offer");

    let OfferType::Object(offer) = offer_resp.offer_type else {
        panic!("expected CredentialOfferType::Object");
    };

    // Initiate the authorization code flow
    let offer_req = OfferRequest {
        client_id: CLIENT_ID.into(),
        subject_id: NORMAL_USER.into(),
        offer,
    };
    let issuance = vercre_holder::issuance::offer(HOLDER_PROVIDER.clone(), &offer_req)
        .await
        .expect("should process offer");

    assert_snapshot!("created", issuance, {
        ".issuance_id" => "[issuance_id]",
        ".grants.authorization_code.issuer_state" => "[issuer_state]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Accept all credentials on offer
    let accept_req = AcceptRequest {
        issuance_id: issuance.issuance_id.clone(),
        accept: None,
    };
    vercre_holder::issuance::accept(HOLDER_PROVIDER.clone(), &accept_req)
        .await
        .expect("should accept offer");

    // Making a token request should thow an error
    vercre_holder::issuance::token(HOLDER_PROVIDER.clone(), &issuance.issuance_id)
        .await
        .expect_err("should not accept token request");

    // Authorization request
    let auth_request = AuthorizeRequest {
        initiator: Initiator::Issuer {
            issuance_id: issuance.issuance_id.clone(),
        },
        redirect_uri: Some(REDIRECT_URI.into()), // Must match client registration.
        authorization_details: None,             /* None implies the wallet wants all offered
                                                  * credentials or is using scope. */
    };
    vercre_holder::issuance::authorize(HOLDER_PROVIDER.clone(), &auth_request)
        .await
        .expect("should authorize");

    // Get (and store) credentials. Accept all on offer.
    let cred_req = CredentialsRequest {
        issuance_id: issuance.issuance_id.clone(),
        ..Default::default()
    };
    vercre_holder::issuance::credentials(HOLDER_PROVIDER.clone(), &cred_req)
        .await
        .expect("should get credentials");
    vercre_holder::issuance::save(
        HOLDER_PROVIDER.clone(),
        &SaveRequest {
            issuance_id: issuance.issuance_id.clone(),
        },
    )
    .await
    .expect("should save credentials");

    let credentials = CredentialStorer::find(&HOLDER_PROVIDER.clone(), None)
        .await
        .expect("should retrieve all credentials");

    assert_eq!(credentials.len(), 1);

    assert_snapshot!("credentials", credentials, {
        "[].vc.issuanceDate" => "[issuanceDate]",
        "[].vc" => insta::sorted_redaction(),
        "[].vc.credentialSubject" => insta::sorted_redaction(),
        "[].metadata" => insta::sorted_redaction(),
        "[].metadata.credential_definition" => insta::sorted_redaction(),
        "[].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
        "[].metadata.credential_definition.credentialSubject.address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
    });
}
