//! Tests for issuer-initiated pre-authorized issuance flow where the holder
//! accepts all credentials and all claims on offer.
mod provider;

use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_holder::issuance::IssuanceState;
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;

use crate::provider as holder;

// Test end-to-end pre-authorized issuance flow (issuer-initiated), with
// acceptance of all credentials on offer.
#[tokio::test]
async fn preauth_2() {
    // Use the issuance service endpoint to create a sample offer that we can
    // use to start the flow.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
        "tx_code_required": true,
        "send_type": SendType::ByVal,
    });

    let issuer_provider = issuer::Provider::new();
    let offer_resp = vercre_issuer::create_offer(issuer_provider.clone(), request)
        .await
        .expect("should get offer");
    let OfferType::Object(offer) = offer_resp.offer_type else {
        panic!("expected CredentialOfferType::Object");
    };

    let provider = holder::Provider::new(Some(issuer_provider), None);

    // Initiate flow state.
    let mut state = IssuanceState::new(CLIENT_ID);

    // Add issuer metadata to flow state.
    let metadata_request = MetadataRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        languages: None,
    };
    let issuer_metadata =
        provider.metadata(metadata_request).await.expect("should get issuer metadata");
    state.issuer(issuer_metadata.credential_issuer).expect("should set issuer metadata");

    // Add authorization server metadata.
    let auth_request = OAuthServerRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        issuer: None,
    };
    let auth_metadata =
        provider.oauth_server(auth_request).await.expect("should get auth metadata");
    state
        .authorization_server(auth_metadata.authorization_server)
        .expect("should set authorization server metadata");

    // Process the offer.
    let offered = state.offer(CLIENT_ID, NORMAL_USER, &offer).expect("should process offer");

    // Present the offer to the holder for them to choose what to accept.
    insta::assert_yaml_snapshot!("offered", offered, {
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });
}
