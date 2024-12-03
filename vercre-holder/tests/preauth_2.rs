//! Tests for issuer-initiated pre-authorized issuance flow where the holder
//! accepts all credentials and all claims on offer.
mod provider;

use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
use vercre_holder::issuance::{CredentialRequestType, FlowType, IssuanceState};
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;

use crate::provider as holder;

// Test end-to-end pre-authorized issuance flow (issuer-initiated), with
// acceptance of all credentials on offer.
#[tokio::test]
async fn preauth_2() {
    // Use the issuance service endpoint to create a sample offer that we can
    // use to start the flow. Include PIN.
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

    //--------------------------------------------------------------------------
    // Initiate flow state.
    //--------------------------------------------------------------------------
    let mut state = IssuanceState::new(FlowType::IssuerPreAuthorized, CLIENT_ID, NORMAL_USER);

    //--------------------------------------------------------------------------
    // Add issuer metadata to flow state.
    //--------------------------------------------------------------------------
    let metadata_request = MetadataRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        languages: None,
    };
    let issuer_metadata =
        provider.metadata(metadata_request).await.expect("should get issuer metadata");
    state.issuer(issuer_metadata.credential_issuer).expect("should set issuer metadata");

    //--------------------------------------------------------------------------
    // Add authorization server metadata.
    //--------------------------------------------------------------------------
    let auth_request = OAuthServerRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        issuer: None,
    };
    let auth_metadata =
        provider.oauth_server(auth_request).await.expect("should get auth metadata");
    state
        .authorization_server(auth_metadata.authorization_server)
        .expect("should set authorization server metadata");

    //--------------------------------------------------------------------------
    // Unpack the offer.
    //--------------------------------------------------------------------------
    let offered = state.offer(&offer).expect("should process offer");

    //--------------------------------------------------------------------------
    // Present the offer to the holder for them to choose what to accept.
    //--------------------------------------------------------------------------
    insta::assert_yaml_snapshot!("offered", offered, {
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Accept all credentials on offer.
    state.accept(&None).expect("should accept offer");

    //--------------------------------------------------------------------------
    // Enter a PIN.
    //--------------------------------------------------------------------------
    // Cheat by getting the PIN from the offer response on the call to the
    // issuance crate to create the offer. In a real-world scenario, the holder
    // would be sent the offer on this main channel and the PIN on a separate
    // channel.
    let pin = offer_resp.tx_code.expect("should have user code");
    state.pin(&pin).expect("should apply pin");

    //--------------------------------------------------------------------------
    // Request an access token from the issuer.
    //--------------------------------------------------------------------------
    let token_request = state.token_request().expect("should get token request");
    let token_response = provider.token(token_request).await.expect("should get token response");
    state.token(&token_response).expect("should get token");

    //--------------------------------------------------------------------------
    // Make credential requests.
    //--------------------------------------------------------------------------
    // For this test we are going to accept all credentials on offer. (Just one
    // in this case but we demonstate the pattern for multiple credentials.) We
    // are making the request by credential identifier.
    let Some(authorized) = &token_response.authorization_details else {
        panic!("no authorization details in token response");
    };
    let mut identifiers = vec![];
    for auth in authorized {
        for id in auth.credential_identifiers.iter() {
            identifiers.push(id.clone());
        }
    }
    let _credential_requests = state
        .credential_requests(CredentialRequestType::CredentialIdentifiers(identifiers), provider)
        .await
        .expect("should construct credential requests");
}
