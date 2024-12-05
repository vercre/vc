//! Tests for issuer-initiated pre-authorized issuance flow where the holder
//! accepts all credentials and all claims on offer, and no grants are provided
//! in the offer.
mod provider;

use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, REDIRECT_URI};
use vercre_holder::issuance::{FlowType, IssuanceState};
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;

use crate::provider as holder;

// Test end-to-end pre-authorized issuance flow, with acceptance of all
// credentials on offer but where no grants are provided in the offer. This test
// is expected to fail issuance.
#[tokio::test]
async fn preauth_no_grants_2() {
    // Use the issuance service endpoint to create a sample offer that we can
    // use to start the flow. This is test set-up only - wallets do not ask an
    // issuer for an offer. Usually this code is internal to an issuer service.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
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
    // Initiate flow state. If no grants are provided in the offer, we need
    // to initialize the flow with `FlowType::IssuerAuthorized`. We use a
    // pre-authorized flow type deliberately here to test that the flow will
    // fail.
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
        .authorization_server(auth_metadata.authorization_server.clone())
        .expect("should set authorization server metadata");

    //--------------------------------------------------------------------------
    // Unpack the offer.
    //--------------------------------------------------------------------------
    let offered = state.offer(&offer).expect("should process offer");

    //--------------------------------------------------------------------------
    // Present the offer to the holder for them to choose what to accept.
    //--------------------------------------------------------------------------
    insta::assert_yaml_snapshot!("offered", offered, {
        "." => insta::sorted_redaction(),
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Accept all credentials and claims on offer
    state.accept(&None).expect("should accept offer");

    //--------------------------------------------------------------------------
    // No need to enter a PIN as we did not require one when creating the offer.
    //--------------------------------------------------------------------------
    //--------------------------------------------------------------------------
    // Constructing a token request should fail as no grants were provided in
    // the offer.
    //--------------------------------------------------------------------------
    state.token_request(None, None).expect_err("should fail to construct a token request");

    //--------------------------------------------------------------------------
    // Construct an authorization request should fail since we have set the wrong
    // flow type.
    //--------------------------------------------------------------------------
    state
        .authorization_request(Some(REDIRECT_URI))
        .expect_err("should fail to construct an authorization request");

    //--------------------------------------------------------------------------
    // Let's just hack the flow type and make sure we get an authorization
    // request. For a real implementation do this on `IssuanceState::new`
    // instead (see above).
    //--------------------------------------------------------------------------
    state.flow_type = FlowType::IssuerAuthorized;
    let auth_request = state
        .authorization_request(Some(REDIRECT_URI))
        .expect("should construct an authorization request");
    insta::assert_yaml_snapshot!("auth_request", auth_request, {
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
        ".code_challenge" => "[code_challenge]",
        ".state" => "[state]",
        ".user_hint" => "[user_hint]",
    });

    // etc... The rest of the flow is tested in `issuer_auth` and
    // `holder_auth` tests so no need to repeat here.
}
