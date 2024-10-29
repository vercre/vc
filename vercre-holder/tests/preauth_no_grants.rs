//! Tests for issuer-initiated pre-authorized issuance flow where the holder
//! accepts all credentials and all claims on offer, and no grants are provided
//! in the offer.

mod provider;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, REDIRECT_URI};
use vercre_holder::issuance::{
    AcceptRequest, AuthorizeRequest, CredentialsRequest, Initiator, OfferRequest, SaveRequest,
};
use vercre_holder::provider::{CredentialStorer, Issuer};
use vercre_holder::{GrantType, OAuthServerRequest};
use vercre_issuer::{OfferType, SendType};
use vercre_macros::create_offer_request;

use crate::provider as holder;

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(Some(ISSUER_PROVIDER.clone()), None));

// Test end-to-end pre-authorized issuance flow, with acceptance of all
// credentials on offer.
#[tokio::test]
async fn preauth_no_grants() {
    // Use the issuance service endpoint to create a sample offer so we can get a
    // valid pre-authorized code.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
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
        subject_id: NORMAL_USER.into(),
        offer,
    };
    let issuance = vercre_holder::issuance::offer(HOLDER_PROVIDER.clone(), &offer_req)
        .await
        .expect("should process offer");

    assert_snapshot!("created", issuance, {
        ".issuance_id" => "[issuance_id]",
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

    // If there are no grants, the wallet will need to authorize before getting
    // a token, so a direct token request should fail.
    vercre_holder::issuance::token(HOLDER_PROVIDER.clone(), &issuance.issuance_id)
        .await
        .expect_err("should fail to get token");

    // Instead, the wallet should check the issuer's OAuth server metadata to
    // see if it supports authorization, then make a request to authorize.
    let oauth_metadata_req = OAuthServerRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        issuer: None,
    };
    let provider = HOLDER_PROVIDER.clone();
    let server = Issuer::oauth_server(&provider, oauth_metadata_req)
        .await
        .expect("should get oauth servier metadata");
    let supported_grants = server
        .authorization_server
        .oauth
        .grant_types_supported
        .expect("should have supported grants");
    assert!(supported_grants.contains(&GrantType::AuthorizationCode));

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
        "[].type" => insta::sorted_redaction(),
        "[].claims[]" => insta::sorted_redaction(),
        "[].claims[].address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
        "[].issuance_date" => "[issuance_date]",
    });
}
