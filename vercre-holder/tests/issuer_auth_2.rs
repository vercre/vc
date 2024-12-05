//! End to end tests for issuer-initiated issuance flow that requires
//! authorization.
mod provider;

use insta::assert_yaml_snapshot;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, REDIRECT_URI};
use vercre_holder::issuance::{CredentialRequestType, FlowType, IssuanceState};
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_infosec::jose::{jws, Type};
use vercre_issuer::{CredentialResponseType, OfferType, SendType};
use vercre_macros::create_offer_request;
use vercre_w3c_vc::proof::{Payload, Verify};

use crate::provider as holder;

// Test end-to-end issuer-initiated flow that requires authorization.
#[tokio::test]
async fn issuer_auth_2() {
    // Use the issuance service endpoint to create a sample offer that we can
    // use to start the flow. This is test set-up only - wallets do not ask an
    // issuer for an offer. Usually this code is internal to an issuer service.
    // We include the requirement for a PIN.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": NORMAL_USER,
        "grant_types": ["authorization_code"],
        "tx_code_required": false, // Leave out PIN for this test
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
    // Initiate flow state. A wallet should check the offer grants and use the
    // appropriate flow type.
    //--------------------------------------------------------------------------

    let grants = offer.grants.clone().unwrap();
    grants.authorization_code.unwrap();
    let mut state = IssuanceState::new(FlowType::IssuerAuthorized, CLIENT_ID, NORMAL_USER);

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
        "." => insta::sorted_redaction(),
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Accept all credentials and all claims on offer.
    state.accept(&None).expect("should accept offer");

    //--------------------------------------------------------------------------
    // Get an authorization code. The redirect URI must match one registered
    // with the issuer on client registration.
    //--------------------------------------------------------------------------
    let auth_request =
        state.authorization_request(Some(REDIRECT_URI)).expect("should get auth request");
    // We should have code challenge and verifier populated on state
    assert!(state.code_challenge.is_some());
    assert!(state.code_verifier.is_some());

    let auth_response = provider.authorization(auth_request).await.expect("should authorize");

    //--------------------------------------------------------------------------
    // Exchange the authorization code for a token.
    //--------------------------------------------------------------------------
    let token_request = state
        .token_request(Some(REDIRECT_URI), Some(&auth_response.code))
        .expect("should get token request");
    let token_response = provider.token(token_request).await.expect("should get token response");
    state.token(&token_response).expect("should stash token");

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
    let jws = state.proof().expect("should get proof");
    let jwt = jws::encode(Type::Openid4VciProofJwt, &jws, &provider)
        .await
        .expect("should encode proof claims");
    let credential_requests = state
        .credential_requests(CredentialRequestType::CredentialIdentifiers(identifiers), &jwt)
        .expect("should construct credential requests");
    for request in credential_requests {
        let credential_response =
            provider.credential(request.1).await.expect("should get credentials");
        // A credential response could contain a single credential, multiple
        // credentials or a deferred transaction ID. Any credential issued also
        // needs its proof verified by using a DID resolver.
        match credential_response.response {
            CredentialResponseType::Credential(vc_kind) => {
                // Single credential in response.
                let Payload::Vc { vc, issued_at } =
                    vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                        .await
                        .expect("should parse credential")
                else {
                    panic!("expected Payload::Vc");
                };
                state
                    .add_credential(&vc, &vc_kind, &issued_at, &request.0)
                    .expect("should add credential");
            }
            CredentialResponseType::Credentials(creds) => {
                // Multiple credentials in response.
                for vc_kind in creds {
                    let Payload::Vc { vc, issued_at } =
                        vercre_w3c_vc::proof::verify(Verify::Vc(&vc_kind), provider.clone())
                            .await
                            .expect("should parse credential")
                    else {
                        panic!("expected Payload::Vc");
                    };
                    state
                        .add_credential(&vc, &vc_kind, &issued_at, &request.0)
                        .expect("should add credential");
                }
            }
            CredentialResponseType::TransactionId(tx_id) => {
                // Deferred transaction ID.
                state.add_deferred(&tx_id, &request.0);
            }
        }
    }

    // The flow is complete and the credential on the issuance state could now
    // be saved to the wallet using the `CredentialStorer` provider trait. For
    // the test we check snapshot of the state's credentials.
    assert_yaml_snapshot!("credentials", state.credentials, {
        "[].type" => insta::sorted_redaction(),
        "[].subject_claims[]" => insta::sorted_redaction(),
        "[].subject_claims[].claims" => insta::sorted_redaction(),
        "[].subject_claims[].claims.address" => insta::sorted_redaction(),
        "[].claim_definitions" => insta::sorted_redaction(),
        "[].claim_definitions.address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
        "[].issuance_date" => "[issuance_date]",
    });
}
