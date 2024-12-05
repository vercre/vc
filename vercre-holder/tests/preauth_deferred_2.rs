//! Tests for issuer-initiated pre-authorized issuance flow where the holder
//! accepts all credentials and all claims on offer but the issuance is
//! deferred.
mod provider;

use insta::assert_yaml_snapshot;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, PENDING_USER};
use vercre_holder::issuance::{CredentialRequestType, FlowType, IssuanceState};
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_infosec::jose::{jws, Type};
use vercre_issuer::{CredentialResponseType, OfferType, SendType};
use vercre_macros::create_offer_request;
use vercre_w3c_vc::proof::{Payload, Verify};

use crate::provider as holder;

// Test end-to-end pre-authorized issuance flow (issuer-initiated), with
// acceptance of all credentials on offer.
#[tokio::test]
async fn preauth_deferred_2() {
    // Use the issuance service endpoint to create a sample offer that we can
    // use to start the flow. This is test set-up only - wallets do not ask an
    // issuer for an offer. Usually this code is internal to an issuer service.
    let request = create_offer_request!({
        "credential_issuer": CREDENTIAL_ISSUER,
        "credential_configuration_ids": ["EmployeeID_JWT"],
        "subject_id": PENDING_USER,
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
    let mut state = IssuanceState::new(FlowType::IssuerPreAuthorized, CLIENT_ID, PENDING_USER);

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
    let token_request = state.token_request(None, None).expect("should get token request");
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

    // Because we used the test subject ID, PENDING_USER, the issuance should
    // have been deferred.
    assert_eq!(state.deferred.len(), 1);
    assert_eq!(state.credentials.len(), 0);

    //--------------------------------------------------------------------------
    // Process deferred transaction.
    //--------------------------------------------------------------------------
    for (tx_id, cfg_id) in state.deferred.clone() {
        let deferred_request =
            state.deferred_request(&tx_id).expect("should construct deferred credential request");
        let deferred_response = provider
            .deferred(deferred_request)
            .await
            .expect("issuer should process deferred request");
        match deferred_response.credential_response.response {
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
                    .add_credential(&vc, &vc_kind, &issued_at, &cfg_id)
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
                        .add_credential(&vc, &vc_kind, &issued_at, &cfg_id)
                        .expect("should add credential");
                }
            }
            CredentialResponseType::TransactionId(tx_id) => {
                // Deferred transaction ID (assumes we get a new one)
                state.add_deferred(&tx_id, &cfg_id);
            }
        }
        state.remove_deferred(&tx_id);
    }

    // Check the deferred transaction has been "used" and the credentials saved.
    assert_eq!(state.deferred.len(), 0);
    assert_eq!(state.credentials.len(), 1);

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
