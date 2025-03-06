//! Pre-Authorized Code Flow

mod utils;

use chrono::Utc;
use credibil_infosec::jose::JwsBuilder;
use credibil_vc::oid4vci::client::{
    CreateOfferRequestBuilder, CredentialRequestBuilder, TokenRequestBuilder,
};
use credibil_vc::oid4vci::endpoint;
use credibil_vc::oid4vci::proof::{self, Payload, Type, Verify};
use credibil_vc::oid4vci::types::{Credential, ProofClaims, ResponseType, TokenGrantType};
use insta::assert_yaml_snapshot as assert_snapshot;
use test_issuer::{
    CLIENT_ID as BOB_CLIENT, CREDENTIAL_ISSUER as ALICE_ISSUER, NORMAL_USER, ProviderImpl,
};

#[tokio::test]
async fn offer_byval() {
    let provider = ProviderImpl::new();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let offer_request = CreateOfferRequestBuilder::new()
        .subject_id(NORMAL_USER)
        .with_credential("EmployeeID_JWT")
        .build();
    let offer_response =
        endpoint::handle(ALICE_ISSUER, offer_request, &provider).await.expect("creates offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = offer_response.offer_type.as_object().expect("has offer object").clone();
    let grants = offer.grants.expect("has grants");
    let pre_auth_grant = grants.pre_authorized_code.expect("has pre-authorized code grant");

    let token_request = TokenRequestBuilder::new()
        .client_id(BOB_CLIENT)
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_grant.pre_authorized_code,
            tx_code: offer_response.tx_code.clone(),
        })
        .build();
    let token_response =
        endpoint::handle(ALICE_ISSUER, token_request, &provider).await.expect("returns token");

    // --------------------------------------------------
    // Bob receives the token and requests a credential
    // --------------------------------------------------
    let claims = ProofClaims {
        iss: Some(BOB_CLIENT.to_string()),
        aud: ALICE_ISSUER.to_string(),
        iat: Utc::now().timestamp(),
        nonce: Some("token_resp.c_nonce".to_string()),
    };
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(claims)
        .add_signer(&test_holder::ProviderImpl)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    let details = &token_response.authorization_details.expect("has authorization details");
    let credential_identifier = &details[0].credential_identifiers[0];
    let access_token = &token_response.access_token;

    let request = CredentialRequestBuilder::new()
        .credential_identifier(credential_identifier)
        .with_proof(jwt)
        .access_token(access_token)
        .build();
    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("returns credential");

    // extract issued credential
    let ResponseType::Credentials { credentials, .. } = &response.response else {
        panic!("expected single credential");
    };
    let Credential { credential } = credentials.first().expect("should have credential");

    // FIXME: verify signature

    // verify the credential is as expected
    let Ok(Payload::Vc { vc, .. }) = proof::verify(Verify::Vc(credential), provider.clone()).await
    else {
        panic!("should be VC");
    };

    assert_snapshot!("credential", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction()
    });
}
