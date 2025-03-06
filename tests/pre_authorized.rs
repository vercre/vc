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

// Should return a credential when using the pre-authorized code flow and the
// credential offer to the allet is made by value.
#[tokio::test]
async fn offer_by_val() {
    let provider = ProviderImpl::new();

    // --------------------------------------------------
    // Alice creates a credential offer for Bob
    // --------------------------------------------------
    let request = CreateOfferRequestBuilder::new()
        .subject_id(NORMAL_USER)
        .with_credential("EmployeeID_JWT")
        .build();
    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should create offer");

    // --------------------------------------------------
    // Bob receives the offer and requests a token
    // --------------------------------------------------
    let offer = response.offer_type.as_object().expect("should have offer").clone();
    let grants = offer.grants.expect("should have grant");
    let pre_auth_grant = grants.pre_authorized_code.expect("should have pre-authorized code grant");

    let request = TokenRequestBuilder::new()
        .client_id(BOB_CLIENT)
        .grant_type(TokenGrantType::PreAuthorizedCode {
            pre_authorized_code: pre_auth_grant.pre_authorized_code,
            tx_code: response.tx_code.clone(),
        })
        .build();
    let token =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return token");

    // --------------------------------------------------
    // Bob receives the token and requests a credential
    // --------------------------------------------------
    // proof of possession of key material
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(ProofClaims {
            iss: Some(BOB_CLIENT.to_string()),
            aud: ALICE_ISSUER.to_string(),
            iat: Utc::now().timestamp(),
            // FIXME: get nonce from Nonce endpoint
            // FIXME: validate nonce in Token endpoint
            nonce: Some("token_resp.c_nonce".to_string()),
        })
        .add_signer(&test_holder::ProviderImpl)
        .build()
        .await
        .expect("builds JWS");
    let jwt = jws.encode().expect("encodes JWS");

    // credential identifier
    let details = &token.authorization_details.expect("should have authorization details");
    let credential_identifier = &details[0].credential_identifiers[0];

    let request = CredentialRequestBuilder::new()
        .credential_identifier(credential_identifier)
        .with_proof(jwt)
        .access_token(token.access_token)
        .build();
    let response =
        endpoint::handle(ALICE_ISSUER, request, &provider).await.expect("should return credential");

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

    assert_snapshot!("offer_by_val", vc, {
        ".validFrom" => "[validFrom]",
        ".credentialSubject" => insta::sorted_redaction()
    });
}
