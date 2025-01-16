//! Tests for wallet-initiated issuance flow where the authorization request is
//! made using a format.
mod provider;

use insta::assert_yaml_snapshot;
use test_utils::issuer::{self, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER, REDIRECT_URI};
use vercre_holder::issuance::{AuthCode, IssuanceFlow, NotAccepted, WithoutOffer, WithoutToken};
use vercre_holder::jose::JwsBuilder;
use vercre_holder::provider::{Issuer, MetadataRequest, OAuthServerRequest};
use vercre_issuer::{
    AuthorizationDetail, AuthorizationDetailType, CredentialAuthorization, CredentialResponseType,
    Format, ProfileW3c,
};
use vercre_w3c_vc::proof::{Payload, Type, Verify};

use crate::provider as holder;

// Test end-to-end wallet-initiated issuance flow, with authorization request
// using a format.
#[tokio::test]
async fn wallet_format() {
    let issuer_provider = issuer::Provider::new();
    let provider = holder::Provider::new(Some(issuer_provider), None);

    //--------------------------------------------------------------------------
    // Get issuer metadata.
    //--------------------------------------------------------------------------
    let metadata_request = MetadataRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        languages: None,
    };
    let issuer_metadata =
        provider.metadata(metadata_request).await.expect("should get issuer metadata");

    //--------------------------------------------------------------------------
    // Get authorization server metadata.
    //--------------------------------------------------------------------------
    let auth_request = OAuthServerRequest {
        credential_issuer: CREDENTIAL_ISSUER.into(),
        issuer: None,
    };
    let auth_metadata =
        provider.oauth_server(auth_request).await.expect("should get auth metadata");

    //--------------------------------------------------------------------------
    // Initiate flow state with the offer and metadata.
    //--------------------------------------------------------------------------
    let state = IssuanceFlow::<WithoutOffer, AuthCode, NotAccepted, WithoutToken>::new(
        CLIENT_ID,
        NORMAL_USER,
        issuer_metadata.credential_issuer.clone(),
        auth_metadata.authorization_server,
    );

    //--------------------------------------------------------------------------
    // Construct an authorization request using the credential definition for
    // the employee ID credential. The expected user workflow would be to
    // present the issuer's metadata to the user and allow them to select which
    // credentialthey want to request. Here we are hardcoding the credential
    // configuration ID for the employee ID credential and asking for that
    // format.
    //--------------------------------------------------------------------------
    let cred_config = issuer_metadata
        .credential_issuer
        .credential_configurations_supported
        .get("EmployeeID_JWT")
        .expect("should have credential configuration");
    let cred_def = match &cred_config.format {
        Format::JwtVcJson(def) => def.credential_definition.clone(),
        _ => panic!("unexpected format"),
    };
    let accept = vec![AuthorizationDetail {
        type_: AuthorizationDetailType::OpenIdCredential,
        credential: CredentialAuthorization::Format(Format::JwtVcJson(ProfileW3c {
            credential_definition: cred_def,
        })),
        locations: None,
    }];
    let state = state.accept(accept);

    let (auth_request, verifier) = state
        .authorization_request(Some(REDIRECT_URI))
        .expect("should construct authorization request");
    let auth_response = provider.authorization(auth_request).await.expect("should authorize");

    //--------------------------------------------------------------------------
    // Exchange the authorization code for an access token.
    //--------------------------------------------------------------------------
    let token_request = state.token_request(&auth_response.code, &verifier, Some(REDIRECT_URI));
    let token_response = provider.token(token_request).await.expect("should get token response");
    let mut state = state.token(token_response.clone());

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
    let jws_claims = state.proof();
    let jws = JwsBuilder::new()
        .jwt_type(Type::Openid4VciProofJwt)
        .payload(jws_claims)
        .add_signer(&provider)
        .build()
        .await
        .expect("should build jws");
    let jwt = jws.encode().expect("should encode jws");
    let credential_requests = state.credential_requests(&identifiers, &jwt).clone();
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
    assert_yaml_snapshot!("credentials", state.credentials(), {
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
