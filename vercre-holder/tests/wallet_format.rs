//! Tests for wallet-initiated issuance flow where the authorization request is
//! made using a format.

mod provider;

use insta::assert_yaml_snapshot as assert_snapshot;
use test_utils::issuer::{CLIENT_ID, CREDENTIAL_ISSUER, REDIRECT_URI};
use vercre_holder::issuance::{AuthorizeRequest, CredentialsRequest, Initiator, SaveRequest};
use vercre_holder::provider::{CredentialStorer, Issuer, MetadataRequest};
use vercre_holder::{
    AuthorizationDetail, AuthorizationDetailType, CredentialAuthorization, Format,
};
use vercre_issuer::ProfileW3c;

use crate::provider::Provider;

// In a real scenario, this will be the result of an authentication request.
const SUBJECT_ID: &str = "normal_user";

// Test end-to-end wallet-initiated issuance flow, with authorization request
// using a format.
#[tokio::test]
async fn wallet_format() {
    let issuer_provider = test_utils::issuer::Provider::new();
    let provider = Provider::new(Some(issuer_provider.clone()), None);

    // Use the provider to discover the credentials available from the issuer.
    let metadata_request = MetadataRequest {
        credential_issuer: "http://vercre.io".into(),
        languages: None,
    };
    let issuer_metadata =
        Issuer::metadata(&provider, metadata_request).await.expect("should get issuer metadata");

    // Construct an authorization request using the format for the employee ID
    // credential.
    let issuer = issuer_metadata.credential_issuer;
    let credential_config = issuer
        .credential_configurations_supported
        .get("EmployeeID_JWT")
        .expect("should have credential configuration");
    let credential_def = match &credential_config.format {
        Format::JwtVcJson(def) => def.credential_definition.clone(),
        _ => panic!("unexpected format"),
    };
    assert_snapshot!("credential_def", credential_def, {
        ".credentialSubject" => insta::sorted_redaction(),
        ".credentialSubject.address" => insta::sorted_redaction(),
    });

    let authorization_request = AuthorizeRequest {
        initiator: Initiator::Wallet {
            client_id: CLIENT_ID.into(),
            scope: None,
            issuer: CREDENTIAL_ISSUER.into(),
            subject_id: SUBJECT_ID.into(),
        },
        redirect_uri: Some(REDIRECT_URI.into()), // Must match client registration.
        authorization_details: Some(vec![AuthorizationDetail {
            type_: AuthorizationDetailType::OpenIdCredential,
            credential: CredentialAuthorization::Format(Format::JwtVcJson(ProfileW3c {
                credential_definition: credential_def,
            })),
            locations: None,
        }]),
    };
    let auth_credentials =
        vercre_holder::issuance::authorize(provider.clone(), &authorization_request)
            .await
            .expect("should authorize");
    let credential_identifiers = auth_credentials.authorized.unwrap();
    assert_eq!(credential_identifiers.len(), 1);
    assert_eq!(credential_identifiers.get("EmployeeID_JWT").unwrap()[0], "PHLEmployeeID");

    // Get (and store) credentials. Accept all on offer.
    let cred_req = CredentialsRequest {
        issuance_id: auth_credentials.issuance_id.clone(),
        ..Default::default()
    };
    vercre_holder::issuance::credentials(provider.clone(), &cred_req)
        .await
        .expect("should get credentials");
    vercre_holder::issuance::save(
        provider.clone(),
        &SaveRequest {
            issuance_id: auth_credentials.issuance_id.clone(),
        },
    )
    .await
    .expect("should save credentials");

    let credentials =
        CredentialStorer::find(&provider, None).await.expect("should retrieve all credentials");

    assert_eq!(credentials.len(), 1);

    assert_snapshot!("credentials", credentials, {
        "[].type" => insta::sorted_redaction(),
        "[].claims[]" => insta::sorted_redaction(),
        "[].claims[].address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
        "[].issuance_date" => "[issuance_date]",
    });
}
