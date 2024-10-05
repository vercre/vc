//! Tests for wallet-initiated issuance flow where the authorization request is
//! made using a format.

mod provider;

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_holder::issuance::{AuthorizeRequest, CredentialsRequest, Initiator};
use vercre_holder::provider::{CredentialStorer, Issuer, MetadataRequest};
use vercre_test_utils::issuer::{CLIENT_ID, CREDENTIAL_ISSUER, REDIRECT_URI};

use crate::provider::Provider;

// In a real scenario, this will be the result of an authentication request.
const SUBJECT_ID: &str = "normal_user";

// Test end-to-end wallet-initiated issuance flow, with authorization request
// using scope.
#[tokio::test]
async fn wallet_scope() {
    let issuer_provider = vercre_test_utils::issuer::Provider::new();
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
    let scope = credential_config.scope.clone().expect("issuer metadata should have scope");

    let authorization_request = AuthorizeRequest {
        initiator: Initiator::Wallet {
            client_id: CLIENT_ID.into(),
            scope: Some(scope),
            issuer: CREDENTIAL_ISSUER.into(),
            subject_id: SUBJECT_ID.into(),
        },
        redirect_uri: Some(REDIRECT_URI.into()), // Must match client registration.
        authorization_details: None,
    };
    let auth_credentials =
        vercre_holder::issuance::authorize(provider.clone(), &authorization_request)
            .await
            .expect("should authorize");
    assert_snapshot!("auth_credentials", auth_credentials, {
        ".issuance_id" => "[issuance_id]",
    });

    // Get (and store) credentials. Accept all on offer.
    let cred_req = CredentialsRequest {
        issuance_id: auth_credentials.issuance_id.clone(),
        credential_identifiers: None,
        format: Some(credential_config.format.clone()),
    };
    vercre_holder::issuance::credentials(provider.clone(), &cred_req)
        .await
        .expect("should get credentials");

    let credentials =
        CredentialStorer::find(&provider, None).await.expect("should retrieve all credentials");

    assert_eq!(credentials.len(), 1);

    assert_snapshot!("credentials", credentials, {
        "[].vc.issuanceDate" => "[issuanceDate]",
        "[].vc" => insta::sorted_redaction(),
        "[].vc.credentialSubject" => insta::sorted_redaction(),
        "[].metadata" => insta::sorted_redaction(),
        "[].metadata.credential_definition" => insta::sorted_redaction(),
        "[].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
        "[].metadata.credential_definition.credentialSubject.address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
    });
}
