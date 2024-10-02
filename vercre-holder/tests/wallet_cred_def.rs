//! Tests for wallet-initiated issuance flow where the authorization request is
//! made using a credential definition.

mod provider;

use insta::assert_yaml_snapshot as assert_snapshot;
use vercre_holder::issuance::{AuthorizeRequest, CredentialsRequest, Initiator};
use vercre_holder::provider::{CredentialStorer, Issuer, MetadataRequest};
use vercre_holder::{
    AuthorizationDetail, AuthorizationDetailType, CredentialAuthorization, FormatIdentifier,
    ProfileClaims,
};
use vercre_test_utils::issuer::{CLIENT_ID, CREDENTIAL_ISSUER, REDIRECT_URI};

use crate::provider::Provider;

// In a real scenario, this will be the result of an authentication request.
const SUBJECT_ID: &str = "normal_user";

// Test end-to-end wallet-initiated issuance flow, with authorization request
// using a credential definition.
#[tokio::test]
async fn wallet_credential_definition() {
    let issuer_provider = vercre_test_utils::issuer::Provider::new();
    let provider = Provider::new(Some(issuer_provider.clone()), None);

    // Use the provider to discover the credentials available from the issuer.
    let metadata_request = MetadataRequest {
        credential_issuer: "http://vercre.io".into(),
        languages: None,
    };
    let issuer_metadata = Issuer::metadata(&provider, metadata_request)
        .await
        .expect("should get issuer metadata");

    // Construct an authorization request using the credential definition for
    // the employee ID credential.
    let issuer = issuer_metadata.credential_issuer;
    let credential_config = issuer
        .credential_configurations_supported
        .get("EmployeeID_JWT")
        .expect("should have credential configuration");
    let claims = match &credential_config.format {
        FormatIdentifier::JwtVcJson(def) => ProfileClaims::W3c(def.credential_definition.clone()),
        _ => panic!("unexpected format"),
    };
    assert_snapshot!("claims", claims, {
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
            credential: CredentialAuthorization::ConfigurationId {
                credential_configuration_id: "EmployeeID_JWT".into(),
                claims: Some(claims),
            },
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
