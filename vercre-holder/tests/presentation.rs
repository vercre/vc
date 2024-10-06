//! End-to-end tests for the presentation (verification) flow.

mod provider;

use std::sync::LazyLock;

use chrono::Utc;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::Map;
use vercre_core::{urlencode, Kind, Quota};
use vercre_datasec::SecOps;
use vercre_dif_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use vercre_holder::credential::Credential;
use vercre_holder::presentation::Status;
use vercre_holder::provider::CredentialStorer;
use vercre_openid::verifier::{CreateRequestRequest, DeviceFlow};
use vercre_test_utils::verifier::{self, VERIFIER_ID};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Format, Payload};

use crate::provider as holder;

static VERIFIER_PROVIDER: LazyLock<verifier::Provider> = LazyLock::new(verifier::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(None, Some(VERIFIER_PROVIDER.clone())));

fn setup_create_request() -> CreateRequestRequest {
    CreateRequestRequest {
        client_id: VERIFIER_ID.into(),
        device_flow: DeviceFlow::CrossDevice,
        purpose: "To verify employment status".into(),
        input_descriptors: vec![InputDescriptor {
            id: "EmployeeID_JWT".into(),
            constraints: Constraints {
                fields: Some(vec![Field {
                    path: vec!["$.type".into()],
                    filter: Some(Filter {
                        type_: "string".into(),
                        value: FilterValue::Const("EmployeeIDCredential".into()),
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            },
            name: None,
            purpose: None,
            format: None,
        }],
        ..Default::default()
    }
}

async fn sample_credential() -> Credential {
    use chrono::TimeZone;
    use serde_json::json;

    let vc = VerifiableCredential {
        context: vec![
            Kind::String("https://www.w3.org/2018/credentials/v1".into()),
            Kind::String("https://www.w3.org/2018/credentials/examples/v1".into()),
        ],
        type_: vec!["VerifiableCredential".into(), "EmployeeIDCredential".into()],
        issuer: Kind::String("https://example.com/issuers/14".into()),
        id: "https://example.com/credentials/3732".into(),
        issuance_date: Utc.with_ymd_and_hms(2023, 11, 20, 23, 21, 55).unwrap(),
        credential_subject: Quota::One(CredentialSubject {
            id: Some("did:example:ebfeb1f712ebc6f1c276e12ec21".into()),
            claims: json!({"employeeId": "1234567890"})
                .as_object()
                .map_or_else(Map::default, Clone::clone),
        }),
        expiration_date: Some(Utc.with_ymd_and_hms(2033, 12, 20, 23, 21, 55).unwrap()),

        ..VerifiableCredential::default()
    };

    let provider = VERIFIER_PROVIDER.clone();
    let signer = SecOps::signer(&provider, VERIFIER_ID).expect("should get verifier");

    let payload = Payload::Vc(vc.clone());
    let jwt = proof::create(Format::JwtVcJson, payload, signer).await.expect("should encode");

    let config = vercre_test_utils::sample::credential_configuration();
    Credential {
        issuer: "https://vercre.io".into(),
        id: vc.id.clone(),
        metadata: config,
        vc: vc.clone(),
        issued: jwt,
        logo: None,
    }
}

#[tokio::test]
async fn e2e_presentation_uri() {
    // Add the credential to the holder's store so it can be found and used by the
    // presentation flow.
    let credential = sample_credential().await;
    CredentialStorer::save(&HOLDER_PROVIDER.clone(), &credential)
        .await
        .expect("should save credential");

    // Use the presentation service endpoint to create a sample request so we can
    // get a valid presentation request object.
    let request_request = setup_create_request();
    let init_request = vercre_verifier::create_request(VERIFIER_PROVIDER.clone(), &request_request)
        .await
        .expect("should get request");

    // Intiate the presentation flow using a url
    let url = init_request.request_uri.expect("should have request uri");
    let presentation = vercre_holder::presentation::request(HOLDER_PROVIDER.clone(), &url)
        .await
        .expect("should process request");

    assert_eq!(presentation.status, Status::Requested);
    assert_snapshot!("presentation_requested", presentation, {
        ".presentation_id" => "[presentation_id]",
        ".**.credentialSubject" => insta::sorted_redaction(),
        ".**.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Authorize the presentation
    let status = vercre_holder::presentation::authorize(
        HOLDER_PROVIDER.clone(),
        presentation.presentation_id.clone(),
    )
    .await
    .expect("should authorize presentation");
    assert_eq!(status, Status::Authorized);

    // Process the presentation
    let response = vercre_holder::presentation::present(
        HOLDER_PROVIDER.clone(),
        presentation.presentation_id.clone(),
    )
    .await
    .expect("should process present");
    assert_snapshot!("response_response", response);
}

#[tokio::test]
async fn e2e_presentation_obj() {
    // Add the credential to the holder's store so it can be found and used by the
    // presentation flow.
    let credential = sample_credential().await;
    CredentialStorer::save(&HOLDER_PROVIDER.clone(), &credential)
        .await
        .expect("should save credential");

    // Use the presentation service endpoint to create a sample request so we can
    // get a valid presentation request object.
    let mut request_request = setup_create_request();
    request_request.device_flow = DeviceFlow::SameDevice;
    let init_request = vercre_verifier::create_request(VERIFIER_PROVIDER.clone(), &request_request)
        .await
        .expect("should get request");

    // Intiate the presentation flow using an object
    let obj = init_request.request_object.expect("should have request object");
    let qs = urlencode::to_string(&obj).expect("should serialize");
    let presentation = vercre_holder::presentation::request(HOLDER_PROVIDER.clone(), &qs)
        .await
        .expect("should process request");

    assert_eq!(presentation.status, Status::Requested);
    assert_snapshot!("presentation_requested2", presentation, {
        ".presentation_id" => "[presentation_id]",
        ".credentials[].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
        ".credentials[].metadata.credential_definition.credentialSubject.address" => insta::sorted_redaction(),
    });

    // Authorize the presentation
    let status = vercre_holder::presentation::authorize(
        HOLDER_PROVIDER.clone(),
        presentation.presentation_id.clone(),
    )
    .await
    .expect("should authorize presentation");
    assert_eq!(status, Status::Authorized);

    // Process the presentation
    let response = vercre_holder::presentation::present(
        HOLDER_PROVIDER.clone(),
        presentation.presentation_id.clone(),
    )
    .await
    .expect("should process present");
    assert_snapshot!("response_response2", response);
}
