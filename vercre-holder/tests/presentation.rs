//! End-to-end tests for the presentation (verification) flow.

mod provider;

use std::collections::HashMap;
use std::sync::LazyLock;

use chrono::Utc;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::Map;
use test_utils::verifier::{self, VERIFIER_ID};
use vercre_core::{urlencode, Kind, Quota};
use vercre_dif_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use vercre_holder::credential::Credential;
use vercre_holder::presentation::Status;
use vercre_holder::provider::CredentialStorer;
use vercre_infosec::KeyOps;
use vercre_issuer::{Claim, ClaimDefinition};
use vercre_openid::issuer::{Display, ValueType};
use vercre_openid::verifier::{CreateRequestRequest, DeviceFlow};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Payload, W3cFormat};

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
        type_: Quota::Many(vec!["VerifiableCredential".into(), "EmployeeIDCredential".into()]),
        issuer: Kind::String("https://example.com/issuers/14".into()),
        id: Some("https://example.com/credentials/3732".into()),
        valid_from: Some(Utc.with_ymd_and_hms(2023, 11, 20, 23, 21, 55).unwrap()),
        credential_subject: Quota::One(CredentialSubject {
            id: Some("did:example:ebfeb1f712ebc6f1c276e12ec21".into()),
            claims: json!({"employeeId": "1234567890"})
                .as_object()
                .map_or_else(Map::default, Clone::clone),
        }),
        valid_until: Some(Utc.with_ymd_and_hms(2033, 12, 20, 23, 21, 55).unwrap()),

        ..VerifiableCredential::default()
    };
    let issuance_date = Utc::now();

    let provider = VERIFIER_PROVIDER.clone();
    let signer = KeyOps::signer(&provider, VERIFIER_ID).expect("should get verifier");

    let payload = Payload::Vc {
        vc: vc.clone(),
        issued_at: issuance_date.timestamp(),
    };
    let jwt = proof::create(W3cFormat::JwtVcJson, payload, &signer).await.expect("should encode");

    let mut claim_def: HashMap<String, Claim> = HashMap::new();
    let claim = Claim::Entry(ClaimDefinition {
        mandatory: Some(true),
        value_type: Some(ValueType::String),
        display: Some(vec![Display {
            name: "Employee ID".into(),
            locale: None,
        }])
    });
    claim_def.insert("employeeId".into(), claim);

    // Turn a Quota of Strings into a Vec of Strings for the type of credential.
    let mut type_ = Vec::new();
    match &vc.type_ {
        Quota::One(t) => type_.push(t.clone()),
        Quota::Many(vc_types) => type_.extend(vc_types.clone()),
    }

    // Turn a Quota of credential subjects into a Vec of credential subjects.
    let mut subject_claims = Vec::new();
    match vc.credential_subject {
        Quota::One(claim) => subject_claims.push(claim.into()),
        Quota::Many(vc_claims) => {
            for claim in vc_claims {
                subject_claims.push(claim.into());
            }
        },
    }

    Credential {
        id: vc.id.clone().expect("should have id"),
        issuer: "https://vercre.io".into(),
        type_,
        format: "jwt_vc_json".into(),
        subject_claims,
        claim_definitions: Some(claim_def),
        display: None,
        issued: jwt,
        issuance_date,
        valid_from: vc.valid_from.clone(),
        valid_until: vc.valid_until.clone(),
        logo: None,
        background: None,
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
        ".credentials[].type" => insta::sorted_redaction(),
        ".credentials[].subject_claims[]" => insta::sorted_redaction(),
        ".credentials[].subject_claims[].claims" => insta::sorted_redaction(),
        ".credentials[].subject_claims[].claims[].address" => insta::sorted_redaction(),
        ".credentials[].claim_definitions" => insta::sorted_redaction(),
        ".credentials[].claim_definitions.address" => insta::sorted_redaction(),
        ".credentials[].issued" => "[issued]",
        ".credentials[].issuance_date" => "[issuance_date]",
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
        ".credentials[].type" => insta::sorted_redaction(),
        ".credentials[].subject_claims[]" => insta::sorted_redaction(),
        ".credentials[].subject_claims[].claims" => insta::sorted_redaction(),
        ".credentials[].subject_claims[].claims[].address" => insta::sorted_redaction(),
        ".credentials[].claim_definitions" => insta::sorted_redaction(),
        ".credentials[].claim_definitions.address" => insta::sorted_redaction(),
        ".credentials[].issued" => "[issued]",
        ".credentials[].issuance_date" => "[issuance_date]",
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
