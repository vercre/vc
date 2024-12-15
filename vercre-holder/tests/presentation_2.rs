//! End-to-end tests for the presentation (verification) flow.
mod provider;

use std::collections::HashMap;

use chrono::Utc;
use insta::assert_yaml_snapshot;
use serde_json::Map;
use test_utils::verifier::{self, VERIFIER_ID};
use vercre_core::{Kind, Quota};
use vercre_dif_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use vercre_holder::credential::Credential;
use vercre_holder::presentation::{
    parse_request_object_response, NotAuthorized, PresentationFlow, WithRequest,
    WithUri, WithoutRequest, WithoutUri,
};
use vercre_holder::provider::{CredentialStorer, Verifier};
use vercre_infosec::{KeyOps, Signer};
use vercre_issuer::{Claim, ClaimDefinition};
use vercre_openid::issuer::{Display, ValueType};
use vercre_openid::verifier::{CreateRequestRequest, DeviceFlow};
use vercre_w3c_vc::model::{CredentialSubject, VerifiableCredential};
use vercre_w3c_vc::proof::{self, Payload, W3cFormat};

use crate::provider as holder;

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

    let provider = verifier::Provider::new();
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
        }]),
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
        }
    }

    Credential {
        id: vc.id.clone().expect("should have id"),
        issuer: "https://vercre.io".into(),
        issuer_name: "Vercre".into(),
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
async fn presentation_uri_2() {
    // Have a credential saved in the wallet ready to present.
    let credential = sample_credential().await;
    let verifier_provider = verifier::Provider::new();
    let provider = holder::Provider::new(None, Some(verifier_provider.clone()));
    provider.save(&credential).await.expect("should save credential");

    // Use the verifier service to create a sample request so we can get a valid
    // presentation request object. This is test set-up only - wallets do not
    // ask a verifer for a request; the verifier presents a presentation request
    // to the wallet.
    let request_request = setup_create_request();
    let init_request = vercre_verifier::create_request(verifier_provider, &request_request)
        .await
        .expect("should get request");

    //--------------------------------------------------------------------------
    // Initiate the presentation flow state using a URL.
    //--------------------------------------------------------------------------
    let url = init_request.request_uri.expect("should have request uri");
    let state = PresentationFlow::<WithUri, WithoutRequest, NotAuthorized>::new(url.clone());

    //--------------------------------------------------------------------------
    // Parse and verify the request object.
    //--------------------------------------------------------------------------
    let request_object_response =
        provider.request_object(&url).await.expect("should get request object");
    let request_object = parse_request_object_response(&request_object_response, provider.clone())
        .await
        .expect("should parse request object response");
    assert_yaml_snapshot!("request_object", request_object, {
        ".nonce" => "[nonce]",
        ".state" => "[state]",
        ".presentation_definition.id" => "[presentation_definition_id]",
    });

    //--------------------------------------------------------------------------
    // Store the request in state.
    //--------------------------------------------------------------------------
    let state = state.request(request_object).expect("should have a valid request object");
    let filter = state.filter().expect("should build filter from request object");

    //--------------------------------------------------------------------------
    // Get the credentials from the holder's credential store that match the
    // verifier's request and present them to the wallet holder for them to
    // agree to presenting them to the verifier.
    //--------------------------------------------------------------------------

    let credentials = provider.find(Some(filter)).await.expect("should find credentials");
    assert_yaml_snapshot!("credentials_requested", credentials, {
        "[].type" => insta::sorted_redaction(),
        "[].subject_claims[]" => insta::sorted_redaction(),
        "[].subject_claims[].claims" => insta::sorted_redaction(),
        "[].subject_claims[].claims[].address" => insta::sorted_redaction(),
        "[].claim_definitions" => insta::sorted_redaction(),
        "[].claim_definitions.address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
        "[].issuance_date" => "[issuance_date]",
    });

    //--------------------------------------------------------------------------
    // Authorize the presentation.
    //--------------------------------------------------------------------------

    let state = state.authorize(&credentials);

    //--------------------------------------------------------------------------
    // Construct a verifiable presentation payload
    //--------------------------------------------------------------------------

    let kid = provider.verification_method().await.expect("should get verification method");
    let vp = state.payload(&kid).expect("should get verifiable presentation payload");

    //--------------------------------------------------------------------------
    // Create a proof and use it to create a presentation response request.
    //--------------------------------------------------------------------------

    let Payload::Vp { vp, client_id, nonce } = vp else {
        panic!("expected Payload::Vp");
    };
    let jwt = proof::create(W3cFormat::JwtVcJson, Payload::Vp { vp, client_id, nonce }, &provider)
        .await
        .expect("should create proof");
    let (res_req, uri) = state.create_response_request(&jwt);

    //--------------------------------------------------------------------------
    // Send the presentation response to the verifier.
    //--------------------------------------------------------------------------

    let response =
        provider.present(uri.as_deref(), &res_req).await.expect("should present to verifier");
    assert_yaml_snapshot!("response_response", response);
}

#[tokio::test]
async fn presentation_obj_2() {
    // Have a credential saved in the wallet ready to present.
    let credential = sample_credential().await;
    let verifier_provider = verifier::Provider::new();
    let provider = holder::Provider::new(None, Some(verifier_provider.clone()));
    provider.save(&credential).await.expect("should save credential");

    // Use the verifier service to create a sample request so we can get a valid
    // presentation request object. This is test set-up only - wallets do not
    // ask a verifer for a request; the verifier presents a presentation request
    // to the wallet.
    let mut request_request = setup_create_request();
    request_request.device_flow = DeviceFlow::SameDevice;
    let init_request = vercre_verifier::create_request(verifier_provider, &request_request)
        .await
        .expect("should get request");

    //--------------------------------------------------------------------------
    // Initiate the presentation flow state using an object.
    //--------------------------------------------------------------------------
    let request_object = init_request.request_object.expect("should have request object");
    assert_yaml_snapshot!("request_object_obj", request_object, {
        ".nonce" => "[nonce]",
        ".state" => "[state]",
        ".presentation_definition.id" => "[presentation_definition_id]",
    });
    let state = PresentationFlow::<WithoutUri, WithRequest, NotAuthorized>::new(request_object)
        .expect("should have a valid request object");
    let filter = state.filter().expect("should build filter from request object");

    //--------------------------------------------------------------------------
    // Get the credentials from the holder's credential store that match the
    // verifier's request and present them to the wallet holder for them to
    // agree to presenting them to the verifier.
    //--------------------------------------------------------------------------

    let credentials = provider.find(Some(filter)).await.expect("should find credentials");
    assert_yaml_snapshot!("credentials_requested_obj", credentials, {
        "[].type" => insta::sorted_redaction(),
        "[].subject_claims[]" => insta::sorted_redaction(),
        "[].subject_claims[].claims" => insta::sorted_redaction(),
        "[].subject_claims[].claims[].address" => insta::sorted_redaction(),
        "[].claim_definitions" => insta::sorted_redaction(),
        "[].claim_definitions.address" => insta::sorted_redaction(),
        "[].issued" => "[issued]",
        "[].issuance_date" => "[issuance_date]",
    });

    //--------------------------------------------------------------------------
    // Authorize the presentation.
    //--------------------------------------------------------------------------

    let state = state.authorize(&credentials);

    //--------------------------------------------------------------------------
    // Construct a presentation submission and verifiable presentation payload
    //--------------------------------------------------------------------------

    let kid = provider.verification_method().await.expect("should get verification method");
    let vp = state.payload(&kid).expect("should get verifiable presentation payload");

    //--------------------------------------------------------------------------
    // Create a proof and use it to create a presentation response request.
    //--------------------------------------------------------------------------

    let Payload::Vp { vp, client_id, nonce } = vp else {
        panic!("expected Payload::Vp");
    };
    let jwt = proof::create(W3cFormat::JwtVcJson, Payload::Vp { vp, client_id, nonce }, &provider)
        .await
        .expect("should create proof");
    let (res_req, uri) = state.create_response_request(&jwt);

    //--------------------------------------------------------------------------
    // Send the presentation response to the verifier.
    //--------------------------------------------------------------------------

    let response =
        provider.present(uri.as_deref(), &res_req).await.expect("should present to verifier");
    assert_yaml_snapshot!("response_response_obj", response);
}
