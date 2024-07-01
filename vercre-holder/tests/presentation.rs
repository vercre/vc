mod providers;

use std::sync::LazyLock;

use dif_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use insta::assert_yaml_snapshot as assert_snapshot;
use openid4vc::issuance::CredentialConfiguration;
use openid4vc::presentation::{CreateRequestRequest, DeviceFlow, PresentationDefinitionType};
use test_utils::verifier;
use vercre_holder::callback::CredentialStorer;
use vercre_holder::credential::Credential;
use vercre_holder::presentation::Status;
use vercre_holder::Endpoint;
use w3c_vc::model::VerifiableCredential;
use w3c_vc::proof::{self, Format, Payload};

use crate::providers::{holder, VERIFIER_ID};

static VERIFIER_PROVIDER: LazyLock<verifier::Provider> = LazyLock::new(verifier::Provider::new);
static HOLDER_PROVIDER: LazyLock<holder::Provider> =
    LazyLock::new(|| holder::Provider::new(None, Some(VERIFIER_PROVIDER.clone())));

static CREATE_REQUEST: LazyLock<CreateRequestRequest> = LazyLock::new(|| CreateRequestRequest {
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
});

async fn sample_credential() -> Credential {
    let vc = VerifiableCredential::sample();

    let payload = Payload::Vc(vc.clone());
    let jwt = proof::create(Format::JwtVcJson, payload, VERIFIER_PROVIDER.clone())
        .await
        .expect("should encode");

    let config = CredentialConfiguration::sample();
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
async fn e2e_presentation() {
    // Add the credential to the holder's store so it can be found and used by the presentation
    // flow.
    let credential = sample_credential().await;
    CredentialStorer::save(&HOLDER_PROVIDER.clone(), &credential)
        .await
        .expect("should save credential");

    // Use the presentation service endpoint to create a sample request so we can get a valid
    // presentation request object.
    let init_request = vercre_verifier::Endpoint::new(VERIFIER_PROVIDER.clone())
        .create_request(&CREATE_REQUEST)
        .await
        .expect("should get request");

    // TODO: Test initiating a presentation flow using a full request object
    //let req_obj = init_request.request_object.expect("should have request object");

    // Intiate the presentation flow using a url
    let url = init_request.request_uri.expect("should have request uri");
    let presentation =
        Endpoint::new(HOLDER_PROVIDER.clone()).request(&url).await.expect("should process request");

    assert_eq!(presentation.status, Status::Requested);
    assert_snapshot!("presentation_requested", presentation, {
        ".id" => "[id]",
        ".request" => insta::sorted_redaction(),
        ".request.nonce" => "[nonce]",
        ".request.state" => "[state]",
        ".request.presentation_definition" => "[presentation_definition]",
        ".credentials[0].metadata.credential_definition.credentialSubject" => insta::sorted_redaction(),
    });

    // Because of the presentation definition ID being unique per call, we redact it in the snapshot
    // above, so do a check of a couple of key fields just to make sure we have data we know will
    // be helpful further in the process.
    let PresentationDefinitionType::Object(pd) =
        presentation.request.presentation_definition.clone()
    else {
        panic!("should have presentation definition");
    };
    assert_eq!(pd.input_descriptors.len(), 1);
    assert_eq!(pd.input_descriptors[0].id, "EmployeeID_JWT");

    // Authorize the presentation
    let presentation = Endpoint::new(HOLDER_PROVIDER.clone())
        .authorize(presentation.id.clone())
        .await
        .expect("should authorize presentation");

    assert_eq!(presentation.status, Status::Authorized);
    assert_snapshot!("presentation_authorized", presentation, {
        ".id" => "[id]",
        ".request" => insta::sorted_redaction(),
        ".request.nonce" => "[nonce]",
        ".request.state" => "[state]",
        ".request.presentation_definition" => "[presentation_definition]",
        ".credentials" => "[credentials checked on previous step]",
    });

    // Process the presentation
    let response = Endpoint::new(HOLDER_PROVIDER.clone())
        .present(presentation.id.clone())
        .await
        .expect("should process present");
    assert_snapshot!("response_response", response);
}
