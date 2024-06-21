mod test_provider;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use openid4vc::issuance::CredentialConfiguration;
use openid4vc::presentation::{CreateRequestRequest, DeviceFlow};
use providers::presentation::VERIFIER;
use test_provider::TestProvider;
use vercre_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use vercre_holder::callback::CredentialStorer;
use vercre_holder::credential::Credential;
use vercre_holder::presentation::Status;
use vercre_holder::Endpoint;
use vercre_vc::model::VerifiableCredential;
use vercre_vc::proof::{self, Format, Payload};

static PROVIDER: LazyLock<TestProvider> = LazyLock::new(|| TestProvider::new());

fn sample_create_request() -> CreateRequestRequest {
    CreateRequestRequest {
        client_id: VERIFIER.into(),
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
    let vc = VerifiableCredential::sample();

    let payload = Payload::Vc(vc.clone());
    let jwt =
        proof::create(Format::JwtVcJson, payload, PROVIDER.clone()).await.expect("should encode");

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
    CredentialStorer::save(&PROVIDER.clone(), &credential).await.expect("should save credential");
    
    // Use the presentation service endpoint to create a sample request so we can get a valid
    // presentation request object.
    let init_request = vercre_verifier::Endpoint::new(PROVIDER.clone())
        .create_request(&sample_create_request())
        .await
        .expect("should get request");
    println!("{:#?}", init_request);

    // TODO: Test initiating a presentation flow using a full request object
    //let req_obj = init_request.request_object.expect("should have request object");

    // Intiate the presentation flow using a url
    let url = init_request.request_uri.expect("should have request uri");
    let presentation =
        Endpoint::new(PROVIDER.clone()).request(&url).await.expect("should process request");
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
    let pd = presentation.request.presentation_definition.clone().expect("should have pd");
    assert_eq!(pd.input_descriptors.len(), 1);
    assert_eq!(pd.input_descriptors[0].id, "EmployeeID_JWT");

    // Authorize the presentation
    let presentation = Endpoint::new(PROVIDER.clone())
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
    let response = Endpoint::new(PROVIDER.clone())
        .present(presentation.id.clone())
        .await
        .expect("should process present");
    assert_snapshot!("response_response", response);
}
