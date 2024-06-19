mod test_provider;

use std::sync::LazyLock;

use insta::assert_yaml_snapshot as assert_snapshot;
use openid4vc::presentation::{CreateRequestRequest, DeviceFlow};
use providers::presentation::VERIFIER;
use test_provider::TestProvider;
use vercre_exch::{Constraints, Field, Filter, FilterValue, InputDescriptor};
use vercre_holder::Endpoint;

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
                    path: vec!["$.type_".into()],
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

// fn sample_request() -> RequestObject {
//     let state_key = "ABCDEF123456";
//     let nonce = "1234567890";
//     let fmt = ClaimFormat {
//         alg: Some(vec![Algorithm::EdDSA.to_string()]),
//         proof_type: None,
//     };

//     RequestObject {
//         response_type: "vp_token".into(),
//         client_id: "https://vercre.io/post".into(),
//         state: Some(state_key.into()),
//         nonce: nonce.into(),
//         response_mode: Some("direct_post".into()),
//         response_uri: Some("https://vercre.io/post".into()),
//         presentation_definition: Some(PresentationDefinition {
//             id: "cd4cf88c-adc9-48b9-91cf-12d8643bff73".into(),
//             purpose: Some("To verify employment status".into()),
//             format: Some(HashMap::from([("jwt_vc".into(), fmt)])),
//             name: None,
//             input_descriptors: vec![InputDescriptor {
//                 id: "EmployeeID_JWT".into(),
//                 constraints: Constraints {
//                     fields: Some(vec![Field {
//                         path: vec!["$.type_".into()],
//                         filter: Some(Filter {
//                             type_: "string".into(),
//                             value: FilterValue::Const("EmployeeIDCredential".into()),
//                         }),
//                         ..Default::default()
//                     }]),
//                     limit_disclosure: None,
//                 },
//                 name: None,
//                 purpose: None,
//                 format: None,
//             }],
//         }),
//         client_id_scheme: Some("redirect_uri".into()),
//         client_metadata: None, // Some(self.client_meta.clone()),
//         redirect_uri: None,
//         scope: None,
//         presentation_definition_uri: None,
//         client_metadata_uri: None,
//     }
// }

// async fn sample_credential() -> Credential {
//     let vc = VerifiableCredential::sample();

//     let payload = Payload::Vc(vc.clone());
//     let jwt =
//         proof::create(Format::JwtVcJson, payload, PROVIDER.clone()).await.expect("should encode");

//     let config = CredentialConfiguration::sample();
//     Credential {
//         issuer: "https://vercre.io".into(),
//         id: vc.id.clone(),
//         metadata: config,
//         vc: vc.clone(),
//         issued: jwt,
//         logo: None,
//     }
// }

#[tokio::test]
async fn e2e_presentation() {
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
    assert_snapshot!("presentation_requested", presentation, {
        ".id" => "[id]",
        ".request" => insta::sorted_redaction(),
        ".request.nonce" => "[nonce]",
        ".request.state" => "[state]",
        ".request.presentation_definition" => "[presentation_definition]",
    });
}
