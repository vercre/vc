#![feature(test)]

extern crate test;

use futures::executor::block_on;
use providers::presentation::Provider;
use serde_json::json;
use test::Bencher;
use openid4vc::presentation::CreateRequestRequest;
use vercre_verifier::Endpoint;

#[bench]
fn request(b: &mut Bencher) {
    let provider = Provider::new();
    let endpoint = Endpoint::new(provider);

    // test set up
    let body = json!({
        "credentials": [
            {"type": ["VerifiableCredential", "EmployeeIDCredential"]},
            {"type": ["VerifiableCredential", "CitizenshipCredential"]}
        ],
    });

    let mut request =
        serde_json::from_value::<CreateRequestRequest>(body).expect("should deserialize");
    request.client_id = "http://vercre.io".into();

    // run benchmark test
    b.iter(|| block_on(endpoint.create_request(&request)));
}
