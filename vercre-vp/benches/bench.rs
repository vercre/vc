#![feature(test)]

extern crate test;

use futures::executor::block_on;
use serde_json::json;
use test::Bencher;
use test_utils::vp_provider::Provider;
use vercre_core::vp::InvokeRequest;
use vercre_vp::Endpoint;

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

    let mut request = serde_json::from_value::<InvokeRequest>(body).expect("should deserialize");
    request.client_id = String::from("http://vercre.io");

    // run benchmark test
    b.iter(|| block_on(endpoint.invoke(&request)));
}
