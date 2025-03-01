//! Tests for the OAuth server metadata.

mod utils;

use credibil_vc::oid4vci;
use credibil_vc::oid4vci::issuer::OAuthServerRequest;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_issuer::CREDENTIAL_ISSUER;

#[tokio::test]
async fn metadata_ok() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let request = OAuthServerRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        issuer: None,
    };
    let response = oid4vci::endpoint::handle(CREDENTIAL_ISSUER, request, &provider)
        .await
        .expect("response is ok");
    assert_snapshot!("oauth_server:metadata_ok:response", response, {
        ".grant_types_supported" => insta::sorted_redaction()
    });
}
