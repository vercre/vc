//! Tests for the OAuth server metadata.

mod utils;

use credibil_vc::issuer;
use credibil_vc::openid::issuer::OAuthServerRequest;
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
    let response = issuer::oauth_server(provider, request).await.expect("response is ok");
    assert_snapshot!("oauth_server:metadata_ok:response", response, {
        ".grant_types_supported" => insta::sorted_redaction()
    });
}
