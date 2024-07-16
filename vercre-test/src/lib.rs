//! # [OpenID for Verifiable Credential Issuance]

mod builder;
mod provider;
mod simple;

use openid::endpoint::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
use proof::signature::Signer;

/// Test request.
#[derive(Clone, Debug, Default)]
pub struct TestRequest {
    /// Return OK.
    pub return_ok: bool,
}

/// Test response.
pub struct TestResponse {}

/// Issuer Provider trait.
pub trait IssuerProvider:
    ClientMetadata + IssuerMetadata + ServerMetadata + Subject + StateManager + Signer + Callback
{
}

#[cfg(test)]
mod tests {
    use provider::TestProvider;

    use super::*;

    #[tokio::test]
    async fn test_ok() {
        let request = TestRequest { return_ok: true };
        let response =
            builder::Endpoint::with_provider(TestProvider::new()).mock_request(&request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_err() {
        let request = TestRequest { return_ok: false };
        let response =
            builder::Endpoint::with_provider(TestProvider::new()).mock_request(&request).await;

        assert!(response.is_err());
    }
}
