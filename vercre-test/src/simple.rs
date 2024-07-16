//! # [OpenID for Verifiable Credential Issuance]

mod endpoint;
mod handler;

use std::fmt::Debug;

use handler::Handler;

use crate::IssuerProvider;

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[derive(Debug)]
pub struct Endpoint<P>
where
    P: IssuerProvider,
{
    provider: P,
}

impl<P> Endpoint<P>
where
    P: IssuerProvider,
{
    #[allow(dead_code)]
    pub fn with_provider(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> Handler for Endpoint<P>
where
    P: IssuerProvider + Debug,
{
    type Provider = P;

    fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::TestProvider;
    use crate::TestRequest;

    #[tokio::test]
    async fn test_ok() {
        let request = TestRequest { return_ok: true };
        let response = Endpoint::with_provider(TestProvider::new()).mock_request(&request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn test_err() {
        let request = TestRequest { return_ok: false };
        let response = Endpoint::with_provider(TestProvider::new()).mock_request(&request).await;

        assert!(response.is_err());
    }
}
