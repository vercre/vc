use openid::Result;

use crate::simple::handler::{shell, Request};
use crate::{IssuerProvider, TestRequest, TestResponse};

impl Request for TestRequest {}

#[allow(dead_code)]
pub async fn make_request(
    provider: impl IssuerProvider, request: &TestRequest,
) -> Result<TestResponse> {
    shell(provider.clone(), request, verify).await?;
    shell(provider, request, process).await
}

async fn verify(_provider: impl IssuerProvider, request: &TestRequest) -> Result<TestResponse> {
    println!("in process: {request:?}");
    Ok(TestResponse {})
}

async fn process(_provider: impl IssuerProvider, request: &TestRequest) -> Result<TestResponse> {
    println!("in process: {request:?}");
    Ok(TestResponse {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::TestProvider;

    #[tokio::test]
    async fn simple_ok() {
        let request = TestRequest { return_ok: true };
        let response = make_request(TestProvider::new(), &request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn simple_err() {
        let request = TestRequest { return_ok: false };
        let response = make_request(TestProvider::new(), &request).await;

        assert!(response.is_err());
    }
}
