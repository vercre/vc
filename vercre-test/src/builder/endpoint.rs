use std::fmt::Debug;

use openid::Result;

use crate::builder::handler::{wrapper, Request};
use crate::builder::BuilderEndpoint;
use crate::{IssuerProvider, TestRequest, TestResponse};

impl Request for TestRequest {
    fn callback_id(&self) -> Option<String> {
        Some("callback_id".into())
    }
}

impl<P> BuilderEndpoint<P>
where
    P: IssuerProvider + Debug,
{
    /// Mock a request to the endpoint.
    pub async fn make_request(&mut self, request: &TestRequest) -> Result<TestResponse> {
        wrapper(request, process).await
    }
}

async fn process(request: &TestRequest) -> Result<TestResponse> {
    println!("in process: {request:?}");
    Ok(TestResponse {})
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::TestProvider;

    #[tokio::test]
    async fn builder_ok() {
        let request = TestRequest { return_ok: true };
        let response =
            BuilderEndpoint::with_provider(TestProvider::new()).make_request(&request).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn current_err() {
        let request = TestRequest { return_ok: false };
        let response =
            BuilderEndpoint::with_provider(TestProvider::new()).make_request(&request).await;

        assert!(response.is_err());
    }
}
