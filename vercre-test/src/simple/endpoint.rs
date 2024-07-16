use std::fmt::Debug;

use openid::{Err, Result};

use crate::simple::handler::{Context, Handler};
use crate::simple::SimpleEndpoint;
use crate::{IssuerProvider, TestRequest, TestResponse};

impl<P> SimpleEndpoint<P>
where
    P: IssuerProvider + Debug,
{
    /// Mock a request to the endpoint.
    pub async fn make_request(&self, request: &TestRequest) -> Result<TestResponse> {
        let ctx = RequestContext {
            _p: std::marker::PhantomData,
        };
        Handler::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct RequestContext<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> Context for RequestContext<P>
where
    P: IssuerProvider + Debug,
{
    type Provider = P;
    type Request = TestRequest;
    type Response = TestResponse;

    fn callback_id(&self) -> Option<String> {
        Some("callback_id".into())
    }

    async fn process(
        &self, _provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        if request.return_ok {
            Ok(TestResponse {})
        } else {
            Err(Err::InvalidRequest("invalid request".into()))
        }
    }
}
