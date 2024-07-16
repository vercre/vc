use std::fmt::Debug;

use openid::{Err, Result};

use crate::current::handler::{Context, Handler};
use crate::current::CurrentEndpoint;
use crate::{IssuerProvider, TestRequest, TestResponse};

impl<P> CurrentEndpoint<P>
where
    P: IssuerProvider + Debug,
{
    /// Mock a request to the endpoint.
    pub async fn make_request(&self, request: &TestRequest) -> Result<TestResponse> {
        let ctx = RequestContext {
            _p: std::marker::PhantomData,
        };
        Handler::handle(self, request, ctx).await
    }
}

struct RequestContext<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> Context for RequestContext<P>
where
    P: IssuerProvider,
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
