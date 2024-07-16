//! # `OpenID` Core

use futures::Future;

// use openid::Result;

// use openid::endpoint::{Callback, Payload, Status};
// use openid::Err;
use crate::IssuerProvider;

pub trait Request {
    fn callback_id(&self) -> Option<String> {
        None
    }
    fn state_key(&self) -> Option<String> {
        None
    }
}

pub trait Handler<'a, P, R, U, E>: Send
where
    R: Request + Sync,
{
    fn handle(self, provider: P, request: &'a R) -> impl Future<Output = Result<U, E>> + Send;
}

// Blanket implementation for all functions that take a provider and a request and return a
// future that resolves to a result.
impl<'a, P, R, U, F, Fut, E> Handler<'a, P, R, U, E> for F
where
    R: 'a + Request + Sync,
    F: FnOnce(P, &'a R) -> Fut + Send,
    Fut: Future<Output = Result<U, E>> + Send + Sync,
{
    fn handle(self, provider: P, request: &'a R) -> impl Future<Output = Result<U, E>> + Send {
        self(provider, request)
    }
}

pub async fn shell<P, R, U, E, F>(provider: P, request: &R, handler: F) -> Result<U, E>
where
    // P: IssuerProvider,
    R: Request + Sync,
    F: for<'a> Handler<'a, P, R, U, E>,
{
    println!("in wrapper: {:?}, {:?}", request.callback_id(), request.state_key());
    handler.handle(provider, request).await
}
