//! # `OpenID` Core

use futures::Future;
use openid::Result;
// use openid::endpoint::{Callback, Payload, Status};
// use openid::Err;

pub trait Request {
    fn callback_id(&self) -> Option<String>;
}

pub trait Handler<'a, R, U>: Send {
    fn handle(self, request: &'a R) -> impl Future<Output = Result<U>> + Send;
}

impl<'a, R: 'a, U, F, Fut> Handler<'a, R, U> for F
where
    F: FnOnce(&'a R) -> Fut + Send,
    Fut: Future<Output = Result<U>> + Send + Sync,
{
    fn handle(self, s: &'a R) -> impl Future<Output = Result<U>> + Send {
        self(s)
    }
}

pub async fn wrapper<R, U, F>(request: &R, handler: F) -> Result<U>
where
    R: Request + Sync,
    F: for<'a> Handler<'a, R, U>,
{
    println!("in wrapper: {}", request.callback_id().unwrap());
    handler.handle(request).await
}
