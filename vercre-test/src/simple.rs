//! # Simple module

mod endpoint;
mod handler;

use std::fmt::Debug;

use handler::Handler;

use crate::IssuerProvider;

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub struct SimpleEndpoint<P>
where
    P: IssuerProvider,
{
    provider: P,
}

impl<P> SimpleEndpoint<P>
where
    P: IssuerProvider,
{
    #[allow(dead_code)]
    pub const fn with_provider(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> Handler for SimpleEndpoint<P>
where
    P: IssuerProvider + Debug,
{
    type Provider = P;

    fn provider(&self) -> &P {
        &self.provider
    }
}
