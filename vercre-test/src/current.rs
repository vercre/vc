//! # Builder module

mod endpoint;
mod handler;



use handler::Handler;

use crate::IssuerProvider;

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
pub struct CurrentEndpoint<P>
where
    P: IssuerProvider,
{
    provider: P,
}

impl<P> CurrentEndpoint<P>
where
    P: IssuerProvider,
{
    #[allow(dead_code)]
    pub fn with_provider(provider: P) -> Self {
        Self { provider }
    }
}

impl<P> Handler for CurrentEndpoint<P>
where
    P: IssuerProvider ,
{
    type Provider = P;

    fn provider(&self) -> &P {
        &self.provider
    }
}
