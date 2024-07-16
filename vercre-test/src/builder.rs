//! # Builder module

mod endpoint;
mod handler;

// use handler::Handler;

use crate::IssuerProvider;

/// Endpoint is used to surface the public Verifiable Presentation endpoints to
/// clients.
#[allow(clippy::module_name_repetitions)]
pub struct BuilderEndpoint<P>
where
    P: IssuerProvider,
{
    #[allow(dead_code)]
    provider: P,
}

impl<P> BuilderEndpoint<P>
where
    P: IssuerProvider,
{
    #[allow(dead_code)]
    pub const fn with_provider(provider: P) -> Self {
        Self { provider }
    }
}

// impl<P> Handler for BuilderEndpoint<P>
// where
//     P: IssuerProvider ,
// {
//     type Provider = P;

//     fn provider(&self) -> &P {
//         &self.provider
//     }
// }
