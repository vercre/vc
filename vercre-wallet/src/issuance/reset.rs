//! # Reset Issuance Flow endpoint
//! 
//! Used to clear the issuance state in case of error handling or when the Holder rejects or cancels
//! an issuance offer.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::provider::{Callback, Client, Signer, StateManager, Storer};
use vercre_core::Result;

use crate::Endpoint;

impl<P> Endpoint<P>
    where
        P: Callback + Client + Signer + StateManager + Storer + Clone + Debug,
{
    /// Reset endpoint clears issuance state.
    /// 
    /// # Errors
    /// 
    /// Returns an error if the provider is unavailable or fails.
    #[instrument(level = "debug", skip(self))]
    pub async fn reset(&self) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, &(), ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = ();
    type Response = ();

    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(&mut self, _providier: &P, _req: &Self::Request) -> Result<&Self> {
        Ok(self)
    }

    async fn process(&self, provider: &P, _req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Clear the issuance state
        provider.purge("issuance").await?;

        Ok(())
    }
}
