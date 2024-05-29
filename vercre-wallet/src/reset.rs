//! # Reset Issuance or Presentation Flow Endpoint
//! 
//! Used to clear the flow state in case of error handling. Used internally when a holder cancels
//! an issuance offer or presentation request.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::Result;

use crate::provider::{Callback, CredentialStorer, Signer, StateManager};
use crate::{Endpoint, Flow};

impl<P> Endpoint<P>
    where
        P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Reset endpoint clears issuance state.
    /// 
    /// # Errors
    /// 
    /// Returns an error if the provider is unavailable or fails.
    #[instrument(level = "debug", skip(self))]
    pub async fn reset(&self, request: &Flow) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
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
    type Request = Flow;
    type Response = ();

    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(&mut self, _providier: &P, _req: &Self::Request) -> Result<&Self> {
        Ok(self)
    }

    async fn process(&self, provider: &P, req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Clear the issuance state
        provider.purge(&req.to_string()).await?;

        Ok(())
    }
}
