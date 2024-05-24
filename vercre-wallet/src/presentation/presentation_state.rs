//! # Get Presentation State Endpoint
//! 
//! This endpoint returns the current state of the presentation process. The state objet is
//! initialized with defaults and the parts are populated with real data as the presentation flow
//! progresses, so careful consideration of the progress of the flow is required before using parts
//! of the state object. This endpoint simply returns whatever is stored in the state store at the
//! time of the request.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::provider::{Callback, Client, Signer, StateManager};
use vercre_core::Result;

use crate::presentation::Presentation;
use crate::store::CredentialStorer;
use crate::{Endpoint, Flow};

impl<P> Endpoint<P>
where
    P: Callback + Client + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Gets the current state of the presentation process. Can return None if no presentation is in
    /// progress.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn get_presentation(&self) -> Result<Option<Presentation>> {
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
    type Response = Option<Presentation>;

    fn callback_id(&self) -> Option<String> {
        None
    }

    async fn verify(&mut self, _provider: &P, _req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        Ok(self)
    }

    async fn process(&self, provider: &P, _req: &Self::Request) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Check we are processing an offer and we are at the expected point in the flow.
        match provider.get_opt(&Flow::Presentation.to_string()).await? {
            Some(stashed) => {
                let presentation: Presentation = serde_json::from_slice(&stashed)?;
                Ok(Some(presentation))
            }
            None => Ok(None),
        }
    }
}
