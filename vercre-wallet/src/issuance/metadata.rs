//! # Metadata endpoint.
//!
//! Used to get metadata from an issuer based on the information supplied in a credential offer.

use std::fmt::Debug;

use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{Callback, Signer, StateManager};
use vercre_core::vci::MetadataResponse;
use vercre_core::{err, Result};

use crate::issuance::{Issuance, Status};
use crate::storer::CredentialStorer;
use crate::{Endpoint, Flow};

impl<P> Endpoint<P>
where
    P: Callback + Signer + StateManager + Clone + Debug + CredentialStorer,
{
    /// Metadata endpoint receives issuer metadata from wallet client. It is the responsibility of
    /// the client to retrieve the metadata and pass it to this endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the provider is unavailable.
    #[instrument(level = "debug", skip(self))]
    pub async fn metadata(&self, request: &MetadataResponse) -> Result<()> {
        let ctx = Context {
            _p: std::marker::PhantomData,
            issuance: Issuance::default(),
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug, Default)]
struct Context<P> {
    _p: std::marker::PhantomData<P>,
    issuance: Issuance,
}

impl<P> vercre_core::Context for Context<P>
where
    P: StateManager + Debug,
{
    type Provider = P;
    type Request = MetadataResponse;
    type Response = ();

    async fn verify(&mut self, provider: &P, req: &Self::Request) -> Result<&Self> {
        tracing::debug!("Context::verify");

        if req.credential_issuer.credential_configurations_supported.is_empty() {
            err!(Err::InvalidRequest, "no credential configurations");
        }

        // Check we are processing an offer from this issuer and we are at the expected point in
        // the flow.
        let Some(stashed) = provider.get_opt(&Flow::Issuance.to_string()).await? else {
            err!(Err::InvalidRequest, "no issuance in progress");
        };
        let issuance: Issuance = serde_json::from_slice(&stashed)?;
        if issuance.offer.credential_issuer != req.credential_issuer.credential_issuer {
            err!(Err::InvalidRequest, "issuer mismatch");
        }
        if issuance.status != Status::Offered {
            err!(Err::InvalidRequest, "invalid issuance status");
        }
        self.issuance = issuance;

        Ok(self)
    }

    async fn process(
        &self, provider: &Self::Provider, req: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // Get the offer from state and populate with credential configurations.
        let mut issuance = self.issuance.clone();

        let creds_supported = &req.credential_issuer.credential_configurations_supported;

        for (cfg_id, cred_cfg) in &mut issuance.offered {
            // find supported credential in metadata and copy to state object.
            let Some(found) = creds_supported.get(cfg_id) else {
                issuance.status =
                    Status::Failed(String::from("Unsupported credential type in offer"));
                err!(Err::InvalidRequest, "unsupported credential type in offer");
            };
            *cred_cfg = found.clone();
        }
        issuance.status = Status::Ready;
        provider.put_opt(&Flow::Issuance.to_string(), serde_json::to_vec(&issuance)?, None).await?;

        Ok(())
    }
}
