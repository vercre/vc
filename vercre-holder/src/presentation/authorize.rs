//! # Issuance Authorization Endpoint
//!
//! The authorize endpoint receives confirmation from the holder that they
//! authorize the agent to present the credential to the verifier.

use anyhow::{anyhow, bail};
use tracing::instrument;

use super::{Presentation, Status};
use crate::provider::HolderProvider;

/// Updates the status of the flow as authorized. The request is the
/// presentation flow ID generated by the `request` endpoint.
#[instrument(level = "debug", skip(provider))]
pub async fn authorize(provider: impl HolderProvider, request: String) -> anyhow::Result<Status> {
    tracing::debug!("Endpoint::authorize");

    let Ok(mut presentation) = super::get_presentation(provider.clone(), &request).await else {
        let e = anyhow!("unable to retrieve presentation state");
        tracing::error!(target: "Endpoint::authorize", ?e);
        return Err(e);
    };

    if presentation.status != Status::Requested {
        let e = anyhow!("invalid presentation state");
        tracing::error!(target: "Endpoint::authorize", ?e);
        return Err(e);
    }
    presentation.status = Status::Authorized;
    if let Err(e) = super::put_presentation(provider.clone(), &presentation).await {
        tracing::error!(target: "Endpoint::authorize", ?e);
        return Err(e);
    }
    Ok(presentation.status)
}

impl Presentation {
    /// Authorize the presentation request.
    /// 
    /// # Errors
    /// Will return an error if there are no credentials to present.
    pub fn authorize(&mut self) -> anyhow::Result<()> {
        if self.credentials.is_empty() {
            bail!("no credentials to present");
        }
        self.status = Status::Authorized;
        Ok(())
    }
}