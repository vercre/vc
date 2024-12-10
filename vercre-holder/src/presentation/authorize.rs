//! # Issuance Authorization Endpoint
//!
//! The authorize endpoint receives confirmation from the holder that they
//! authorize the agent to present the credential to the verifier.

use anyhow::bail;

use super::{PresentationState, Status};

impl PresentationState {
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
