//! # Issuance Offer Set PIN
//!
//! The `pin` endpoint is used to set a PIN for use in the token request as part
//! of the issuance flow.

use anyhow::bail;

use super::{IssuanceState, Status};

impl IssuanceState {
    /// Progress the issuance flow by setting a PIN.
    /// 
    /// # Errors
    /// Will return an error if the current state is inconsistent with setting a
    /// PIN.
    pub fn pin(&mut self, pin: &str) -> anyhow::Result<()> {
        if self.status != Status::PendingPin {
            bail!("invalid issuance state status");
        };
    
        // Update the state of the flow to indicate the PIN has been set.
        self.pin = Some(pin.into());
        self.status = Status::Accepted;

        Ok(())
    }
}
