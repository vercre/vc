//! # Issuance Offer Acceptance
//!
//! The `accept` endpoint is used to register acceptance of a credential issuance offer with the
//! issuance flow. If a PIN is required, this endpoint will simply update the state to indicate
//! that, otherwise it will proceed with the token request and credential requests.

use std::fmt::Debug;

use anyhow::anyhow;
use tracing::instrument;

use crate::issuance::{Issuance, Status};
use crate::provider::StateManager;
use crate::Endpoint;

impl<P> Endpoint<P>
where
    P: StateManager + Debug,
{
    /// Progresses the issuance flow triggered by a holder accepting a credential offer.
    /// The request is the issuance flow ID.
    #[instrument(level = "debug", skip(self))]
    pub async fn accept(&self, request: String) -> anyhow::Result<Issuance> {
        tracing::debug!("Endpoint::accept");

        let mut issuance = match self.get_issuance(&request).await {
            Ok(issuance) => issuance,
            Err(e) => {
                tracing::error!(target: "Endpoint::accept", ?e);
                return Err(e);
            }
        };

        if issuance.status != Status::Ready {
            let e = anyhow!("invalid issuance state");
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        }
        let Some(grants) = &issuance.offer.grants else {
            let e = anyhow!("no grants");
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        };
        let Some(pre_auth_code) = &grants.pre_authorized_code else {
            let e = anyhow!("no pre-authorized code");
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        };
        if pre_auth_code.tx_code.is_some() {
            issuance.status = Status::PendingPin;
        } else {
            issuance.status = Status::Accepted;
        }

        // Stash the state for the next step.
        if let Err(e) = self.put_issuance(&issuance).await {
            tracing::error!(target: "Endpoint::accept", ?e);
            return Err(e);
        };

        Ok(issuance)
    }
}
