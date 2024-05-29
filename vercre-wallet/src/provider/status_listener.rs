//! # Status Listener
//! 
//! The status listener trait allows a client to receive updates as the wallet progresses through a
//! flow. Note that this mechanism is only providing status updates on wallet progress. There is a
//! separate callback mechanism defined in the OpenID for Verifiable Credential Issuance and
//! OpenID for Verifiable Presentation specifiations that provide for an endpoint-based callback
//! directly from the issuance or verification services. 

use crate::issuance::Status as IssuanceStatus;
use crate::presentation::Status as PresentationStatus;

pub trait StatusListener {
    /// Notify the listener of a status change during the issuance process.
    fn notify_issuance(&self) -> IssuanceStatus;
}