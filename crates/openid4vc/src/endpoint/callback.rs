//! # Client Callback
//!
//! This module defines the callback trait and helper functions used for
//! callbacks to client applications.

/// Indication of the status of an issuance or presentation flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// The vercre-wallet has received an issuance offer and has decided to action.
    IssuanceRequested,

    /// A credential issuance has been successfully processed.
    CredentialIssued,

    /// A presentation request has been made.
    PresentationRequested,

    /// A presentation has been successfully verified.
    PresentationVerified,

    /// An error occurred.
    Error,
}

/// Content of a status update.
pub struct Payload {
    /// Callback identifier
    pub id: String,

    /// Status of the issuance or presentation flow.
    pub status: Status,

    /// Description to give more textual information about the status.
    pub context: String,
}