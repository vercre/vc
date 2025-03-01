//! # `OpenID` for Verifiable Credential Issuance

mod authorization;
mod credential;
mod credential_offer;
mod metadata;
mod token;

use std::fmt::Debug;

pub use authorization::*;
pub use credential::*;
pub use credential_offer::*;
pub use metadata::*;
use serde::{Deserialize, Serialize};
pub use token::*;

/// Used by the Wallet to notify the Credential Issuer of certain events for
/// issued Credentials. These events enable the Credential Issuer to take
/// subsequent actions after issuance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationRequest {
    /// The Credential Issuer for which the notification is intended.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub credential_issuer: String,

    /// A previously issued Access Token, as extracted from the Authorization
    /// header of the Credential Request. Used to grant access to register a
    /// client.
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub access_token: String,

    /// As received from the issuer in the Credential Response.
    pub notification_id: String,

    /// Type of the notification event.
    pub event: NotificationEvent,

    /// Human-readable ASCII text providing additional information, used to
    /// assist the Credential Issuer developer in understanding the event
    /// that occurred.
    ///
    /// Values for the `event_description` parameter MUST NOT include characters
    /// outside the set %x20-21 / %x23-5B / %x5D-7E.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_description: Option<String>,
}

/// Used by the Credential Issuer to notify the Wallet of certain events for
/// issued Credentials. These events enable the Wallet to take subsequent
/// actions after issuance.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[allow(clippy::enum_variant_names)]
pub enum NotificationEvent {
    /// Credential was successfully stored in the Wallet.
    CredentialAccepted,

    /// Used in all other unsuccessful cases.
    #[default]
    CredentialFailure,

    /// Used when unsuccessful Credential issuance was caused by a user action.
    CredentialDeleted,
}

/// When the Credential Issuer has successfully received the Notification
/// Request from the Wallet, it MUST respond with an HTTP status code in the 2xx
/// range.
///
/// Use of the HTTP status code 204 (No Content) is RECOMMENDED.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NotificationResponse {}
