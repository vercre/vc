//! # Holder Agent (Wallet)
//!
//! This module defines types and traits to enable wallets or other holder
//! agents to interact with the `vercre-holder` endpoints.

use std::ops::Deref;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vercre_openid::issuer::CredentialDisplay;
use vercre_w3c_vc::model::VerifiableCredential;

/// The Credential model contains information about a credential owned by the
/// Wallet.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Credential {
    /// Credential `id` is the credential's unique identifier
    /// (from Verifiable Credential `id` or generated if credential has no
    /// `id`).
    pub id: String,

    /// The credential issuer.
    pub issuer: String,

    /// The unpacked Verifiable Credential. Used to display VC details and for
    /// `JSONPath` Presentation Definition queries.
    pub vc: VerifiableCredential,

    /// The Verifiable Credential as issued, for use in Presentation
    /// Submissions. This could be a base64-encoded JWT or 'stringified'
    /// JSON.
    pub issued: String,

    /// The date the credential was issued.
    pub issuance_date: DateTime<Utc>,

    /// Display information from the issuer's metadata for this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// A base64-encoded logo image for the credential ingested from the logo
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Logo>,
}

/// Use Deref to access the `VerifiableCredential` fields directly.
impl Deref for Credential {
    type Target = VerifiableCredential;

    fn deref(&self) -> &Self::Target {
        &self.vc
    }
}

/// Logo information for a credential.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "EncodedLogo")]
pub struct Logo {
    /// The logo image as a base64-encoded string.
    pub image: String,

    /// Content type. e.g. "image/png"
    #[serde(rename = "mediaType")]
    pub media_type: String,
}
