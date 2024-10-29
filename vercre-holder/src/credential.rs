//! # Holder Agent (Wallet)
//!
//! This module defines types and traits to enable wallets or other holder
//! agents to interact with the `vercre-holder` endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_dif_exch::Claims;
use vercre_openid::issuer::CredentialDisplay;

/// A subject and its associated claims.
/// 
/// Similar to `vercre_w3c_vc::model::vc::CredentialSubject`, but with stronger
/// typing for wallet implementations that may use code generation.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CredentialSubject {
    /// The subject identifier.
    pub id: String,

    /// The claims associated with the subject.
    pub claims: Vec<Map<String, Value>>,
}

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

    /// The Verifiable Credential as issued, for use in Presentation
    /// Submissions. This could be a base64-encoded JWT or 'stringified'
    /// JSON.
    pub issued: String,

    /// The credential type. Used to determine whether a credential matches a
    /// presentation request.
    #[serde(rename = "type")]
    pub type_: Vec<String>,

    /// Credential format. Information on how the encoded credential is
    /// formatted.
    pub format: String,

    /// Claims as a JSON object.
    pub claims: Vec<Map<String, Value>>,

    /// The date the credential was issued.
    pub issuance_date: DateTime<Utc>,

    /// The date the credential is valid from.
    #[serde(skip_serializing_if = "Option::is_none")]    
    pub valid_from: Option<DateTime<Utc>>,

    /// The date the credential is valid until (expiry).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,

    /// Display information from the issuer's metadata for this credential.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<Vec<CredentialDisplay>>,

    /// A base64-encoded logo image for the credential ingested from the logo
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo: Option<Image>,

    /// A base64-encoded background image for the credential ingested from the
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<Image>,
}

/// Get the claims on the VC as a JSON object.
impl Claims for Credential {
    /// Serialize Claims as a JSON object.
    ///
    /// # Errors
    ///
    /// The implementation should return an error if the Claims cannot be
    /// serialized to JSON.
    fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        serde_json::to_value(self).map_err(Into::into)
    }
}

/// Image information for a credential.
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename = "Image")]
pub struct Image {
    /// The logo image as a base64-encoded string.
    pub image: String,

    /// Content type. e.g. "image/png"
    #[serde(rename = "mediaType")]
    pub media_type: String,
}
