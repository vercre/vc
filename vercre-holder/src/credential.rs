//! # Holder Agent (Wallet)
//!
//! This module defines types and traits to enable wallets or other holder
//! agents to interact with the `vercre-holder` endpoints.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use vercre_dif_exch::Claims;
use vercre_openid::issuer::CredentialDisplay;
use vercre_w3c_vc::model::CredentialSubject;

/// A set of claims for a subject (holder).
/// 
/// (Some credentials can be issued to multiple subjects).
#[derive(Clone, Default, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubjectClaims {
    /// An identifier of the subject (holder) of the claims.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The claims for the subject as a map of JSON objects.
    pub claims: Map<String, Value>
}

impl From<CredentialSubject> for SubjectClaims {
    fn from(subject: CredentialSubject) -> Self {
        Self {
            id: subject.id,
            claims: subject.claims,
        }
    }
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

    /// Claims for one or more subjects (holders).
    pub subject_claims: Vec<SubjectClaims>,

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
    pub logo: Option<ImageData>,

    /// A base64-encoded background image for the credential ingested from the
    /// url in the display section of the metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background: Option<ImageData>,
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
pub struct ImageData {
    /// The logo image as a base64-encoded string.
    pub data: String,

    /// Content type. e.g. "image/png"
    #[serde(rename = "mediaType")]
    pub media_type: String,
}
