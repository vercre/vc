//! # Model

//! # MSO MDOC
//!
//! See pg 31 of spec.
//!
//! The Mobile Security Object (MSO) Mobile Device Object (MDOC) is a data
//! structure that contains the data elements that are signed by the issuer
//! and the mobile device. The issuer signs the data elements to authenticate
//! the issuer data, and the mobile device signs the data elements to
//! authenticate the mobile device data. The MSO MDOC is returned in the
//! DeviceResponse structure.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::tag24::Tag24;
use crate::{bytes, mso};

/// Error codes for unreturned documents
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ErrorCode {
    /// Error code for unreturned documents
    SomeCode,
}

/// Data elements signed by the issuer
///
/// See 8.3.2.1.2.2 Device retrieval mdoc response.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSigned {
    /// Returned data elements
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<IssuerNameSpaces>,

    /// The mobile security object (MSO) for issuer data authentication.
    /// COSE_Sign1 with a payload of MobileSecurityObjectBytes
    pub issuer_auth: mso::IssuerAuth,
}

/// Returned data elements for each namespace
pub type IssuerNameSpaces = HashMap<String, Vec<IssuerSignedItemBytes>>;

/// IssuerSignedItemBytes: to_bytes(Tag 24(bstr .cbor IssuerSignedItem))
pub type IssuerSignedItemBytes = Tag24<IssuerSignedItem>;

/// Issuer-signed data element
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuerSignedItem {
    /// Digest ID for issuer data authentication
    pub digest_id: i32,

    /// Random hexadecimal value for issuer data authentication.
    /// (min. 16 bytes).
    pub random: String,

    /// Data element identifier. For example, "family_name"
    pub element_identifier: String,

    /// Data element value. For example, "Smith"
    pub element_value: ciborium::Value,
}
