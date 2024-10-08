//! # Mobile Security Object (MSO)
//!
//! The MSO is used to provide Issuer data authentication for the associated
//! `mdoc`. It contains a signed digest (e.g. SHA-256) of the `mdoc`, including
//! the digests in the MSO.
//!
//! See 9.1.2.4 Signing method and structure for MSO.

use std::collections::BTreeMap;

use coset::CoseSign1;
use serde::{Deserialize, Serialize};

use crate::cose::{CoseKey, Tagged};

/// Signed payload of MobileSecurityObjectBytes
/// MobileSecurityObjectBytes = #6.24(bstr .cbor MobileSecurityObject)
pub type IssuerAuth = Tagged<CoseSign1>;

pub type ValueDigests = BTreeMap<Namespace, DigestIds>;
pub type Namespace = String;
pub type DigestIds = Vec<BTreeMap<DigestId, Digest>>;
pub type DigestId = i32;
pub type Digest = Vec<u8>;

/// An mdoc digital signature is generated over the mobile security object (MSO).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    /// Version of the MobileSecurityObject
    version: String,

    /// Message digest algorithm used.
    digest_algorithm: DigestAlgorithm,

    /// An order set of value digests for each data element in each namespace.
    value_digests: ValueDigests,

    /// Device key information
    device_key_info: DeviceKeyInfo,

    /// Document type as used in Documents
    doc_type: String,

    /// Validity information for the MSO
    validity_info: ValidityInfo,
}

/// Digest algorithm used by the MSO.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DigestAlgorithm {
    /// SHA-256
    #[serde(rename = "SHA-256")]
    SHA256,

    /// SHA-384
    #[serde(rename = "SHA-384")]
    SHA384,

    /// SHA-512
    #[serde(rename = "SHA-512")]
    SHA512,
}

/// Device key info holds mdoc authentication public key.
/// Encoded as an untagged `COSE_Key` element as specified in [RFC 9052], [RFC 9053]
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceKeyInfo {
    /// Device key
    device_key: BTreeMap<usize, CoseKey>,

    /// Key authorizations
    #[serde(skip_serializing_if = "Option::is_none")]
    key_authorizations: Option<Vec<KeyAuthorization>>,

    /// Key info
    #[serde(skip_serializing_if = "Option::is_none")]
    key_info: Option<BTreeMap<i64, DeviceKey>>,
}

/// Device key
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum DeviceKey {
    /// Device key as a string
    String(String),

    /// Device key as an integer
    Int(i64),
}

/// Key authorization
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorization {
    /// Key authorization namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<Vec<String>>,

    /// Map of data elements by name space.
    /// e.g. <namespace: [data elements]>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<BTreeMap<String, Vec<String>>>,
}

/// Validity information for the MSO
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    /// Time the MSO was signed
    signed: String,

    /// Time the MSO is valid from
    valid_from: String,

    /// Time the MSO is valid until
    valid_until: String,
}
