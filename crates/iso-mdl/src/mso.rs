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

pub type ValueDigests = BTreeMap<NameSpace, DigestIds>;
pub type NameSpace = String;
pub type DigestIds = BTreeMap<DigestId, Digest>;

/// DigestID is an unsigned integer used to match the hashes in the MSO to the
/// data elements in the mdoc response.
///
/// The Digest ID must be unique within a namespace with no correlation between
/// ID’s for the same namespace/element in different MSO’s. The value must be
/// smaller than 2^31.
pub type DigestId = i32;

pub type Digest = Vec<u8>;

/// An mdoc digital signature is generated over the mobile security object (MSO).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileSecurityObject {
    /// Version of the MobileSecurityObject. Must be 1.0.
    version: Version,

    /// Message digest algorithm used.
    digest_algorithm: DigestAlgorithm,

    /// An ordered set of value digests for each data element in each name space.
    value_digests: ValueDigests,

    /// Device key information
    device_key_info: DeviceKeyInfo,

    /// The document type of the document being signed.
    doc_type: String,

    /// Validity information for the MSO
    validity_info: ValidityInfo,
}

/// Digest algorithm used by the MSO.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Version {
    /// Version 1.0
    #[serde(rename = "1.0")]
    V1_0,
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

/// Used to hold the mdoc authentication public key and information related to
/// this key. Encoded as an untagged `COSE_Key` element as specified in
/// [RFC 9052] and [RFC 9053].
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
    key_info: Option<BTreeMap<i64, ciborium::Value>>,
}

/// Name spaces authorized for the MSO
pub type AuthorizedNameSpaces = Vec<NameSpace>;

/// Data elements authorized for the MSO
pub type AuthorizedDataElements = BTreeMap<NameSpace, DataElementsArray>;

/// Array of data element identifiers
pub type DataElementsArray = Vec<DataElementIdentifier>;

/// Data element identifier
pub type DataElementIdentifier = String;

/// Key authorization
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyAuthorization {
    /// Key authorization namespace
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_spaces: Option<AuthorizedNameSpaces>,

    /// Map of data elements by name space.
    /// e.g. <namespace: [data elements]>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_elements: Option<AuthorizedDataElements>,
}

/// Contains information related to the validity of the MSO and its signature.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidityInfo {
    /// Time the MSO was signed
    signed: String,

    /// The timestamp before which the MSO is not yet valid. Should be equal
    /// or later than the `signed` element
    valid_from: String,

    /// The timestamp after which the MSO is no longer valid.
    ///
    /// The value must be later than the `valid_from` element.
    valid_until: String,

    /// The time at which the issuing authority expects to re-sign the MSO
    /// (and potentially update data elements).
    pub expected_update: Option<String>,
}
