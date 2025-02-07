//! # Bitstring Status List
//!
//! Types and helpers for implementing a status list using a bitstring. Follows
//! the specification [Bitstring Status List v1.0](https://www.w3.org/TR/vc-bitstring-status-list/).

use std::io::Write;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use bitvec::bits;
use bitvec::order::Lsb0;
use bitvec::view::BitView;
use chrono::Utc;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;
use credibil_infosec::Signer;
use vercre_w3c_vc::model::{CredentialStatus, CredentialSubject, StatusPurpose, VcBuilder};
use vercre_w3c_vc::proof::{self, Payload, W3cFormat};

use crate::config::ListConfig;
use crate::log::StatusLogEntry;
use crate::verifier;

// TODO: Configurable.
// TODO: This is minimum length as per spec. May need to be configurable
// for data VCs where potentially huge numbers of credentials of a type
// can be issued. Or we need to use a more sophisticated list sharding.
// (Currently assumes one list per credential type.) Business requirements
// for short-lived data credentials may not require status lists anyway and
// we could just bump up this limit to something large but practical and
// only support lists up to that length. Alternatively, we can re-use list
// entries once a credential expires.
const MAX_ENTRIES: usize = 131_072;

/// Default time-to-live in milliseconds for a status list credential.
pub const DEFAULT_TTL: u64 = 300_000;

/// Standard error codes for bitstring-based status list validation.
///
/// The standard calls for returning strongly typed errors when a verifier
/// attempts to validate a verifiable credential against a published status
/// list.
///
/// [Processing Errors](https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors)
#[derive(Error, Debug, Deserialize)]
pub enum Error {
    /// Retrievel of the status list failed.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-128", "code": -128, "title": "status retrieval error", "detail": "{0}"}}"#)]
    Retrieval(String),

    /// Validation of the status entry failed.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-129", "code": -129, "title": "status verification error", "detail": "{0}"}}"#)]
    Verification(String),

    /// The status list length does not satisfy the minimum length required for
    /// herd privacy.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-130", "code": -130, "title": "status list length error", "detail": "{0}"}}"#)]
    ListLength(String),

    /// The index into the status list is larger than the length of the list.
    #[error(r#"{{"type": "https://www.w3.org/ns/credentials/status-list#-67", "code": -67, "title": "range error", "detail": "{0}"}}"#)]
    Range(String),
}

impl Serialize for Error {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as SerdeError;

        let Ok(error) = serde_json::from_str::<ValidationError>(&self.to_string()) else {
            return Err(SerdeError::custom("failed to serialize error"));
        };
        error.serialize(serializer)
    }
}

impl Error {
    /// Transform error to `ValidationError` compatible json format.
    #[must_use]
    pub fn to_json(self) -> serde_json::Value {
        serde_json::from_str(&self.to_string()).unwrap_or_default()
    }
}

/// Error response for bitstring status list validation.
///
/// [Processing Errors](https://www.w3.org/TR/vc-bitstring-status-list/#processing-errors)
/// [RFC 9457: Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457)
#[derive(Deserialize, Serialize)]
pub struct ValidationError {
    /// Type of error in URL format.
    ///
    /// The type value of the error object MUST be a URL that starts with the
    /// value `https://www.w3.org/ns/credentials/status-list#` and ends with the
    /// value in the section listed below.
    #[serde(rename = "type")]
    pub type_: String,

    /// Integer code
    ///
    /// The code value MUST be the integer code described in the specification.
    pub code: i32,

    /// Title
    ///
    /// The title value SHOULD provide a short but specific human-readable
    /// string for the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Detail
    ///
    /// The detail value SHOULD provide a longer human-readable string for the
    /// error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Generates a compressed, encoded bitstring representing the status list for
/// the given issued credentials and the purpose implied by a list
/// configuration.
///
/// # Errors
///
/// Returns an error if there is a compression or encoding problem, or the
/// provided status position is out of range of the bitstring size.
///
/// Must be a multi-base encoded base64 url without padding. It is the
/// encoded representation of the GZIP-compressed bitstring values for
/// the associated range of verifiable credential status values. The
/// uncompressed bitstring must be at least 16KB in size. The bitstring
/// must be encoded such that the first index, with a value of zero, is
/// located at the left-most bit in the bitstring, and the last index, with
/// a value of one less than the length of the bitstring, is located at the
/// right-most bit in the bitstring.
///
/// Note: This function scans the entire status log presented to construct a
/// bitstring from scratch which will be inefficient compared to a method for
/// processing a known update to the status of an individual credential. (A new
/// credential issued or an update to the status of an existing one).
//
// TODO: Provide methods for updating the bitstring incrementally.
#[allow(clippy::module_name_repetitions)]
pub fn bitstring(config: &ListConfig, issued: &[StatusLogEntry]) -> anyhow::Result<String> {
    let bits = bits![mut 0; MAX_ENTRIES];
    for entry in issued {
        for status in &entry.status {
            if status.purpose != config.purpose {
                continue;
            }

            let position = status.list_index * config.size;
            if position >= bits.len() {
                return Err(anyhow!("status index out of range"));
            }
            match config.purpose {
                StatusPurpose::Revocation | StatusPurpose::Suspension => {
                    bits.set(position, status.value != 0);
                }
                StatusPurpose::Message => {
                    let value = status.value.view_bits::<Lsb0>();
                    for (i, bit) in value.iter().enumerate() {
                        bits.set(position + i, *bit);
                    }
                }
            }
        }
    }

    let uncompressed = bits.into_iter().map(|b| if *b { '1' } else { '0' }).collect::<String>();

    let mut gz_encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz_encoder.write_all(uncompressed.as_bytes())?;
    let compressed = gz_encoder.finish()?;

    let encoded = Base64UrlUnpadded::encode_string(&compressed);

    Ok(encoded)
}

/// Generates a bitstring status list credential for the given status type.
///
/// The credential is suitable for publishing on an endpoint for verifiers to
/// check.
///
/// Requires the bitstring to be pre-generated. This allows for the implementer
/// to use an efficient generation and/or maintenance method.
///
/// If `ttl` is not provided, a value of `DEFAULT_TTL` will be used.
///
/// Generates a credential in `jwt_vc_json` format with a `jwt` proof type.
///
/// # Errors
///
/// * verifiable credential building errors.
/// * signing errors.
pub async fn credential(
    credential_issuer: &str, config: &ListConfig, status_list_base_url: &str, bitstring: &str,
    ttl: Option<u64>, signer: &impl Signer,
) -> anyhow::Result<String> {
    let mut base_url = status_list_base_url.to_string();
    if !base_url.ends_with('/') {
        base_url.push('/');
    }
    let id = format!("{base_url}/{}", config.list);

    let mut claims = Map::new();
    claims.insert("type".into(), Value::String("BitstringStatusList".into()));
    claims.insert("purpose".into(), Value::String(config.purpose.to_string()));
    claims.insert("encodedList".into(), Value::String(bitstring.into()));

    let cache_time = ttl.unwrap_or(DEFAULT_TTL);
    claims.insert("ttl".into(), Value::Number(cache_time.into()));

    let issued_at = Utc::now().timestamp();

    let vc = VcBuilder::new()
        .id(id.clone())
        .add_type("BitstringStatusListCredential")
        .issuer(credential_issuer)
        .add_subject(CredentialSubject {
            id: Some(format!("{id}#list")),
            claims,
        })
        .build()?;
    let jwt = proof::create(W3cFormat::JwtVcJson, Payload::Vc { vc, issued_at }, signer).await?;

    Ok(jwt)
}

/// Validates a credential from the status information contained inside it.
///
/// Uses a provider to retrieve the status list, which is assumed to be in
/// bitstring format.
///
/// # Errors
///
/// Will return a specific `ValidationError` if the status list is not resolved
/// or processing the status list fails for the given `CredentialStatus`.
pub fn validate(
    _resolver: &impl verifier::Status, _status: &CredentialStatus,
) -> Result<bool, Error> {
    // The following process, or one generating the exact output, MUST be followed
    // when validating a verifiable credential that is contained in a
    // BitstringStatusListCredential. The algorithm takes a status list verifiable
    // credential as input and either throws an error or returns a status list
    // credential as output.

    // Let credentialToValidate be a verifiable credential containing a
    // credentialStatus entry that is a BitstringStatusListEntry.
    // Let minimumNumberOfEntries be 131,072 unless a different lower bound is
    // established by a specific ecosystem specification. Let status purpose be
    // the value of statusPurpose in the credentialStatus entry in the
    // credentialToValidate. Dereference the statusListCredential URL, and
    // ensure that all proofs verify successfully. If the dereference fails, raise a
    // STATUS_RETRIEVAL_ERROR. If any of the proof verifications fail, raise a
    // STATUS_VERIFICATION_ERROR. Verify that the status purpose is equal to a
    // statusPurpose value in the statusListCredential. Note: The
    // statusListCredential might contain multiple status purposes in a single list.
    // If the values are not equal, raise a STATUS_VERIFICATION_ERROR.
    // Let compressed bitstring be the value of the encodedList property of the
    // BitstringStatusListCredential. Let credentialIndex be the value of the
    // statusListIndex property of the BitstringStatusListEntry. Generate a
    // revocation bitstring by passing compressed bitstring to the Bitstring
    // Expansion Algorithm. If the length of the revocation bitstring divided by
    // statusSize is less than minimumNumberOfEntries, raise a
    // STATUS_LIST_LENGTH_ERROR. Let status be the value in the bitstring at the
    // position indicated by the credentialIndex multiplied by the size. If the
    // credentialIndex multiplied by the size is a value outside of the range of the
    // bitstring, a RANGE_ERROR MUST be raised. Let result be an empty map.
    // Set the status key in result to status, and set the purpose key in result to
    // the value of statusPurpose. If status is 0, set the valid key in result
    // to true; otherwise, set it to false. If the statusPurpose is message, set
    // the message key in result to the corresponding message of the value as
    // indicated in the statusMessages array. Return result.
    // When a statusListCredential URL is dereferenced, server implementations MAY
    // provide a mechanism to dereference the status list as of a particular point
    // in time. When an issuer provides such a mechanism, it enables a verifier to
    // determine changes in status to a precision chosen by the issuer, such as
    // hourly, daily, or weekly. If such a feature is supported, and if query
    // parameters are supported by the URL scheme, then the name of the query
    // parameter MUST be timestamp and the value MUST be a valid URL-encoded
    // [XMLSCHEMA11-2] dateTimeStamp string value. The result of dereferencing such
    // a timestamp-parameterized URL MUST be either a status list credential
    // containing the status list as it existed at the given point in time, or a
    // STATUS_RETRIEVAL_ERROR. If the result is an error, implementations MAY
    // attempt the retrieval again with a different timestamp value, or without a
    // timestamp value, as long as the verifier's validation rules permit such an
    // action.

    // Verifiers SHOULD cache the retrieved status list and SHOULD use proxies or
    // other mechanisms, such as Oblivious HTTP, that hide retrieval behavior from
    // the issuer.

    // Note: Issuer validation is use case dependent
    // It is expected that a verifier will ensure that it trusts the issuer of a
    // verifiable credential, as well as the issuer of the associated
    // BitstringStatusListCredential, before using the information contained in
    // either credential for further decision making purposes. Implementers are
    // advised that the issuers of these credential might differ, such as when the
    // original issuer of the verifiable credential does not maintain a record of
    // its validity.

    todo!()
}
