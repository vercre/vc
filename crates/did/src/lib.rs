#![allow(missing_docs)]
#![feature(let_chains)]

//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod document;
pub mod error;
mod key;
mod web;

use std::collections::HashMap;
use std::future::Future;

pub use error::Error;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::document::{Document, DocumentMetadata, VerificationMethod};

pub type Result<T> = std::result::Result<T, Error>;

pub trait DidClient: Send + Sync {
    fn get(&self, url: &str) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}

/// Resolve a DID to a DID document.
///
/// The [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) functions
/// resolve a DID into a DID document by using the "Read" operation of the applicable
/// DID method.
///
/// Caveats:
/// - No JSON-LD Processing, however, valid JSON-LD is returned.
/// - Ignores accept header.
/// - Only returns application/did+ld+json.
/// - did:key support for ed25519
/// - did:web support for .well-known and path based DIDs.
///
/// # Errors
///
/// Returns a [DID resolution](https://www.w3.org/TR/did-core/#did-resolution-metadata)
/// error as specified.
pub async fn resolve(
    did: &str, opts: Option<Options>, client: impl DidClient,
) -> crate::Result<Resolve> {
    // use DID-specific resolver
    let method = did.split(':').nth(1).unwrap_or_default();

    let result = match method {
        "key" => key::DidKey::resolve(did, opts, client),
        "web" => web::DidWeb::resolve(did, opts, client).await,
        _ => Err(Error::MethodNotSupported(format!("{method} is not supported"))),
    };

    if let Err(e) = result {
        return Ok(Resolve {
            metadata: Metadata {
                error: Some(e.to_string()),
                error_message: Some(e.message()),
                content_type: ContentType::DidLdJson,
                ..Metadata::default()
            },
            ..Resolve::default()
        });
    };

    result
}

/// Dereference a DID URL into a resource.
///
/// # Errors
pub async fn dereference(
    did_url: &str, opts: Option<Options>, client: impl DidClient,
) -> crate::Result<Dereference> {
    let method = did_url.split(':').nth(1).unwrap_or_default();

    match method {
        "key" => key::DidKey::dereference(did_url, opts, client),
        "web" => web::DidWeb::dereference(did_url, opts, client).await,
        _ => Err(Error::MethodNotSupported(format!("{method} is not supported"))),
    }
}

/// Used to pass addtional values to a `resolve` and `dereference` methods. Any
/// properties used should be registered in the DID Specification Registries.
///
/// The `accept` property is common to all resolver implementations. It is used by
/// users to specify the Media Type when calling the `resolve_representation` method.
/// For example:
///
/// ```json
/// {
///    "accept": "application/did+ld+json"
/// }
/// ```
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Options {
    /// [`accept`](https://www.w3.org/TR/did-spec-registries/#accept) resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<ContentType>,

    // pub public_key_format: Option<String>,
    //
    /// Additional options.
    #[serde(flatten)]
    pub additional: Option<HashMap<String, Metadata>>,
}

/// The DID URL syntax supports parameters in the URL query component. Adding a DID
/// parameter to a DID URL means the parameter becomes part of the identifier for a
/// resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Parameters {
    /// Identifies a service from the DID document by service's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// A relative URI reference that identifies a resource at a service endpoint,
    /// which is selected from a DID document by using the service parameter.
    /// MUST use URL encoding if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "relative-ref")]
    pub relative_ref: Option<String>,

    /// Identifies a specific version of a DID document to be resolved (the version ID
    /// could be sequential, or a UUID, or method-specific).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,

    /// Identifies a version timestamp of a DID document to be resolved. That is, the
    /// DID document that was valid for a DID at a certain time.
    /// An XML datetime value [XMLSCHEMA11-2] normalized to UTC 00:00:00 without
    /// sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>,

    /// A resource hash of the DID document to add integrity protection, as specified
    /// in [HASHLINK]. This parameter is non-normative.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hl")]
    pub hashlink: Option<String>,

    /// Additional parameters.
    #[serde(flatten)]
    pub additional: Option<HashMap<String, Value>>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resolve {
    #[serde(rename = "@context")]
    pub context: String,

    /// Resolution metadata.
    pub metadata: Metadata,

    /// The DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Document>,

    /// DID document metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_metadata: Option<DocumentMetadata>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dereference {
    /// A metadata structure consisting of values relating to the results of the
    /// DID URL dereferencing process. MUST NOT be empty in the case of an error.
    pub metadata: Metadata,

    /// The dereferenced resource corresponding to the DID URL. MUST be empty if
    /// dereferencing was unsuccessful. MUST be empty if dereferencing is
    /// unsuccessful.
    pub content_stream: Option<Resource>,

    /// Metadata about the `content_stream`. If `content_stream` is a DID document,
    /// this MUST be `DidDocumentMetadata`. If dereferencing is unsuccessful, MUST
    /// be empty.
    pub content_metadata: Option<ContentMetadata>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Resource {
    VerificationMethod(VerificationMethod),
}

impl Default for Resource {
    fn default() -> Self {
        Self::VerificationMethod(VerificationMethod::default())
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    /// The Media Type of the returned resource.
    pub content_type: ContentType,

    /// The error code from the dereferencing process, if applicable.
    /// Values of this field SHOULD be registered in the DID Specification Registries.
    /// Common values are `invalid_did_url` and `not_found`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// A human-readable explanation of the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Additional information about the resolution or dereferencing process.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub additional: Option<Value>,
}

/// The Media Type of the returned resource.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum ContentType {
    #[default]
    #[serde(rename = "application/did+ld+json")]
    DidLdJson,

    #[serde(rename = "application/ld+json")]
    LdJson,
}

/// Metadata about the `content_stream`. If `content_stream` is a DID document,
/// this MUST be `DidDocumentMetadata`. If dereferencing is unsuccessful, MUST
/// be empty.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ContentMetadata {
    /// The DID document metadata.
    #[serde(flatten)]
    #[serde(skip_serializing_if = "Option::is_none")]
    document_metadata: Option<DocumentMetadata>,
}
