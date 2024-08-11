//! # DID Resolver
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod document;
mod key;
mod web;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::did::document::{Document, DocumentMetadata, Service, VerificationMethod};
use crate::{did, DidResolver};

/// Did Result type using did module-specific Error
pub type Result<T> = std::result::Result<T, Error>;

/// Dereference a DID URL into a resource.
///
/// # Errors
pub async fn dereference(
    did_url: &str, opts: Option<Options>, resolver: &impl DidResolver,
) -> did::Result<Dereferenced> {
    // extract DID from DID URL
    let url = url::Url::parse(did_url)
        .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;
    let did = format!("did:{}", url.path());

    // resolve DID document
    let method = did_url.split(':').nth(1).unwrap_or_default();
    let resolution = match method {
        "key" => key::DidKey::resolve(&did, opts, resolver)?,
        "web" => web::DidWeb::resolve(&did, opts, resolver).await?,
        _ => return Err(Error::MethodNotSupported(format!("{method} is not supported"))),
    };

    let Some(document) = resolution.document else {
        return Err(Error::InvalidDid("Unable to resolve DID document".into()));
    };

    // process document to dereference DID URL for requested resource
    let Some(verifcation_methods) = document.verification_method else {
        return Err(Error::NotFound("verification method missing".into()));
    };

    // for now we assume the DID URL is the ID of the verification method
    // e.g. did:web:demo.credibil.io#key-0
    let Some(vm) = verifcation_methods.iter().find(|vm| vm.id == did_url) else {
        return Err(Error::NotFound("verification method not found".into()));
    };

    Ok(Dereferenced {
        metadata: Metadata {
            content_type: ContentType::DidLdJson,
            ..Metadata::default()
        },
        content_stream: Some(Resource::VerificationMethod(vm.clone())),
        content_metadata: Some(ContentMetadata {
            document_metadata: resolution.document_metadata,
        }),
    })
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

// /// The DID URL syntax supports parameters in the URL query component. Adding a DID
// /// parameter to a DID URL means the parameter becomes part of the identifier for a
// /// resource.
// #[derive(Clone, Debug, Default, Deserialize, Serialize)]
// #[serde(rename_all = "camelCase")]
// pub struct Parameters {
//     /// Identifies a service from the DID document by service's ID.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub service: Option<String>,

//     /// A relative URI reference that identifies a resource at a service endpoint,
//     /// which is selected from a DID document by using the service parameter.
//     /// MUST use URL encoding if set.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(alias = "relative-ref")]
//     pub relative_ref: Option<String>,

//     /// Identifies a specific version of a DID document to be resolved (the version ID
//     /// could be sequential, or a UUID, or method-specific).
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub version_id: Option<String>,

//     /// Identifies a version timestamp of a DID document to be resolved. That is, the
//     /// DID document that was valid for a DID at a certain time.
//     /// An XML datetime value [XMLSCHEMA11-2] normalized to UTC 00:00:00 without
//     /// sub-second decimal precision. For example: 2020-12-20T19:17:47Z.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub version_time: Option<String>,

//     /// A resource hash of the DID document to add integrity protection, as specified
//     /// in [HASHLINK]. This parameter is non-normative.
//     #[serde(skip_serializing_if = "Option::is_none")]
//     #[serde(rename = "hl")]
//     pub hashlink: Option<String>,

//     /// Additional parameters.
//     #[serde(flatten)]
//     pub additional: Option<HashMap<String, Value>>,
// }

/// Returned by `resolve` DID methods.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resolved {
    /// Resolution metadata.
    pub metadata: Metadata,

    /// The DID document.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document: Option<Document>,

    /// DID document metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub document_metadata: Option<DocumentMetadata>,
}

/// `Dereferenced` contains the result of dereferencing a DID URL.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Dereferenced {
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

/// Resource represents the DID document resource returned as a result of DID
/// dereferencing. The resource is a DID document or a subset of a DID document.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum Resource {
    ///  DID `Document` resource.
    Document(Document),

    /// `VerificationMethod` resource.
    VerificationMethod(VerificationMethod),

    /// `Service` resource.
    Service(Service),
}

impl Default for Resource {
    fn default() -> Self {
        Self::Document(Document::default())
    }
}

/// DID document metadata.
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
    /// JSON-LD representation of a DID document.
    #[default]
    #[serde(rename = "application/did+ld+json")]
    DidLdJson,
    //
    // /// The JSON-LD Media Type.
    // #[serde(rename = "application/ld+json")]
    // LdJson,
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
    pub document_metadata: Option<DocumentMetadata>,
}

/// DID resolution error codes
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The DID method is not supported.
    #[error("methodNotSupported")]
    MethodNotSupported(String),

    /// The DID supplied to the DID resolution function does not conform to
    /// valid syntax.
    #[error("invalidDid")]
    InvalidDid(String),

    /// The DID resolver was unable to find the DID document resulting from
    /// this resolution request.
    #[error("notFound")]
    NotFound(String),

    /// The representation requested via the accept input metadata property is not
    /// supported by the DID method and/or DID resolver.
    #[error("representationNotSupported")]
    RepresentationNotSupported(String),

    /// The DID URL is invalid
    #[error("invalidDidUrl")]
    InvalidDidUrl(String),

    // ---- Creation Errors ----  //
    /// The byte length of raw public key does not match that expected for the
    /// associated multicodecValue.
    #[error("invalidPublicKeyLength")]
    InvalidPublicKeyLength(String),

    /// The public key is invalid
    #[error("invalidPublicKey")]
    InvalidPublicKey(String),

    /// Public key format is not known to the implementation.
    #[error("unsupportedPublicKeyType")]
    UnsupportedPublicKeyType(String),

    /// Other, unspecified errors.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    /// Returns the error code.
    #[must_use]
    pub fn code(&self) -> String {
        self.to_string()
    }

    /// Returns the associated error message.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::MethodNotSupported(msg)
            | Self::InvalidDid(msg)
            | Self::NotFound(msg)
            | Self::InvalidDidUrl(msg)
            | Self::RepresentationNotSupported(msg)
            | Self::InvalidPublicKeyLength(msg)
            | Self::InvalidPublicKey(msg)
            | Self::UnsupportedPublicKeyType(msg) => msg.clone(),
            Self::Other(err) => err.to_string(),
        }
    }
}

#[cfg(test)]
mod test {
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;
    use crate::Binding;

    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _binding: Binding) -> anyhow::Result<Document> {
            serde_json::from_slice(include_bytes!("did/did-web-ecdsa.json"))
                .map_err(|e| anyhow!("issue deserializing document: {e}"))
        }
    }

    #[test]
    fn error_code() {
        let err = Error::MethodNotSupported("Method not supported".into());

        println!("err: {:?}", err.to_string());
        assert_eq!(err.message(), "Method not supported");
    }

    #[tokio::test]
    async fn deref_web() {
        const DID_URL: &str = "did:web:demo.credibil.io#key-0";

        let dereferenced =
            dereference(DID_URL, None, &MockResolver).await.expect("should dereference");
        assert_snapshot!("deref_web", dereferenced);
    }

    #[tokio::test]
    async fn deref_key() {
        const DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

        let dereferenced =
            dereference(DID_URL, None, &MockResolver).await.expect("should dereference");
        assert_snapshot!("deref_key", dereferenced);
    }
}
