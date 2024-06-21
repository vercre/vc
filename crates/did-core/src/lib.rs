#![allow(missing_docs)]

//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

mod did;
mod document;
mod key;

use std::collections::HashMap;

use anyhow::anyhow;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::did::Error;
use crate::document::{Document, DocumentMetadata};

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
pub fn resolve(did: &str, opts: Option<Options>) -> did::Result<Resolution> {
    // use DID-specific resolver
    let method = did.split(':').nth(1).unwrap_or_default();
    let result = match method {
        "key" => key::DidKey.resolve(did, opts),
        _ => Err(Error::MethodNotSupported(format!("{method} is not supported"))),
    };

    if let Err(e) = result {
        return Ok(Resolution {
            metadata: Metadata {
                error: Some(e.to_string()),
                error_message: Some(e.message()),
                content_type: ContentType::DidLdJson,
                ..Metadata::default()
            },
            ..Resolution::default()
        });
    };

    result
}

/// DID resolution functions required to be implemented by conforming DID resolvers.
pub trait Resolver {
    /// Returns the DID document specifier by the `did` argument in its abstract form
    /// (a map).
    ///
    /// # Errors
    ///
    /// Returns an error if the DID cannot be resolved.
    fn resolve(&self, did: &str, opts: Option<Options>) -> did::Result<Resolution>;

    /// Returns the DID Document as a byte stream formatted to represent the Media Type
    /// specified in the `accept` property of the `options` argument.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID cannot be resolved.
    fn resolve_representation(&self, did: &str, opts: Option<Options>) -> did::Result<Vec<u8>> {
        let document = self.resolve(did, opts)?;

        // TODO: honour the accept property's media type
        serde_json::to_vec(&document).map_err(|e| Error::Other(anyhow!("issue decoding key: {e}")))
    }

    /// Dereferences the provided DID URL into a resource with contents depending on the
    /// DID URL's components, including the DID method, method-specific identifier, path,
    /// query, and fragment.
    ///
    /// See <https://w3c-ccg.github.io/did-resolution/#dereferencing> for more
    /// detail.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID cannot be dereferenced.
    // TODO: expand this error.
    fn dereference(&self, did_url: &str, opts: Option<Options>) -> did::Result<Resource>;
}

/// `ResolutionOptions` is used to pass addtional values to a `resolve` method. The
/// properties and values should be registered in the DID Specification Registries.
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
///
/// This property is OPTIONAL for the resolveRepresentation function and MUST NOT be
/// used with the resolve function.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Options<'a> {
    #[serde(borrow = "'a")]
    #[serde(flatten)]
    options: HashMap<&'a str, &'a str>,
}

impl<'a> Options<'a> {
    pub fn add(&mut self, key: &'a str, value: &'a str) {
        self.options.insert(key, value);
    }

    #[must_use]
    pub fn options(&self) -> HashMap<&str, &str> {
        self.options.clone()
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resolution {
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
pub struct Resource {
    /// A metadata structure consisting of values relating to the results of the
    /// DID URL dereferencing process. MUST NOT be empty in the case of an error.
    pub metadata: Metadata,

    /// The dereferenced resource corresponding to the DID URL. MUST be empty if
    /// dereferencing was unsuccessful. MUST be empty if dereferencing is
    /// unsuccessful.
    pub content_stream: Option<Document>,

    /// Metadata about the `content_stream`. If `content_stream` is a DID document,
    /// this MUST be `DidDocumentMetadata`. If dereferencing is unsuccessful, MUST
    /// be empty.
    pub content_metadata: Option<ContentMetadata>,
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

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct Jwk {
    /// Key identifier.
    /// For example, "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Key type
    pub kty: KeyType,

    /// Cryptographic curve type.
    pub crv: Curve,

    /// X coordinate.
    pub x: String,

    /// Y coordinate. Not required for `EdDSA` verification keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Use of the key. For example, "sig" for signing or "enc" for
    /// encryption.
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    OKP,
}

/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum Curve {
    /// Ed25519 curve
    #[default]
    Ed25519,
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use serde_json::{json, Value};

    use super::*;

    #[test]
    fn resolve_key() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let resolution = resolve(did, None).expect("should resolve");

        let res_str = serde_json::to_string(&resolution).expect("should deserialize");
        println!("{res_str}");

        let document: Document =
            serde_json::from_value(DID_KEY.to_owned()).expect("should deserialize");
        assert_eq!(resolution.document.unwrap(), document);
    }
    static DID_KEY: LazyLock<Value> = LazyLock::new(|| {
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                    "Ed25519VerificationKey2020": "https://w3id.org/security#Ed25519VerificationKey2020",
                    "publicKeyJwk": {
                        "@id": "https://w3id.org/security#publicKeyJwk",
                        "@type": "@json"
                    }
                }
            ],
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "verificationMethod": [
                {
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "type": "Ed25519VerificationKey2020",
                    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
                    }
                }
            ],
            "authentication": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "assertionMethod": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ]
        })
    });
}
