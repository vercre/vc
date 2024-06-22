//! # DID Key Resolver
//!
//! See <https://w3c-ccg.github.io/did-resolution>

pub mod operations;

use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;

use crate::did::{self, Error};
use crate::document::{CreateOptions, Operator};
use crate::{ContentMetadata, ContentType, Metadata, Options, Resolution, Resolver, Resource};

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:(?<key>z[a-km-zA-HJ-NP-Z1-9]+)$").expect("should compile")
});
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:z[a-km-zA-HJ-NP-Z1-9]+(?:&?[^=&]*=[^=&]*)*(#z[a-km-zA-HJ-NP-Z1-9]+)*$")
        .expect("should compile")
});

#[allow(clippy::module_name_repetitions)]
pub struct DidKey;

impl Resolver for DidKey {
    fn resolve(&self, did: &str, _: Option<Options>) -> did::Result<Resolution> {
        // check DID is valid AND extract key
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:key".into()));
        };
        let key = &caps["key"];

        // per the spec, use the create operation to generate a DID document
        let options = CreateOptions {
            enable_encryption_key_derivation: true,
            ..CreateOptions::default()
        };

        let document =
            operations::DidOp.create(did, options).map_err(|e| Error::InvalidDid(e.to_string()))?;

        Ok(Resolution {
            context: "https://w3id.org/did-resolution/v1".into(),
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                additional: Some(json!({
                    "pattern": "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$",
                    "did": {
                        "didString": did,
                        "methodSpecificId": key,
                        "method": "key"
                    }
                })),
                ..Metadata::default()
            },
            document: Some(document),
            ..Resolution::default()
        })
    }

    fn dereference(&self, did_url: &str, _opts: Option<Options>) -> did::Result<Resource> {
        // validate URL against pattern
        if !URL_REGEX.is_match(did_url) {
            return Err(Error::InvalidDidUrl("invalid did:key URL".into()));
        }
        let url = url::Url::parse(did_url)
            .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;

        // extract URL parameters from query string (if any)
        // let params = match url.query().as_ref() {
        //     Some(query) => Some(
        //         serde_urlencoded::from_str::<Parameters>(query)
        //             .map_err(|e| Error::InvalidDidUrl(format!("issue parsing query: {e}")))?,
        //     ),
        //     None => None,
        // };

        // resolve DID document
        let did = format!("did:{}", url.path());
        let resolution = self.resolve(&did, None)?;

        Ok(Resource {
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                ..Metadata::default()
            },
            content_stream: resolution.document,
            content_metadata: Some(ContentMetadata {
                document_metadata: resolution.document_metadata,
            }),
        })
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;

    use serde_json::{json, Value};

    use super::*;
    use crate::document::Document;

    #[test]
    fn resolve() {
        let resolved = DidKey.resolve(DID, None).expect("should resolve");

        // check document is expected
        let document: Document =
            serde_json::from_value(DOCUMENT_MULTI.to_owned()).expect("should deserialize");
        assert_eq!(resolved.document, Some(document));

        // check metadata is expected
        let metadata: Metadata =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        assert_eq!(resolved.metadata, metadata);
    }

    #[test]
    fn dereference() {
        let resolved = DidKey.dereference(DID_URL, None).expect("should resolve");
        println!("did_url: {:?}", resolved);
    }

    const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    // const DID: &str = "did:key:z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p";
    const DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    static DOCUMENT_MULTI: LazyLock<Value> = LazyLock::new(|| {
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                "https://w3id.org/security/data-integrity/v1"
            ],
            "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "verificationMethod": [
                {
                    "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "type": "Multikey",
                    "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                    "publicKeyMultibase": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                }
            ],
            "authentication": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "assertionMethod": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "capabilityInvocation": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "capabilityDelegation": [
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
            ],
            "keyAgreement": [{
                "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p",
                "type": "Multikey",
                "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "publicKeyMultibase": "z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"
            }]
        })
    });
    // static DOCUMENT_JWK: LazyLock<Value> = LazyLock::new(|| {
    //     json!({
    //         "@context": [
    //             "https://www.w3.org/ns/did/v1",
    //             {
    //                 "Ed25519VerificationKey2020": "https://w3id.org/security#Ed25519VerificationKey2020",
    //                 "publicKeyJwk": {
    //                     "@id": "https://w3id.org/security#publicKeyJwk",
    //                     "@type": "@json"
    //                 }
    //             }
    //         ],
    //         "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //         "verificationMethod": [
    //             {
    //                 "id": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //                 "type": "Ed25519VerificationKey2020",
    //                 "controller": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    //                 "publicKeyJwk": {
    //                     "kty": "OKP",
    //                     "crv": "Ed25519",
    //                     "x": "Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY"
    //                 }
    //             }
    //         ],
    //         "authentication": [
    //             "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    //         ],
    //         "assertionMethod": [
    //             "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    //         ]
    //     })
    // });
    static METADATA: LazyLock<Value> = LazyLock::new(|| {
        json!({
          "contentType": "application/did+ld+json",
          "pattern": "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$",
          "did": {
            "didString": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "methodSpecificId": "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "method": "key"
          }
        })
    });
}
