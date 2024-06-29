//! # DID Key Resolver
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its core,
//! it is based on expanding a cryptographic public key into a DID Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c-ccg.github.io/did-resolution>

use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;

use super::DidKey;
use crate::did::{self, Error};
use crate::document::{CreateOptions, Operator};
use crate::{ContentMetadata, ContentType, Metadata, Options, Resolution, Resolver, Resource};

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:z[a-km-zA-HJ-NP-Z1-9]+(?:&?[^=&]*=[^=&]*)*(#z[a-km-zA-HJ-NP-Z1-9]+)*$")
        .expect("should compile")
});

impl Resolver for DidKey {
    fn resolve(&self, did: &str, _: Option<Options>) -> did::Result<Resolution> {
        // per the spec, use the create operation to generate a DID document
        let options = CreateOptions {
            enable_encryption_key_derivation: true,
            ..CreateOptions::default()
        };

        let document = DidKey.create(did, options).map_err(|e| Error::InvalidDid(e.to_string()))?;

        Ok(Resolution {
            context: "https://w3id.org/did-resolution/v1".into(),
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                additional: Some(json!({
                    "pattern": "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$",
                    "did": {
                        "didString": did,
                        "methodSpecificId": did[8..],
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
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;

    const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    #[test]
    fn resolve() {
        let resolved = DidKey.resolve(DID, None).expect("should resolve");

        assert_snapshot!("document", resolved.document);
        assert_snapshot!("metadata", resolved.metadata);
    }

    #[test]
    fn dereference() {
        let resource = DidKey.dereference(DID_URL, None).expect("should resolve");

        assert_snapshot!("resource", resource);
    }
}
