//! # DID Key Resolver
//!
//! See <https://w3c-ccg.github.io/did-method-key/#create>

use std::sync::LazyLock;

use base64ct::{Base64UrlUnpadded, Encoding};
use regex::Regex;
use serde_json::json;

use crate::did::{self, Error};
use crate::document::{Document, Kind, VerificationMethod};
use crate::{
    ContentMetadata, ContentType, Curve, Jwk, KeyType, Metadata, Options, Resolution, Resolver,
    Resource,
};

const ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
const VALID_DID: &str = "^did:key:z[a-km-zA-HJ-NP-Z1-9]+$";

static DID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(VALID_DID).expect("should compile"));
static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:z[a-km-zA-HJ-NP-Z1-9]+(?:&?[^=&]*=[^=&]*)*(#z[a-km-zA-HJ-NP-Z1-9]+)*$")
        .expect("should compile")
});

#[allow(clippy::module_name_repetitions)]
pub struct DidKey;

impl Resolver for DidKey {
    fn resolve(&self, did: &str, _opts: Option<Options>) -> did::Result<Resolution> {
        if !DID_REGEX.is_match(did) {
            return Err(Error::InvalidDidUrl("invalid did:key URL".to_string()));
        }
        // if !did.starts_with("did:key:") {
        //     return Err(Error::InvalidDid("DID is not did:key".into()));
        // }
        // if did.split('#').count() > 1 {
        //     return Err(Error::InvalidDid("DID contains fragment".into()));
        // }

        // decode the the DID key
        let (_, raw) = multibase::decode(&did[8..])
            .map_err(|e| Error::InvalidDid(format!("issue decoding key: {e}")))?;
        if raw.len() - 2 != 32 {
            return Err(Error::InvalidDid("invalid key length".into()));
        }
        if raw[0..2] != ED25519_PREFIX {
            return Err(Error::InvalidDid("unsupported signature".into()));
        }

        // we only support Ed25519 keys (for now)
        let key_def = "Ed25519VerificationKey2020";
        let jwk = Jwk {
            kty: KeyType::OKP,
            crv: Curve::Ed25519,
            x: Base64UrlUnpadded::encode_string(&raw[2..]),
            ..Jwk::default()
        };
        let key = did.split(':').last().unwrap();
        let kid = format!("{did}#{key}");

        let document = Document {
            context: vec![
                Kind::Simple("https://www.w3.org/ns/did/v1".into()),
                Kind::Rich(json!({
                    "publicKeyJwk": {
                        "@id": "https://w3id.org/security#publicKeyJwk",
                        "@type": "@json"
                    },
                    key_def: format!("https://w3id.org/security#{key_def}"),
                })),
            ],
            id: did.into(),
            verification_method: Some(vec![VerificationMethod {
                id: kid.clone(),
                type_: key_def.into(),
                controller: did.into(),
                public_key_jwk: Some(jwk),
                ..VerificationMethod::default()
            }]),
            authentication: Some(vec![Kind::Simple(kid.clone())]),
            assertion_method: Some(vec![Kind::Simple(kid)]),
            ..Document::default()
        };

        Ok(Resolution {
            metadata: Metadata {
                content_type: ContentType::DidLdJson,
                additional: Some(json!({
                    "pattern": VALID_DID,
                    "did": {
                        "didString": did,
                        "methodSpecificId": key,
                        "method": "key"
                    }
                })),
                ..Metadata::default()
            },
            document: Some(document),
            document_metadata: None,
        })
    }

    fn dereference(&self, did_url: &str, _opts: Option<Options>) -> did::Result<Resource> {
        // validate URL against pattern
        if !URL_REGEX.is_match(did_url) {
            return Err(Error::InvalidDidUrl("invalid did:key URL".to_string()));
        }
        let url = url::Url::parse(did_url)
            .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;

        let options = if let Some(query) = url.query().as_ref() {
            Some(
                serde_urlencoded::from_str::<Options>(query)
                    .map_err(|e| Error::InvalidDidUrl(format!("issue decoding query: {e}")))?,
            )
        } else {
            None
        };

        // get DID document
        let did = format!("did:{}", url.path());
        let resolution = self.resolve(&did, options)?;

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

    #[test]
    fn resolve() {
        let did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        let resolved = DidKey.resolve(did, None).expect("should resolve");

        let document: Document =
            serde_json::from_value(DOCUMENT.to_owned()).expect("should deserialize");
        assert_eq!(resolved.document, Some(document));

        let metadata: Metadata =
            serde_json::from_value(METADATA.to_owned()).expect("should deserialize");
        assert_eq!(resolved.metadata, metadata);
    }

    #[test]
    fn dereference() {
        // let did_url = url::Url::parse(DID_URL).expect("should parse");
        let resolved = DidKey.dereference(DID_URL, None).expect("should resolve");
        println!("did_url: {:?}", resolved);
    }

    static DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK?test=aw#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    static DOCUMENT: LazyLock<Value> = LazyLock::new(|| {
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
