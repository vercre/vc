//! # DID Key Resolver
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its core,
//! it is based on expanding a cryptographic public key into a DID Document.
//!
//! See:
//!
//! - <https://w3c-ccg.github.io/did-method-key>
//! - <https://w3c.github.io/did-resolution>

use std::sync::LazyLock;

use regex::Regex;
use serde_json::json;

use super::DidKey;
use crate::document::CreateOptions;
use crate::error::Error;
use crate::resolution::{
    ContentMetadata, ContentType, Dereference, DidClient, Metadata, Options, Resolve, Resource,
};

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:(?<identifier>z[a-km-zA-HJ-NP-Z1-9]+)$").expect("should compile")
});

impl DidKey {
    pub fn resolve(did: &str, _: Option<Options>, _: impl DidClient) -> crate::Result<Resolve> {
        // check DID is valid AND extract key
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:key".into()));
        };
        let multikey = &caps["identifier"];

        // decode the the DID key
        let (_, key_bytes) = multibase::decode(multikey)
            .map_err(|e| Error::InvalidDid(format!("issue decoding key: {e}")))?;
        if key_bytes.len() - 2 != 32 {
            return Err(Error::InvalidDid("invalid key length".into()));
        }
        if key_bytes[0..2] != ED25519_CODEC {
            return Err(Error::InvalidDid("unsupported signature".into()));
        }

        // per the spec, use the create operation to generate a DID document
        let options = CreateOptions {
            enable_encryption_key_derivation: true,
            ..CreateOptions::default()
        };

        let document =
            Self::create(&key_bytes[2..], options).map_err(|e| Error::InvalidDid(e.to_string()))?;

        Ok(Resolve {
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
            ..Resolve::default()
        })
    }

    #[allow(clippy::needless_pass_by_value)]
    pub fn dereference(
        did_url: &str, _opts: Option<Options>, client: impl DidClient,
    ) -> crate::Result<Dereference> {
        // validate URL against pattern
        let url = url::Url::parse(did_url)
            .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;

        // resolve DID document
        let did = format!("did:{}", url.path());
        let resolution = Self::resolve(&did, None, client)?;

        let Some(document) = resolution.document else {
            return Err(Error::InvalidDid("Unable to resolve DID document".into()));
        };
        let Some(verifcation_methods) = document.verification_method else {
            return Err(Error::NotFound("verification method missing".into()));
        };

        // for now we assume the DID URL is the ID of the verification method
        // e.g. did:key:z6MkhaXgBZD#z6MkhaXgBZD
        let Some(vm) = verifcation_methods.iter().find(|vm| vm.id == did_url) else {
            return Err(Error::NotFound("verification method not found".into()));
        };

        Ok(Dereference {
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
}

#[cfg(test)]
mod test {
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;

    const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
    const DID_URL: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    struct Client {}
    impl DidClient for Client {
        async fn get(&self, _url: &str) -> anyhow::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn resolve() {
        let resolved = DidKey::resolve(DID, None, Client {}).expect("should resolve");
        assert_snapshot!("resolved", resolved);
    }

    #[tokio::test]
    async fn dereference() {
        let dereferenced =
            DidKey::dereference(DID_URL, None, Client {}).expect("should dereference");
        assert_snapshot!("dereferenced", dereferenced);
    }
}
