//! # DID Key Resolver
//!
//! The `did:key` method is a DID method for static cryptographic keys. At its
//! core, it is based on expanding a cryptographic public key into a DID
//! Document.
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
use crate::resolution::{ContentType, Metadata, Options, Resolved};
use crate::DidResolver;

const ED25519_CODEC: [u8; 2] = [0xed, 0x01];
static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:key:(?<identifier>z[a-km-zA-HJ-NP-Z1-9]+)$").expect("should compile")
});

impl DidKey {
    pub fn resolve(did: &str, _: Option<Options>, _: &impl DidResolver) -> crate::Result<Resolved> {
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

        Ok(Resolved {
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
            ..Resolved::default()
        })
    }
}

#[cfg(test)]
mod test {
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;
    use crate::document::Document;

    const DID: &str = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> anyhow::Result<Document> {
            Ok(Document::default())
        }
    }

    #[tokio::test]
    async fn resolve() {
        let resolved = DidKey::resolve(DID, None, &MockResolver).expect("should resolve");
        assert_snapshot!("resolved", resolved);
    }
}
