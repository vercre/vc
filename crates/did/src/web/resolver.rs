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

use super::DidWeb;
use crate::error::Error;
use crate::resolution::{ContentType, Metadata, Options, Resolved};
use crate::DidResolver;

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:web:(?<identifier>[a-zA-Z1-9.-:%]+)$").expect("should compile")
});

impl DidWeb {
    pub async fn resolve(
        did: &str, _: Option<Options>, resolver: &impl DidResolver,
    ) -> crate::Result<Resolved> {
        let Some(caps) = DID_REGEX.captures(did) else {
            return Err(Error::InvalidDid("DID is not a valid did:web".to_string()));
        };
        let identifier = &caps["identifier"];

        // 1. Replace ":" with "/" in the method specific identifier to obtain the fully
        //    qualified domain name and optional path.
        let domain = identifier.replace(':', "/");

        // 2. If the domain contains a port percent decode the colon.
        let domain = domain.replace("%3A", ":");

        // 3. Generate an HTTPS URL to the expected location of the DID document by
        //    prepending https://.
        let mut url = format!("https://{domain}");

        // 4. If no path has been specified in the URL, append /.well-known.
        if !identifier.contains(':') {
            url = format!("{url}/.well-known");
        }

        // 5. Append /did.json to complete the URL.
        url = format!("{url}/did.json");

        // 6. Perform an HTTP GET request to the URL using an agent that can
        //    successfully negotiate a secure HTTPS connection, which enforces the
        //    security requirements as described in 2.6 SecOps and privacy
        //    considerations.
        let document = resolver.resolve(&url).await.map_err(Error::Other)?;

        // TODO: implement security requirement:
        // 7. When performing the DNS resolution during the HTTP GET request, the client
        //    SHOULD utilize [RFC8484] in order to prevent tracking of the identity
        //    being resolved.

        // // per the spec, use the create operation to generate a DID document
        // let options = CreateOptions {
        //     enable_encryption_key_derivation: true,
        //     ..CreateOptions::default()
        // };

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
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;
    use crate::document::Document;

    struct MockResolver;
    impl DidResolver for MockResolver {
        async fn resolve(&self, _url: &str) -> anyhow::Result<Document> {
            serde_json::from_slice(include_bytes!("did-ecdsa.json"))
                .map_err(|e| anyhow!("issue deserializing document: {e}"))
        }
    }

    #[tokio::test]
    async fn resolve_normal() {
        const DID_URL: &str = "did:web:demo.credibil.io";

        let resolved = DidWeb::resolve(DID_URL, None, &MockResolver).await.expect("should resolve");
        assert_snapshot!("document", resolved.document);
        assert_snapshot!("metadata", resolved.metadata);
    }
}
