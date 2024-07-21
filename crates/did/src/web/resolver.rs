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

use anyhow::anyhow;
use regex::Regex;
use serde_json::json;

use super::DidWeb;
use crate::did::{self, Error};
use crate::DidClient;
// use crate::document::{CreateOptions, Operator};
use crate::{ContentMetadata, ContentType, Metadata, Options, Resolution, Resolver, Resource};

static URL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:web:(?<identifier>[a-zA-Z1-9.-:%]+)$").expect("should compile")
});

impl Resolver for DidWeb {
    async fn resolve(
        &self, did: &str, _: Option<Options>, client: impl DidClient,
    ) -> did::Result<Resolution> {
        let Some(caps) = URL_REGEX.captures(did) else {
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
        let url = format!("https://{domain}");

        // 4. If no path has been specified in the URL, append /.well-known.
        // 5. Append /did.json to complete the URL.
        let url = if identifier.contains(':') {
            format!("{url}/did.json")
        } else {
            format!("{url}/.well-known/did.json")
        };

        // 6. Perform an HTTP GET request to the URL using an agent that can successfully
        //    negotiate a secure HTTPS connection, which enforces the security requirements
        //    as described in 2.6 Security and privacy considerations.
        let bytes = client.get(&url).await.map_err(Error::Other)?;
        // let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("msg");
        // println!("doc: {doc}");

        let document = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(anyhow!("issue deserializing document: {e}")))?;

        // 7. When performing the DNS resolution during the HTTP GET request, the client
        //    SHOULD utilize [RFC8484] in order to prevent tracking of the identity being
        //    resolved.

        // // per the spec, use the create operation to generate a DID document
        // let options = CreateOptions {
        //     enable_encryption_key_derivation: true,
        //     ..CreateOptions::default()
        // };

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

    async fn dereference(
        &self, did_url: &str, _opts: Option<Options>, client: impl DidClient,
    ) -> did::Result<Resource> {
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
        let resolution = self.resolve(&did, None, client).await?;

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
    use anyhow::anyhow;
    use insta::assert_json_snapshot as assert_snapshot;

    use super::*;

    struct Client {}
    impl DidClient for Client {
        async fn get(&self, url: &str) -> anyhow::Result<Vec<u8>> {
            reqwest::get(url).await?.bytes().await.map_err(|e| anyhow!("{e}")).map(|b| b.to_vec())
        }
    }

    #[tokio::test]
    async fn resolve_normal() {
        const DID_URL: &str = "did:web:demo.credibil.io";
        let resolved = DidWeb.resolve(DID_URL, None, Client {}).await.expect("should resolve");

        assert_snapshot!("document", resolved.document);
        assert_snapshot!("metadata", resolved.metadata);
    }

    // #[tokio::test]
    // async fn resolve_path() {
    //     const DID_URL: &str = "did:web:demo.credibil.io%3A443:demo";
    //     let resolved = DidWeb.resolve(DID_URL, None, Client {}).await.expect("should resolve");

    //     assert_snapshot!("document", resolved.document);
    //     assert_snapshot!("metadata", resolved.metadata);
    // }

    // #[test]
    // fn dereference() {
    //     let resource = DidWeb.dereference(DID_URL, None).expect("should resolve");

    //     assert_snapshot!("resource", resource);
    // }
}
