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

use anyhow::anyhow;
use regex::Regex;
use serde_json::json;

use super::DidWeb;
use crate::error::Error;
use crate::{
    ContentMetadata, ContentType, Dereference, DidClient, Metadata, Options, Resolve, Resource,
};

static DID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^did:web:(?<identifier>[a-zA-Z1-9.-:%]+)$").expect("should compile")
});

impl DidWeb {
    pub async fn resolve(
        did: &str, _: Option<Options>, client: impl DidClient,
    ) -> crate::Result<Resolve> {
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

        // 6. Perform an HTTP GET request to the URL using an agent that can successfully
        //    negotiate a secure HTTPS connection, which enforces the security requirements
        //    as described in 2.6 Security and privacy considerations.
        let bytes = client.get(&url).await.map_err(Error::Other)?;

        let document = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Other(anyhow!("issue deserializing document: {e}")))?;

        // TODO: implement security requirement:
        // 7. When performing the DNS resolution during the HTTP GET request, the client
        //    SHOULD utilize [RFC8484] in order to prevent tracking of the identity being
        //    resolved.

        // // per the spec, use the create operation to generate a DID document
        // let options = CreateOptions {
        //     enable_encryption_key_derivation: true,
        //     ..CreateOptions::default()
        // };

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

    pub async fn dereference(
        did_url: &str, _opts: Option<Options>, client: impl DidClient,
    ) -> crate::Result<Dereference> {
        let url = url::Url::parse(did_url)
            .map_err(|e| Error::InvalidDidUrl(format!("issue parsing URL: {e}")))?;

        println!("url: {}", url.fragment().unwrap());

        // resolve DID document
        let did = format!("did:{}", url.path());
        let resolution = Self::resolve(&did, None, client).await?;

        let Some(document) = resolution.document else {
            return Err(Error::InvalidDid("Unable to resolve DID document".into()));
        };
        let Some(verifcation_methods) = document.verification_method else {
            return Err(Error::NotFound("verification method missing".into()));
        };

        // for now we assume the DID URL is the ID of the verification method
        // e.g. did:web:demo.credibil.io#key-0
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

    struct Client {}
    impl DidClient for Client {
        async fn get(&self, _url: &str) -> anyhow::Result<Vec<u8>> {
            Ok(include_bytes!("did.json").to_vec())
            // reqwest::get(url).await?.bytes().await.map_err(|e| anyhow!("{e}")).map(|b| b.to_vec())
        }
    }

    #[tokio::test]
    async fn resolve_normal() {
        const DID_URL: &str = "did:web:demo.credibil.io";
        let resolved = DidWeb::resolve(DID_URL, None, Client {}).await.expect("should resolve");

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
