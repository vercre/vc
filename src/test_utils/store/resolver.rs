use anyhow::anyhow;
use credibil_did::Document;

use crate::openid::provider::Result;

/// Dereference DID URL to public key. For example,
/// did:web:demo.credibil.io#key-0.
#[allow(clippy::unused_async)]
pub async fn resolve_did(_url: &str) -> Result<Document> {
    serde_json::from_slice(include_bytes!("did.json"))
        .map_err(|e| anyhow!("issue deserializing document: {e}"))
}
