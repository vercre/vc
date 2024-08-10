use anyhow::anyhow;
use vercre_datasec::{Binding, Document};
use vercre_openid::provider::Result;

/// Dereference DID URL to public key. For example,  did:web:demo.credibil.io#key-0.
///
/// did:web:demo.credibil.io -> did:web:demo.credibil.io/.well-known/did.json
/// did:web:demo.credibil.io:entity:supplier -> did:web:demo.credibil.io/entity/supplier/did.json
pub async fn resolve_did(_binding: Binding) -> Result<Document> {
    serde_json::from_slice(include_bytes!("did.json"))
        .map_err(|e| anyhow!("issue deserializing document: {e}"))
}
