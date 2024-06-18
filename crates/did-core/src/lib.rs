#![allow(missing_docs)]

//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

/// DID Resolver is implemented by DID resolvers.
///
/// The [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) functions
/// resolve a DID into a DID document by using the "Read" operation of the applicable
/// DID method.
///
/// Caveats:
/// - No JSON-LD Processing, however, valid JSON-LD is returned.
/// - Ignores accept header.
/// - Only returns application/did+ld+json.
/// - did:key support for secp256r1, secp348r1, secp256k1, ed25519, x25519
/// - did:web support for .well-known and path based DIDs.
mod document;
mod ion;
mod jwk;
mod key;

use serde::{Deserialize, Serialize};

use crate::document::{DidDocument, DidDocumentMetadata};

pub fn resolve(did: &str, opts: impl ResolutionOptions) -> anyhow::Result<DidResolution> {
    match did.split(':').next() {
        Some("jwk") => jwk::DidJwk.resolve(did, opts),
        Some("ion") => ion::DidIon.resolve(did, opts),
        _ => unimplemented!(),
    }
}

pub trait DidResolver {
    fn resolve(&self, did: &str, opts: impl ResolutionOptions) -> anyhow::Result<DidResolution>;

    fn resolve_representation(
        &self, did: &str, opts: impl ResolutionOptions,
    ) -> anyhow::Result<DidResolution>;
}

pub trait ResolutionOptions {
    fn options(&self, key: &str) -> Option<Vec<(String, String)>>;
}

pub trait DidDereferencer {
    fn dereference(&self, did: &str, opts: impl ResolutionOptions)
        -> anyhow::Result<DidResolution>;
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DidResolution {
    pub did_document: DidDocument,
    pub did_resolution_metadata: DidResolutionMetadata,
    pub did_document_metadata: DidDocumentMetadata,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct DidResolutionMetadata {
    pub error: Option<String>,
    pub content_type: Option<String>,
    pub property_set: Vec<(String, String)>,
}
