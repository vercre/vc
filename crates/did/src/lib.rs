#![feature(let_chains)]

//! # DID Resolver
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

// TODO: add support for the following:
//   key type: EcdsaSecp256k1VerificationKey2019 | JsonWebKey2020 | Ed25519VerificationKey2020 |
//             Ed25519VerificationKey2018 | X25519KeyAgreementKey2019
//   crv: Ed25519 | secp256k1 | P-256 | P-384 | p-521

mod document;
mod error;
mod key;
mod resolution;
mod web;

use std::future::Future;

pub use error::Error;
pub use resolution::{
    dereference, resolve, ContentType, Dereferenced, Metadata, Options, Resolved, Resource,
};

pub use crate::document::Document;

/// Returns DID-specific errors.
pub type Result<T> = std::result::Result<T, Error>;

pub trait DidOps: Send + Sync {
    /// Returns a resolver that can be used to resolve an external reference to
    /// public key material.
    ///
    /// # Errors
    ///
    /// Returns an error if the resolver cannot be created.
    fn resolver(&self, identifier: &str) -> anyhow::Result<impl DidResolver>;
}

/// `DidResolver` is used to proxy the resolution of a DID document. Resolution can
/// either be local as in the case of `did:key`, or remote as in the case of `did:web`
/// or `did:ion`.
///
/// Implementers simply implement the transport protocol for the binding and return
/// the resulting DID document.
pub trait DidResolver: Send + Sync {
    /// Resolve the DID URL to a DID Document.
    ///
    /// # Errors
    ///
    /// Returns an error if the DID URL cannot be resolved.
    fn resolve(
        &self, binding: Binding,
    ) -> impl Future<Output = anyhow::Result<Document>> + Send + Sync;
}

/// DID resolver binding options used by the client DID Resolver (proxy) to bind to a
/// DID resolution server.
pub enum Binding {
    /// Local binding (no transport protocol)
    Local,

    /// HTTPS binding
    Https(String),

    /// RPC binding to remote (`DIDComm`?) binding
    Rpc(String),
}
