#![allow(missing_docs)]
#![feature(let_chains)]

//! # DID Resolver
//!
//! This crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod document;
pub mod error;
mod key;
mod resolution;
mod web;

pub use error::Error;
pub use resolution::{
    dereference, resolve, ContentType, Dereference, DidClient, Metadata, Options, Resolve, Resource,
};

pub type Result<T> = std::result::Result<T, Error>;

// TODO:

// Support:
// (key) type: EcdsaSecp256k1VerificationKey2019 | JsonWebKey2020 | Ed25519VerificationKey2020 | Ed25519VerificationKey2018 | X25519KeyAgreementKey2019
// crv: Ed25519 | secp256k1 | P-256 | P-384 | p-521

// JWK Thumbprint
// It is RECOMMENDED that JWK kid values are set to the public key fingerprint [RFC7638]:
//  Create hash (SHA-256) of UTF-8 representation of JSON from {crv,kty,x,y}
//
// example:
//  - JSON: {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
//  - SHA-256: 90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89
//  - base64url JWK Thumbprint: "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

// https://www.rfc-editor.org/rfc/rfc7638
