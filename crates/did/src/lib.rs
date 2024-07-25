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
