//! # Verifiable Credentials
//!
//! This crate provides common utilities for the Vercre project and is not
//! intended to be used directly.
//!
//! This library encompasses the family of W3C Recommendations for Verifiable
//! Credentials, as outlined below.
//!
//! The recommendations provide a mechanism to express credentials on the Web in
//! a way that is cryptographically secure, privacy respecting, and
//! machine-verifiable.

pub mod model;

pub use anyhow::anyhow;

// TODO: move this macro to a more appropriate location (its own crate perhaps).
// N.B. the current dependency tree is a little complex, so this is a temporary
// solution that avoids cyclic dependencies.
