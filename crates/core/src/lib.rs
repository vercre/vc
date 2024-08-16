//! # Core Utilities for Vercre
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.

// generic member access API on the error trait
// https://github.com/rust-lang/rust/issues/99301
#![feature(error_generic_member_access)]

pub mod gen;
pub mod stringify;

use serde::{Deserialize, Serialize};

/// Wrap the @context property to support serialization/deserialization of an ordered
/// set composed of any combination of URLs and/or objects, each processable as a
/// [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Simple string value
    String(String),

    /// Complex object value
    Object(T),
}

impl<T: Default> Default for Kind<T> {
    fn default() -> Self {
        Self::String(String::new())
    }
}

/// `Quota` allows serde to serialize/deserialize a single object or a set of objects.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Quota<T> {
    /// Single object
    One(T),

    /// Set of objects
    Many(Vec<T>),
}

impl<T: Default> Default for Quota<T> {
    fn default() -> Self {
        Self::One(T::default())
    }
}

impl<T: Default> Quota<T> {
    /// Returns `true` if the quota is a single object.
    pub const fn is_one(&self) -> bool {
        match self {
            Self::One(_) => true,
            Self::Many(_) => false,
        }
    }

    /// Returns `true` if the quota contains an array of objects.
    pub const fn is_many(&self) -> bool {
        match self {
            Self::One(_) => false,
            Self::Many(_) => true,
        }
    }
}
