//! # Verifiable Credentials Data Model
//!
//! The Verifiable Credentials [Data Model v2.0] specification defines core VC concepts
//! that all other specifications depend on, plays a central role. The model is defined
//! in abstract terms, and applications express their specific credentials using a
//! serialization of the data model. The current specifications mostly use a JSON
//! serialization; the community may develop other serializations in the future.
//!
//! When Verifiable Credentials are serialized in JSON, it is important to trust that
//! the structure of a Credential may be interpreted in a consistent manner by all
//! participants in the verifiable credential ecosystem. The Verifiable Credentials
//! [JSON Schema] Specification defines how JSON schema can be used for that purpose.
//!
//! [Data Model v2.0]: https://www.w3.org/TR/vc-data-model-2.0
//! [JSON Schema]: https://www.w3.org/TR/vc-json-schema/

pub mod vc;
pub mod vp;

use ::serde::{Deserialize, Serialize};
pub use vc::*;
pub use vp::*;

// TODO: move this to crate where it can be shared with DID impls.

/// Wrap the @context property to support serialization/deserialization of an ordered
/// set composed of any combination of URLs and/or objects, each processable as a
/// [JSON-LD Context](https://www.w3.org/TR/json-ld11/#the-context).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Kind<T> {
    /// Context URL
    Simple(String),

    /// Context object
    Rich(T),
}

impl<T: Default> Default for Kind<T> {
    fn default() -> Self {
        Self::Simple(String::new())
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

/// `StrObj` allows serde to serialize/deserialize a string or an object.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum StrObj<T> {
    /// Field is a string
    String(String),

    /// Field is an object
    Object(T),
}

impl<T: Default> Default for StrObj<T> {
    fn default() -> Self {
        Self::String(String::new())
    }
}
