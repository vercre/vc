//! # Verifiable Credentials Data Model
//!
//! The Verifiable Credentials [Data Model v2.0] specification defines core VC
//! concepts that all other specifications depend on, plays a central role. The
//! model is defined in abstract terms, and applications express their specific
//! credentials using a serialization of the data model. The current
//! specifications mostly use a JSON serialization; the community may develop
//! other serializations in the future.
//!
//! When Verifiable Credentials are serialized in JSON, it is important to trust
//! that the structure of a Credential may be interpreted in a consistent manner
//! by all participants in the verifiable credential ecosystem. The Verifiable
//! Credentials [JSON Schema] specification defines how JSON schema can be used
//! for that purpose.
//!
//! [Data Model v2.0]: https://www.w3.org/TR/vc-data-model-2.0
//! [JSON Schema]: https://www.w3.org/TR/vc-json-schema/

pub mod vc;
pub mod vp;

pub use vc::*;
pub use vp::*;

// TODO: move this to crate where it can be shared with DID impls.
