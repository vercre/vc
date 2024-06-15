//! # VC JSON Schema
//! 
//! Based on [VC JSON Schema], this module provides a mechanism to make use of a 
//! JSON Schemas with Verifiable Credentials.
//! 
//! A significant part of the integrity of a Verifiable Credential comes from the
//! ability to structure its contents so that all three parties — issuer, holder,
//! verifier — may have a consistent mechanism of trust in interpreting the data 
//! that they are provided with. We introducing a new data model for an object to
//! facilitate backing Credentials with JSON Schemas that we call a Credential Schema.
//! 
//! The module provides a standardized way of creating Credential Schemas to be used
//! in credentialing systems. Credential Schemas may apply to any portion of a 
//! Verifiable Credential. Multiple JSON Schemas may back a single Verifiable 
//! Credential, e.g. a schema for the credentialSubject and another for other 
//! credential properties.
//! 
//! [VC JSON Schema]: https://www.w3.org/TR/vc-json-schema
