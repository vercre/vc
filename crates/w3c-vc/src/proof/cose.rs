//! # COSE Proofs
//!
//! CBOR Object Signing and Encryption (COSE) proofs are a form of enveloping proofs 
//! of Credentials based on [RFC9052].
//!
//! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
//! recommendation defines a "bridge" between these and the Verifiable Credentials Data
//! Model v2.0, specifying the suitable header claims, media types, etc.
//!
//! The usage of COSE [RFC9052] is similar to JOSE, except that all structures are
//! represented in CBOR [RFC8949]. From the Credentials point of view, however, the
//! structure is similar insofar as the Credential (or the Presentation) is again the
//! payload for COSE. The usage of CBOR means that the final representation of the
//! Verifiable Credential (or Presentation) has a significantly reduced footprint which
//! can be, for example, shown in a QR Code.
//!
//! [RFC9052]: https://www.rfc-editor.org/rfc/rfc9052
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose/