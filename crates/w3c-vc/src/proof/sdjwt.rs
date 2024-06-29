//! # SD-JWT Proofs
//!
//! Selective Disclosure for JWTs proofs are a form of enveloping proofs 
//! of Credentials based on [SD-JWT].
//!
//! The Securing Verifiable Credentials using JOSE and COSE [VC-JOSE-COSE]
//! recommendation defines a "bridge" between these and the Verifiable Credentials Data
//! Model v2.0, specifying the suitable header claims, media types, etc.
//!
//! The [SD-JWT] is a variant of JOSE, which allows for the selective disclosure of
//! individual claims. Claims can be selectively hidden or revealed to the verifier,
//! but nevertheless all claims are cryptographically protected against modification.
//!  This approach is obviously more complicated than the JOSE case but, from the
//! Credentials point of view, the structure is again similar. The original Credential
//! is the payload for SD-JWT; and it is the holder's responsibility to use the SD-JWT
//!  when presenting the Credential to a verifier using selective disclosure.
//!
//! [SD-JWT]: https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt
//! [VC-JOSE-COSE]: https://w3c.github.io/vc-jose-cose/