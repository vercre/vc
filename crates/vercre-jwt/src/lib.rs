//! Securing Credentials
//!
//! Verifiable Credentials can be secured using two different mechanisms: enveloping
//! proofs or embedded proofs. In both cases, a proof cryptographically secures a
//! Credential (for example, using digital signatures). In the enveloping case,
//! the proof wraps around the Credential, whereas embedded proofs are included in the
//! serialization, alongside the Credential itself.
//!
//! ## Envelooping Proofs
//!
//! A family of enveloping proofs is defined in the [Securing Verifiable Credentials
//! using JOSE and COSE] document, relying on technologies defined by
//! the IETF. Other types of enveloping proofs may be specified by the community.
//!
//! ## Embedded Proofs
//!
//! The general structure for embedded proofs is defined in a separate [Verifiable
//! Credential Data Integrity 1.0] specification. Furthermore, some instances of this
//! general structure are specified in the form of the "cryptosuites": Data Integrity
//! [EdDSA Cryptosuites v1.0], Data Integrity [ECDSA Cryptosuites v1.0], and Data
//! Integrity [BBS Cryptosuites v1.0].
//!
//! [Securing Verifiable Credentials using JOSE and COSE]: https://w3c.github.io/vc-jose-cose
//! [Verifiable Credential Data Integrity 1.0]: https://www.w3.org/TR/vc-data-integrity
//! [EdDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-eddsa
//! [ECDSA Cryptosuites v1.0]: https://www.w3.org/TR/vc-di-ecdsa
//! [BBS Cryptosuites v1.0]: https://w3c.github.io/vc-di-bbs

pub mod jwt;

use std::future::{Future, IntoFuture};

pub use crate::jwt::Algorithm;

/// Signer is used by implementers to provide signing functionality for
/// Verifiable Credential issuance and Verifiable Presentation submissions.
pub trait Signer: Send + Sync {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm;

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String;

    /// Sign is a convenience method for infallible Signer implementations.
    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    /// `TrySign` is the fallible version of Sign.
    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
