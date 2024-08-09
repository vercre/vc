//! # DID Resolver
//!
//! This crate provides common utilities for the Vercre project and is not intended to be used
//! directly.
//!
//! The crate provides a DID Resolver trait and a set of default implementations for
//! resolving DIDs.
//!
//! See [DID resolution](https://www.w3.org/TR/did-core/#did-resolution) fpr more.

pub mod document;
mod key;
mod resolution;
mod web;

pub use document::Document;
pub use resolution::{
    dereference, resolve, ContentType, Dereference, Metadata, Options, Resolve, Resource,
};

/// Did Result type using did module-specific Error
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

/// DID resolution error codes
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// The DID method is not supported.
    #[error("methodNotSupported")]
    MethodNotSupported(String),

    /// The DID supplied to the DID resolution function does not conform to
    /// valid syntax.
    #[error("invalidDid")]
    InvalidDid(String),

    /// The DID resolver was unable to find the DID document resulting from
    /// this resolution request.
    #[error("notFound")]
    NotFound(String),

    #[error("representationNotSupported")]
    RepresentationNotSupported(String),

    /// The DID URL is invalid
    #[error("invalidDidUrl")]
    InvalidDidUrl(String),

    // ---- Creation Errors ----  //
    /// The byte length of raw public key does not match that expected for the
    /// associated multicodecValue.
    #[error("invalidPublicKeyLength")]
    InvalidPublicKeyLength(String),

    /// The public key is invalid
    #[error("invalidPublicKey")]
    InvalidPublicKey(String),

    /// Public key format is not known to the implementation.
    #[error("unsupportedPublicKeyType")]
    UnsupportedPublicKeyType(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl Error {
    #[must_use]
    pub fn code(&self) -> String {
        self.to_string()
    }

    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::MethodNotSupported(msg)
            | Self::InvalidDid(msg)
            | Self::NotFound(msg)
            | Self::InvalidDidUrl(msg)
            | Self::RepresentationNotSupported(msg)
            | Self::InvalidPublicKeyLength(msg)
            | Self::InvalidPublicKey(msg)
            | Self::UnsupportedPublicKeyType(msg) => msg.clone(),
            Self::Other(err) => err.to_string(),
        }
    }
}

// impl From<anyhow::Error> for Error {
//     fn from(err: anyhow::Error) -> Self {
//         Self
//     }
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn error_code() {
        let err = Error::MethodNotSupported("Method not supported".into());

        println!("err: {:?}", err.to_string());
        assert_eq!(err.message(), "Method not supported");
    }
}
