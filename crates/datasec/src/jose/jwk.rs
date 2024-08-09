//! # JSON Web Key (JWK)
//!
//! A JWK ([RFC7517]) is a JSON representation of a cryptographic key.  
//! Additionally, a JWK Set (JWKS) is used to represent a set of JWKs.
//!
//! See [RFC7517] for more detail.
//!
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517

use serde::{Deserialize, Serialize};

use crate::jose::jwe::EncryptionAlgorithm;

/// Simplified JSON Web Key (JWK) key structure.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
pub struct PublicKeyJwk {
    /// Key identifier.
    /// For example, "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Key type.
    pub kty: KeyType,

    /// Cryptographic curve type.
    pub crv: Curve,

    /// X coordinate.
    pub x: String,

    /// Y coordinate. Not required for `EdDSA` verification keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Algorithm intended for use with the key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<EncryptionAlgorithm>,

    /// Use of the key.
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<KeyUse>,
}

/// Cryptographic key type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum KeyType {
    /// Octet key pair (Edwards curve)
    #[default]
    #[serde(rename = "OKP")]
    Okp,

    /// Elliptic curve key pair
    #[serde(rename = "EC")]
    Ec,

    /// Octet string
    #[serde(rename = "oct")]
    Oct,
}

// #[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
// /// Algorithms described by [RFC 7518](https://tools.ietf.org/html/rfc7518).
// /// This enum is serialized `untagged`.
// #[serde(untagged)]
// pub enum Algorithm {
//     // /// Algorithms meant for Digital signature or MACs
//     // /// See [RFC7518#3](https://tools.ietf.org/html/rfc7518#section-3)
//     // Signature(SignatureAlgorithm),

//     // /// Algorithms meant for key management. The algorithms are either meant to
//     // /// encrypt a content encryption key or determine the content encryption key.
//     // /// See [RFC7518#4](https://tools.ietf.org/html/rfc7518#section-4)
//     // KeyManagement(KeyManagementAlgorithm),

//     // /// Algorithms meant for content encryption.
//     // /// See [RFC7518#5](https://tools.ietf.org/html/rfc7518#section-5)
//     // Encryption(EncryptionAlgorithm),
// }

/// Cryptographic curve type.
#[derive(Clone, Debug, Default, Deserialize, Serialize, Eq, PartialEq)]
pub enum Curve {
    /// Ed25519 curve
    #[default]
    Ed25519,

    /// secp256k1 curve
    #[serde(rename = "ES256K", alias = "secp256k1")]
    Es256K,
}

/// The intended usage of the public `KeyType`. This enum is serialized `untagged`
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyUse {
    /// Public key is to be used for signature verification
    #[default]
    #[serde(rename = "sig")]
    Signature,

    /// Public key is to be used for encryption
    #[serde(rename = "enc")]
    Encryption,
}

/// A set of JWKs.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Jwks {
    /// The set of public key JWKs
    pub keys: Vec<PublicKeyJwk>,
}
