//! # JSON Web Key (JWK)
//!
//! A JWK ([RFC7517]) is a JSON representation of a cryptographic key.  
//! Additionally, a JWK Set (JWKS) is used to represent a set of JWKs.
//!
//! See [RFC7517] for more detail.
//!
//! TODO:
//! Support:
//! (key) type: `EcdsaSecp256k1VerificationKey2019` | `JsonWebKey2020` |
//!     `Ed25519VerificationKey2020` | `Ed25519VerificationKey2018` |
//!     `X25519KeyAgreementKey2019`
//! crv: `Ed25519` | `secp256k1` | `P-256` | `P-384` | `P-521`
//!
//! JWK Thumbprint [RFC7638]
//! It is RECOMMENDED that JWK kid values are set to the public key fingerprint:
//!  - create SHA-256 hash of UTF-8 representation of JSON from {crv,kty,x,y}
//!
//! For example:
//!  - JSON: `{"crv":"Ed25519","kty":"OKP","x":"
//!    11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}`
//!  - SHA-256: `90facafea9b1556698540f70c0117a22ea37bd5cf3ed3c47093c1707282b4b89`
//!  - base64url JWK Thumbprint: `kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k`
//!
//! [RFC7638]: https://www.rfc-editor.org/rfc/rfc7638
//! [RFC7517]: https://www.rfc-editor.org/rfc/rfc7517

use serde::{Deserialize, Serialize};

use crate::jose::jwe::EncryptionAlgorithm;
use crate::{Curve, KeyType, KeyUse};

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

/// A set of JWKs.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Jwks {
    /// The set of public key JWKs
    pub keys: Vec<PublicKeyJwk>,
}
