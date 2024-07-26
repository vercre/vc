//! # Controller Document

use proof::jose::jwk::PublicKeyJwk;
use serde::{Deserialize, Serialize};

/// A controller document contains a set of verification methods that specify
/// relationships between the controller and a set of public keys.
///
/// The relationships permit the use of the verification methods for the purpose of
/// authenticating or authorizing interactions with the controller or associated
/// parties.
///
/// For example, a public key can be used to verify that a signer has control over
/// the associated cryptographic private key.
///
/// Verification methods might take many parameters. For example, a controller
/// document lists five cryptographic keys from which any three are required to
/// contribute to a cryptographic threshold signature.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Controller {
    /// Verification methods supported by the controller.
    pub verification_methods: Vec<VerificationMethod>,
}

/// The `VerificationMethod` contains set of parameters that can be used together with a
/// process to independently verify a proof.
///
/// For example, a cryptographic public key can be used as a verification method with
/// respect to a digital signature; in such usage, it verifies that the signer possessed
/// the associated cryptographic private key.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// A URL for the verification method.
    ///
    /// For example, did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A.
    pub id: String,

    /// The verification method type. One of `JsonWebKey` or `Multikey`.
    #[serde(rename = "type")]
    pub type_: MethodType,

    /// A URL referencing the controller of the verification method. This could resolve
    /// to a DID Document or a `.well-known` endpoint.
    pub controller: String,

    /// An [XMLSCHEMA11-2](https://www.rfc-editor.org/rfc/rfc3339) dateTimeStamp
    /// specifying when the verification method should stop being used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked: Option<String>,

    /// The public key JWK used to for verification. MUST NOT be set if `public-key-multibase`
    /// is set.
    ///
    /// For example,
    ///
    /// ```json
    ///  "publicKeyJwk": {
    ///     "crv": "Ed25519",
    ///     "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
    ///     "kty": "OKP",
    ///     "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
    /// }
    /// ```
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<PublicKeyJwk>,

    /// A Multibase-encoded public key. MUST NOT be set if `public-key-jwk` is set.
    ///
    /// For example, `z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu`.
    ///
    /// See <https://www.w3.org/TR/vc-data-integrity/#multibase-0>.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
}

/// The format of the public keys, based on either the JWK [RFC7517] format or a
/// Multibase [MULTIBASE] encoding of the keys, called Multikey.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum MethodType {
    #[default]
    /// Verification method type of JSON Web Key (JWK)
    /// [RFC7517](https://www.rfc-editor.org/rfc/rfc7517).
    JsonWebKey,

    /// Verification method type of [Multibase](https://www.ietf.org/archive/id/draft-multiformats-multibase-08.html)
    /// Multikey.
    Multikey,
}
