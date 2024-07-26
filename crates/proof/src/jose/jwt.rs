//! # JSON Web Token (JWT)
//!
//! JSON Web Token (JWT) is a compact, URL-safe means of representing
//! claims to be transferred between two parties.  The claims in a JWT
//! are encoded as a JSON object that is used as the payload of a JSON
//! Web Signature (JWS) structure or as the plaintext of a JSON Web
//! Encryption (JWE) structure, enabling the claims to be digitally
//! signed or integrity protected with a Message Authentication Code
//! (MAC) and/or encrypted.

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

use crate::jose::jwk::PublicKeyJwk;
use crate::signature::Algorithm;

/// Represents a JWT as used for proof and credential presentation.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Jwt<T> {
    /// The JWT header.
    pub header: Header,

    /// The JWT claims.
    pub claims: T,
}

/// Represents the JWT header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Digital signature algorithm identifier as per IANA "JSON Web Signature
    /// and Encryption Algorithms" registry.
    pub alg: Algorithm,

    /// Used to declare the media type [IANA.MediaTypes](http://www.iana.org/assignments/media-types)
    /// of the JWS.
    pub typ: Type,

    // /// Contains the key ID. If the Credential is bound to a DID, the kid refers to a
    // /// DID URL which identifies a particular key in the DID Document that the
    // /// Credential should bound to. Alternatively, may refer to a key inside a JWKS.
    // ///
    // /// MUST NOT be set if `jwk` property is set.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub kid: Option<String>,

    // /// Contains the key material the new Credential shall be bound to.
    // ///
    // /// MUST NOT be set if `kid` is set.
    // #[serde(skip_serializing_if = "Option::is_none")]
    // pub jwk: Option<PublicKeyJwk>,
    /// The key material for the public key
    #[serde(flatten)]
    pub key: KeyType,

    /// Contains a certificate (or certificate chain) corresponding to the key used to
    /// sign the JWT. This element MAY be used to convey a key attestation. In such a
    /// case, the actual key certificate will contain attributes related to the key
    /// properties.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,

    /// Contains an OpenID.Federation Trust Chain. This element MAY be used to convey
    /// key attestation, metadata, metadata policies, federation Trust Marks and any
    /// other information related to a specific federation, if available in the chain.
    ///
    /// When used for signature verification, `kid` MUST be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_chain: Option<String>,
}

/// The JWT `typ` claim.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Type {
    /// JWT `typ` for Verifiable Credential.
    #[default]
    #[serde(rename = "jwt")]
    Credential,

    /// JWT `typ` for Verifiable Presentation.
    #[serde(rename = "jwt")]
    Presentation,

    /// JWT `typ` for Authorization Request Object.
    #[serde(rename = "oauth-authz-req+jwt")]
    Request,

    /// JWT `typ` for Wallet's Proof of possession of key material.
    #[serde(rename = "openid4vci-proof+jwt")]
    Proof,
}

impl Display for Type {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The type of public key material for the JWT.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum KeyType {
    /// Contains the key ID. If the Credential is bound to a DID, the kid refers to a
    /// DID URL which identifies a particular key in the DID Document that the
    /// Credential should bound to. Alternatively, may refer to a key inside a JWKS.
    #[serde(rename = "kid")]
    KeyId(String),

    /// Contains the key material the new Credential shall be bound to.
    #[serde(rename = "jwk")]
    Jwk(PublicKeyJwk),
}

impl Default for KeyType {
    fn default() -> Self {
        Self::KeyId(String::new())
    }
}
