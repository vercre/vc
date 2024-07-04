//! # JSON Web Encryption (JWE)
//!
//! JWE ([RFC7516]) specifies how encrypted content can be represented using JSON.
//!
//! See JWA ([RFC7518]) for more on the cyptographic algorithms and identifiers
//! used.
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! Set of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
//! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml

// Compact:
// base64Url(UTF8(JWE Protected Header)) + '.' +
// base64Url(JWE Encrypted Key) + '.' +
// base64Url(JWE Initialization Vector) + '.' +
// base64Url(JWE Ciphertext) + '.' +
// base64Url(JWE Authentication Tag)

// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

// https://www.rfc-editor.org/rfc/rfc7516.html (JSON Web Encryption (JWE))
// https://www.rfc-editor.org/rfc/rfc7518.html (JSON Web Algorithms (JWA))

// "alg_values_supported" : [
// 	"ECDH-ES" // <- Diffie-Hellman Ephemeral Static key agreement using Concat KDF
// ],
// "enc_values_supported" : [
// 	"A128GCM" // <- 128-bit AES-GCM
// ],

// https://www.rfc-editor.org/rfc/rfc7518#appendix-C:

// {
// 	"alg":"ECDH-ES",
// 	"enc":"A128GCM",
// 	"apu":"QWxpY2U",
// 	"apv":"Qm9i",
// 	"epk": {
// 		"kty":"EC",
//         "crv":"P-256",
//         "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//         "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
// 	}
// }
//
// {
//     "protected":"<integrity-protected header contents>",
//     "unprotected":<non-integrity-protected header contents>,
//     "header":<more non-integrity-protected header contents>,
//     "encrypted_key":"<encrypted key contents>",
//     "aad":"<additional authenticated data contents>",
//     "iv":"<initialization vector contents>",
//     "ciphertext":"<ciphertext contents>",
//     "tag":"<authentication tag contents>"
// }

use core_utils::Quota;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// use crate::jose::jwa::Algorithm;
use crate::jose::jwk::Jwk;

/// Encrypt the plaintext and return the JWE.
#[allow(dead_code)]
pub fn encrypt() -> anyhow::Result<String> {
    todo!()
}

/// Decrypt the JWE and return the plaintext.
#[allow(dead_code)]
pub fn decrypt() -> anyhow::Result<String> {
    todo!()
}

/// In JWE JSON serialization, one or more of the JWE Protected Header, JWE Shared
/// Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be present. In
/// this case, the members of the JOSE Header are the union of the members of the JWE
/// Protected Header, JWE Shared Unprotected Header, and JWE Per-Recipient Unprotected
/// Header values that are present.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Jwe {
    /// JWE protected header, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    protected: Option<String>,

    /// Shared unprotected header as a JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    unprotected: Option<Value>,

    /// Encrypted key, as a base64Url encoded string.
    encrypted_key: String,

    /// JWE initialization vector, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    iv: Option<String>,

    /// JWE AAD, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<String>,

    /// JWE Ciphertext, as a base64Url encoded string.
    ciphertext: String,

    /// Authentication tag, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<String>,

    /// Recipients array contains information specific to a single
    /// recipient.
    recipients: Quota<Recipient>,
}

/// Contains information specific to a single recipient.
/// MUST be present with exactly one array element per recipient, even if some
/// or all of the array element values are the empty JSON object "{}".
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Recipient {
    /// JWE Per-Recipient Unprotected Header.
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Header>,

    /// The recipient's JWE Encrypted Key, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_key: Option<String>,
}

/// Represents the JWE header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Has the same meaning as for JWS, except it identifies the cryptographic
    /// algorithm used to encrypt or determine the value of the CEK.
    pub alg: Algorithm,

    /// The content encryption algorithm used to perform authenticated encryption
    /// on the plaintext to produce the ciphertext and the Authentication
    /// Tag. MUST be an AEAD algorithm.
    pub enc: Encoding,

    /// Key agreement `PartyUInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apu: String,

    /// Key agreement `PartyVInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apv: String,

    /// The ephemeral public key created by the originator for use in key agreement
    /// algorithms.
    pub epk: Jwk,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Algorithm {
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum Encoding {
    #[default]
    #[serde(rename = "A128GCM")]
    A128Gcm,
}
