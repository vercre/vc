//! # JSON Web Encryption (JWE)
//!
//! JWE ([RFC7516]) specifies how encrypted content can be represented using JSON.
//!
//! See JWA ([RFC7518]) for more on the cyptographic algorithms and identifiers
//! used.
//!
//! CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE ([ECDH])
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
//! [ECDH]: https://tools.ietf.org/html/rfc8037

// https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms

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

use std::fmt::{self, Display};

use aes_gcm::aead::KeyInit;
use aes_gcm::{AeadInPlace, Aes128Gcm};
use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded as Base64, Encoding};
use core_utils::Quota;
use crypto_box::aead::{Aead, AeadCore, OsRng};
use crypto_box::{ChaChaBox, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jose::jwk::{Curve, KeyType, PublicKeyJwk};

const CEK_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;

/// Encrypt the plaintext and return the JWE.
#[allow(dead_code)]
pub fn encrypt<T: Serialize>(plaintext: T, recipient_key: &[u8; 32]) -> anyhow::Result<String> {
    // 1. Key Management Mode determines the Content Encryption Key (CEK)
    //     - alg: "ECDH-ES" (Diffie-Hellman Ephemeral Static key agreement using Concat KDF)
    //     - enc: "A128GCM" (128-bit AES-GCM)

    // 2. Generate a CEK — Content Encryption Mode — to encrypt payload
    let cek = Aes128Gcm::generate_key(&mut OsRng);

    // 3. Use Key Agreement Algorithm (ECDH) to compute a shared secret to wrap the CEK.
    // 4. Encrypt the CEK and set as the JWE Encrypted Key.
    let sender_secret = SecretKey::generate(&mut OsRng);
    let cek_box = ChaChaBox::new(&PublicKey::from(*recipient_key), &sender_secret);

    let encrypted_cek = cek_box
        .encrypt(&ChaChaBox::generate_nonce(&mut OsRng), cek.as_slice())
        .map_err(|e| anyhow!("issue encrypting CEK: {e}"))?;

    // 9. Generate a random JWE Initialization Vector (nonce) of the correct size
    //    for the content encryption algorithm (A128GCM).
    let iv = Aes128Gcm::generate_nonce(&mut OsRng);

    // // 12. Create the JSON Header object -> JWE Protected Header.
    let header = Header {
        alg: CekAlgorithm::EcdhEs,
        enc: EncryptionAlgorithm::A128Gcm,
        apu: Base64::encode_string(b"Alice"),
        apv: Base64::encode_string(b"Bob"),
        epk: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64::encode_string(&sender_secret.public_key().to_bytes()),
            ..PublicKeyJwk::default()
        },
        iv: iv.to_vec(),
        tag: vec![0; TAG_LENGTH],
    };
    let header_bytes = serde_json::to_vec(&header)?;

    // 14. Set the Additional Authenticated Data (AAD) encryption parameter to
    //     Encoded Protected Header (step 13)
    let aad = &header_bytes;

    // 15. Encrypt plaintext using the CEK, the JWE Initialization Vector, and the
    //     Additional Authenticated Data using the content encryption algorithm to
    //     create the JWE Ciphertext value and the JWE Authentication Tag (which is
    //     the Authentication Tag output from the encryption operation).
    let mut in_out = serde_json::to_vec(&plaintext)?;
    let tag = Aes128Gcm::new(&cek)
        .encrypt_in_place_detached(&iv, aad, &mut in_out)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    let jwe = Jwe {
        protected: Some(Base64::encode_string(&serde_json::to_vec(&header_bytes)?)),
        encrypted_key: Base64::encode_string(&encrypted_cek),
        iv: Some(Base64::encode_string(&iv)),
        aad: Some(Base64::encode_string(aad)),
        ciphertext: Base64::encode_string(&in_out),
        tag: Some(Base64::encode_string(&tag)),
        ..Jwe::default()
    };

    // 19. Return Compact Serialization of the JWE
    Ok(jwe.to_string())
}

/// Decrypt the JWE and return the plaintext.
#[allow(dead_code)]
pub fn decrypt() -> anyhow::Result<String> {
    todo!()
}

/// Represents the JWE header.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Header {
    /// Identifies the algorithm used to encrypt or determine the value of the
    /// content encryption key (CEK).
    pub alg: CekAlgorithm,

    /// The algorithm used to perform authenticated encryption on the plaintext
    /// to produce the ciphertext and the Authentication Tag. MUST be an AEAD
    /// algorithm.
    pub enc: EncryptionAlgorithm,

    /// Key agreement `PartyUInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apu: String,

    /// Key agreement `PartyVInfo` value, used to generate the shared key.
    /// Contains producer information as a base64url string.
    pub apv: String,

    /// The ephemeral public key created by the originator for use in key agreement
    /// algorithms.
    pub epk: PublicKeyJwk,

    /// Initialization vector, or nonce, used in the encryption
    pub iv: Vec<u8>,

    /// The authentication tag resulting from the encryption
    pub tag: Vec<u8>,
}

/// In JWE JSON serialization, one or more of the JWE Protected Header, JWE Shared
/// Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be present. In
/// this case, the members of the JOSE Header are the union of the members of the JWE
/// Protected Header, JWE Shared Unprotected Header, and JWE Per-Recipient Unprotected
/// Header values that are present.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
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

/// Compact Serialization
///     base64(JWE Protected Header) + '.'
///     + base64(JWE Encrypted Key) + '.'
///     + base64(JWE Initialization Vector) + '.'
///     + base64(JWE Ciphertext) + '.'
///     + base64(JWE Authentication Tag)
impl Display for Jwe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let header = self.protected.as_ref().map_or("", String::as_str);
        let cek = &self.encrypted_key;
        let iv = self.iv.as_ref().map_or("", String::as_str);
        let ciphertext = &self.ciphertext;
        let tag = self.tag.as_ref().map_or("", String::as_str);

        write!(f, "{header}.{cek}.{iv}.{ciphertext}.{tag}")
    }
}

/// Contains information specific to a single recipient.
/// MUST be present with exactly one array element per recipient, even if some
/// or all of the array element values are the empty JSON object "{}".
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct Recipient {
    /// JWE Per-Recipient Unprotected Header.
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Header>,

    /// The recipient's JWE Encrypted Key, as a base64Url encoded string.
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_key: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CekAlgorithm {
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    #[default]
    #[serde(rename = "A128GCM")]
    A128Gcm,
}

#[cfg(test)]
mod test {
    // use x25519_dalek::StaticSecret;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    use super::*;

    #[test]
    fn test_encrypt() {
        // let secret_key = StaticSecret::random_from_rng(&mut OsRng);

        let recipient_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let recipient_public = PublicKey::from(&recipient_secret);

        let res = encrypt("test", &recipient_public.to_bytes());
        println!("{:?}", res);
    }
}
