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

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use core_utils::Quota;
use rand::rngs::OsRng;
use rand::RngCore;
use ring::aead;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{EphemeralSecret, PublicKey};

// use crate::jose::jwa::Algorithm;
use crate::jose::jwk::PublicKeyJwk;
use crate::jose::jwk::{Curve, KeyType};

const CEK_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;

/// Encrypt the plaintext and return the JWE.
#[allow(dead_code)]
pub fn encrypt<T: Serialize>(payload: T, recipient_key: &[u8; 32]) -> anyhow::Result<String> {
    // 1. Key Management Mode determines the Content Encryption Key (CEK)
    //    alg: "ECDH-ES" (Diffie-Hellman Ephemeral Static key agreement using Concat KDF)
    //    enc: "A128GCM" (128-bit AES-GCM)

    // 2. Generate a CEK — Content Encryption Mode — to encrypt payload
    let mut cek: Vec<u8> = vec![0; CEK_LENGTH];
    OsRng.fill_bytes(&mut cek);

    // 3. Use Key Agreement Algorithm to compute an shared secret to wrap the CEK.
    let sender_secret = EphemeralSecret::random_from_rng(OsRng);
    let sender_public = PublicKey::from(&sender_secret);
    let shared_secret = sender_secret.diffie_hellman(&PublicKey::from(*recipient_key));
    let epk = PublicKeyJwk {
        kty: KeyType::Okp,
        crv: Curve::Ed25519,
        x: Base64UrlUnpadded::encode_string(&sender_public.to_bytes()),
        ..PublicKeyJwk::default()
    };

    // 4. Encrypt the CEK and set as the JWE Encrypted Key.
    let encrypted_cek = encrypt_cek(&cek, &shared_secret.to_bytes())?;

    // 9. Generate a random JWE Initialization Vector (nonce) of the correct size
    //    for the content encryption algorithm (A128GCM).
    let mut iv: [u8; aead::NONCE_LEN] = [0; aead::NONCE_LEN];
    OsRng.fill_bytes(&mut iv);

    // 12. Create the JSON Header object -> JWE Protected Header.
    let header = Header {
        alg: CekAlgorithm::EcdhEs,
        enc: EncryptionAlgorithm::A128Gcm,
        apu: Base64UrlUnpadded::encode_string(b"Alice"),
        apv: Base64UrlUnpadded::encode_string(b"Bob"),
        epk,
        iv: iv.to_vec(),
        tag: vec![0; TAG_LENGTH],
    };
    let header_bytes = serde_json::to_vec(&header)?;

    // 14. Set the Additional Authenticated Data encryption parameter to
    //     Encoded Protected Header (step 13)

    // 15. Encrypt plaintext using the CEK, the JWE Initialization Vector, and the
    //     Additional Authenticated Data using the content encryption algorithm to
    //     create the JWE Ciphertext value and the JWE Authentication Tag (which is
    //     the Authentication Tag output from the encryption operation).
    let payload_bytes = serde_json::to_vec(&payload)?;
    let (ciphertext, tag) = encrypt_content(&payload_bytes, &cek, &iv, &header_bytes)?;

    // 19. base64(JWE Protected Header) '.'  base64(JWE Encrypted Key) '.'
    //     base64(JWE Initialization Vector) '.'  base64(JWE Ciphertext) '.'
    //     base64(JWE Authentication Tag)
    let enc_header = Base64UrlUnpadded::encode_string(&serde_json::to_vec(&header_bytes)?);
    let enc_cek = Base64UrlUnpadded::encode_string(&encrypted_cek);
    let enc_iv = Base64UrlUnpadded::encode_string(&iv);
    let enc_payload = Base64UrlUnpadded::encode_string(&ciphertext);
    let enc_tag = Base64UrlUnpadded::encode_string(&tag);

    Ok(format!("{enc_header}.{enc_cek}.{enc_iv}.{enc_payload}.{enc_tag}"))
}

fn encrypt_cek(cek: &[u8], shared_secret: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut nonce: [u8; aead::NONCE_LEN] = [0; aead::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let aead_nonce = aead::Nonce::assume_unique_for_key(nonce);
    let aead_aad = aead::Aad::from(&[]);
    let mut in_out = cek.to_vec();

    let encryption_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, shared_secret)
        .map_err(|e| anyhow!("key issue: {e}"))?;
    let sealing_key = aead::LessSafeKey::new(encryption_key);

    let _ = sealing_key
        .seal_in_place_separate_tag(aead_nonce, aead_aad, &mut in_out)
        .map_err(|e| anyhow!("issue encrypting CEK: {e}"))?;

    Ok(in_out)
}

fn encrypt_content(
    plaintext: &[u8], cek: &[u8], iv: &[u8], aad: &[u8],
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let aead_nonce =
        aead::Nonce::try_assume_unique_for_key(iv).map_err(|e| anyhow!("nonce issue: {e}"))?;
    let aead_aad = aead::Aad::from(aad);
    let mut in_out: Vec<u8> = plaintext.to_vec();

    let encryption_key =
        aead::UnboundKey::new(&aead::AES_128_GCM, cek).map_err(|e| anyhow!("key issue: {e}"))?;
    let sealing_key = aead::LessSafeKey::new(encryption_key);

    let tag = sealing_key
        .seal_in_place_separate_tag(aead_nonce, aead_aad, &mut in_out)
        .map_err(|e| anyhow!("tag issue: {e}"))?;

    Ok((in_out, tag.as_ref().to_vec()))
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
