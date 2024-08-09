//! # JSON Web Encryption (JWE)
//!
//! JWE ([RFC7516]) specifies how encrypted content can be represented using JSON.
//! See JWA ([RFC7518]) for more on the cyptographic algorithms and identifiers
//! used.
//!
//! See also:
//!
//! - <https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms>
//! - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signatures in JOSE ([ECDH])
//!
//! ## Note
//!
//! If the JWT is only a JWE, iss, exp and aud MUST be omitted in the JWT Claims
//! of the JWE, and the processing rules as per JARM Section 2.4 related to
//! these claims do not apply. [OpenID4VP] JWT - JWE
//!
//! [RFC7516]: https://www.rfc-editor.org/rfc/rfc7516
//! [RFC7518]: https://www.rfc-editor.org/rfc/rfc7518
//! [IANA]: https://www.iana.org/assignments/jose/jose.xhtml
//! [ECDH]: https://tools.ietf.org/html/rfc8037

//! # Example
//!
//! Reference JSON for ECDH/A128GCM from specification
//! (<https://www.rfc-editor.org/rfc/rfc7518#appendix-C>):
//!
//!```json
//! {
//!     "alg":"ECDH-ES",
//!     "enc":"A128GCM",
//!     "apu":"QWxpY2U",
//!     "apv":"Qm9i",
//!     "epk": {
//!          "kty":"EC",
//!          "crv":"P-256",
//!          "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
//!          "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"
//!     }
//! }
//! ```

// TODO: investigate PartyUInfo and PartyVInfo more thoroughly
// The ephemeral public key for the Agreement is stored alongside the wrapped per-file key.
// The KDF is Concatenation Key Derivation Function (Approved Alternative 1) as described in
// 5.8.1 of NIST SP 800-56A. AlgorithmID is omitted. PartyUInfo and PartyVInfo are the ephemeral
// and static public keys, respectively. SHA256 is used as the hashing function.

use std::fmt::{self, Display};
use std::str::FromStr;

use aes_gcm::aead::KeyInit; // heapless,
use aes_gcm::{AeadInPlace, Aes128Gcm, Key, Nonce};
use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded as Base64, Encoding};
use crypto_box::aead::{AeadCore, OsRng};
use crypto_box::Tag;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jose::jwk::{Curve, KeyType, PublicKeyJwk};
use crate::{Decryptor, Encryptor};

/// Encrypt plaintext and return a JWE.
///
/// N.B. We currently only support ECDH-ES key agreement and A128GCM
/// content encryption.
///
/// # Errors
///
/// Returns an error if the plaintext cannot be encrypted.
pub async fn encrypt<T: Serialize + Send>(
    plaintext: T, recipient_key: &[u8; 32], encryptor: &impl Encryptor,
) -> anyhow::Result<String> {
    // 1. Key Management Mode determines the Content Encryption Key (CEK)
    //     - alg: "ECDH-ES" (Diffie-Hellman Ephemeral Static key agreement using Concat KDF)
    //     - enc: "A128GCM" (128-bit AES-GCM)

    // 2. Generate a CEK — Content Encryption Mode — to encrypt payload
    let cek = Aes128Gcm::generate_key(&mut OsRng);

    // 3. Use Key Agreement Algorithm (ECDH) to compute a shared secret to wrap the CEK.
    // 4. Encrypt the CEK and set as the JWE Encrypted Key.
    let encrypted_cek = encryptor.encrypt(&cek, recipient_key).await?;

    // 9. Generate a random JWE Initialization Vector (nonce) of the correct size
    //    for the content encryption algorithm (A128GCM).
    let iv = Aes128Gcm::generate_nonce(&mut OsRng);

    // 12. Create the JSON Header object (JWE Protected Header).
    let header = Header {
        alg: CekAlgorithm::EcdhEs,
        enc: EncryptionAlgorithm::A128Gcm,
        apu: Base64::encode_string(b"Alice"),
        apv: Base64::encode_string(b"Bob"),
        epk: PublicKeyJwk {
            kty: KeyType::Okp,
            crv: Curve::Ed25519,
            x: Base64::encode_string(&encryptor.public_key()),
            ..PublicKeyJwk::default()
        },
    };

    // 14. Set the Additional Authenticated Data (AAD) encryption parameter to
    //     Encoded Protected Header (step 13)
    let aad = &Base64::encode_string(&serde_json::to_vec(&header)?);

    // 15. Encrypt plaintext using the CEK, the JWE Initialization Vector, and the
    //     Additional Authenticated Data using the content encryption algorithm to
    //     create the JWE Ciphertext value and the JWE Authentication Tag (which is
    //     the Authentication Tag output from the encryption operation).
    let mut buffer = serde_json::to_vec(&plaintext)?;

    let tag = Aes128Gcm::new(&cek)
        .encrypt_in_place_detached(&iv, aad.as_bytes(), &mut buffer)
        .map_err(|e| anyhow!("issue encrypting: {e}"))?;

    let jwe = Jwe {
        protected: header,
        encrypted_key: Base64::encode_string(&encrypted_cek),
        iv: Base64::encode_string(&iv),
        ciphertext: Base64::encode_string(&buffer),
        tag: Base64::encode_string(&tag),
        ..Jwe::default()
    };

    // 19. Return Compact Serialization of the JWE
    Ok(jwe.to_string())
}

// use aes_gcm::aead::heapless::Vec;
// use aes_gcm::AesGcm;

/// Decrypt the JWE and return the plaintext.
///
/// N.B. We currently only support ECDH-ES key agreement and A128GCM
///
/// # Errors
///
/// Returns an error if the JWE cannot be decrypted.
pub async fn decrypt<T: DeserializeOwned>(
    compact_jwe: &str, decryptor: &impl Decryptor,
) -> anyhow::Result<T> {
    // 1. Parse the JWE to extract the serialized values of it's components.
    // 3. Verify the JWE Protected Header.
    // 4. If using JWE Compact Serialization, let JOSE Header = JWE Protected Header.
    let jwe = Jwe::from_str(compact_jwe)?;

    // 2. Base64url decode the JWE Protected Header, JWE Encrypted Key,
    //    JWE Initialization Vector, JWE Ciphertext, JWE Authentication Tag, and
    //    JWE AAD,
    let encrypted_cek = Base64::decode_vec(&jwe.encrypted_key)
        .map_err(|e| anyhow!("issue decoding `encrypted_key`: {e}"))?;
    let iv = Base64::decode_vec(&jwe.iv).map_err(|e| anyhow!("issue decoding `iv`: {e}"))?;
    let ciphertext = Base64::decode_vec(&jwe.ciphertext)
        .map_err(|e| anyhow!("issue decoding `ciphertext`: {e}"))?;
    let tag = Base64::decode_vec(&jwe.tag).map_err(|e| anyhow!("issue decoding `tag`: {e}"))?;

    // 6. Determine the Key Management Mode specified by "alg"
    // N.B. not necessary as only ECDH-ES is supported

    // 9. When Key Wrapping, Key Encryption, or Key Agreement with Key Wrapping are
    //    employed, decrypt the JWE Encrypted Key to produce the CEK.
    // TODO: check kty and crv (at present we assume Ed25519)
    let sender_key = Base64::decode_vec(&jwe.protected.epk.x)
        .map_err(|e| anyhow!("issue decoding sender public key `x`: {e}"))?;
    let sender_key: &[u8; crypto_box::KEY_SIZE] = sender_key.as_slice().try_into()?;

    let cek = decryptor.decrypt(&encrypted_cek, sender_key).await?;

    // 12. Record whether the CEK could be successfully determined for this recipient.
    // 14. Compute the Encoded Protected Header value base64(JWE Protected Header).
    // 15. Let the Additional Authenticated Data (JWE AAD) = Encoded Protected Header.
    let aad = jwe.protected.to_string();

    // 16. Decrypt the JWE Ciphertext using the CEK, the JWE Initialization Vector,
    //     the Additional Authenticated Data value, and the JWE Authentication Tag.
    let mut buffer = ciphertext;
    let nonce = Nonce::from_slice(&iv);
    let tag = Tag::from_slice(&tag);

    Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&cek))
        .decrypt_in_place_detached(nonce, aad.as_bytes(), &mut buffer, tag)
        .map_err(|e| anyhow!("issue decrypting: {e}"))?;

    Ok(serde_json::from_slice(&buffer)?)
}

/// In JWE JSON serialization, one or more of the JWE Protected Header, JWE Shared
/// Unprotected Header, and JWE Per-Recipient Unprotected Header MUST be present. In
/// this case, the members of the JOSE Header are the union of the members of the JWE
/// Protected Header, JWE Shared Unprotected Header, and JWE Per-Recipient Unprotected
/// Header values that are present.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwe {
    /// JWE protected header.
    protected: Header,

    /// Shared unprotected header as a JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    unprotected: Option<Value>,

    /// Encrypted key, as a base64Url encoded string.
    encrypted_key: String,

    /// AAD value, base64url encoded. Not used for JWE Compact Serialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    aad: Option<String>,

    /// Initialization vector (nonce), as a base64Url encoded string.
    iv: String,

    /// Ciphertext, as a base64Url encoded string.
    ciphertext: String,

    /// Authentication tag resulting from the encryption, as a base64Url encoded string.
    tag: String,
    //
    // /// Recipients array contains information specific to a single
    // /// recipient.
    // recipients: Quota<Recipient>,
}

/// Compact Serialization
///     base64(JWE Protected Header) + '.'
///     + base64(JWE Encrypted Key) + '.'
///     + base64(JWE Initialization Vector) + '.'
///     + base64(JWE Ciphertext) + '.'
///     + base64(JWE Authentication Tag)
impl Display for Jwe {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let protected = &self.protected.to_string();
        let encrypted_key = &self.encrypted_key;
        let iv = &self.iv;
        let ciphertext = &self.ciphertext;
        let tag = &self.tag;

        write!(f, "{protected}.{encrypted_key}.{iv}.{ciphertext}.{tag}")
    }
}

impl FromStr for Jwe {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 5 {
            return Err(anyhow!("invalid JWE"));
        }

        Ok(Self {
            protected: Header::from_str(parts[0])?,
            encrypted_key: parts[1].to_string(),
            iv: parts[2].to_string(),
            ciphertext: parts[3].to_string(),
            tag: parts[4].to_string(),
            ..Self::default()
        })
    }
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
}

/// Serialize Header to base64 encoded string
impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = serde_json::to_vec(&self).map_err(|_| fmt::Error)?;
        write!(f, "{}", Base64::encode_string(&bytes))
    }
}

impl FromStr for Header {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = Base64::decode_vec(s).map_err(|e| anyhow!("issue decoding header: {e}"))?;
        serde_json::from_slice(&bytes).map_err(|e| anyhow!("issue deserializing header: {e}"))
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

/// The algorithm used to encrypt or determine the value of the content encryption
/// key (CEK).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum CekAlgorithm {
    /// Elliptic Curve Diffie-Hellman Ephemeral-Static key agreement
    /// (using Concat KDF).
    #[default]
    #[serde(rename = "ECDH-ES")]
    EcdhEs,
}

/// The algorithm used to perform authenticated encryption on the plaintext to
/// produce the ciphertext and the Authentication Tag. MUST be an AEAD algorithm.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES in Galois/Counter Mode (GCM) using a 128-bit key.
    #[default]
    #[serde(rename = "A128GCM")]
    A128Gcm,
}

#[cfg(test)]
mod test {
    use crypto_box::aead::{Aead, OsRng};
    use crypto_box::{ChaChaBox, PublicKey, SecretKey};

    use super::*;

    #[tokio::test]
    async fn round_trip() {
        let key_store = KeyStore::new();
        let recipient_public = PublicKey::from(&key_store.recipient_secret);

        // round trip: encrypt and then decrypt
        let plaintext = "The true sign of intelligence is not knowledge but imagination.";

        let compact_jwe = encrypt(plaintext, &recipient_public.to_bytes(), &key_store)
            .await
            .expect("should encrypt");
        let decrypted: String = decrypt(&compact_jwe, &key_store).await.expect("should decrypt");

        assert_eq!(plaintext, decrypted);
    }

    // Basic key store for testing
    struct KeyStore {
        x25519_secret: x25519_dalek::StaticSecret,
        recipient_secret: SecretKey,
    }

    impl KeyStore {
        fn new() -> Self {
            Self {
                x25519_secret: x25519_dalek::StaticSecret::random_from_rng(&mut OsRng),
                recipient_secret: SecretKey::generate(&mut OsRng),
            }
        }
    }

    impl Encryptor for KeyStore {
        async fn encrypt(
            &self, plaintext: &[u8], recipient_public_key: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            let pk: &[u8; 32] = recipient_public_key.try_into()?;

            let secret_key = SecretKey::from_bytes(self.x25519_secret.to_bytes());

            let chachabox = ChaChaBox::new(&PublicKey::from(*pk), &secret_key);
            let ciphertext = chachabox
                .encrypt(&Nonce::default(), plaintext)
                .map_err(|e| anyhow!("issue encrypting: {e}"))?;

            Ok(ciphertext)
        }

        fn public_key(&self) -> Vec<u8> {
            x25519_dalek::PublicKey::from(&self.x25519_secret).as_bytes().to_vec()
        }
    }

    impl Decryptor for KeyStore {
        async fn decrypt(
            &self, ciphertext: &[u8], sender_public_key: &[u8],
        ) -> anyhow::Result<Vec<u8>> {
            let pk: &[u8; 32] = sender_public_key.try_into()?;

            let chachabox = ChaChaBox::new(&PublicKey::from(*pk), &self.recipient_secret);
            let plaintext = chachabox
                .decrypt(&Nonce::default(), ciphertext)
                .map_err(|e| anyhow!("issue decrypting: {}", e.to_string()))?;

            Ok(plaintext)
        }
    }
}
