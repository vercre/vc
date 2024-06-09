use std::str;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey};
use vercre_vc::proof::jose;

const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

#[must_use]
pub fn did() -> String {
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "X25519",
        "use": "enc",
        "x": JWK_X,
    });
    let jwk_str = jwk.to_string();
    let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

    format!("did:jwk:{jwk_b64}")
}

#[must_use]
pub fn kid() -> String {
    format!("{}#0", did())
}

#[must_use]
pub fn alg() -> jose::Algorithm {
    jose::Algorithm::EdDSA
}

/// Sign the provided message.
///
/// # Panics
#[must_use]
pub fn sign(msg: &[u8]) -> Vec<u8> {
    // let mut csprng = OsRng;
    // let signing_key: Ed25519SigningKey = Ed25519SigningKey::generate(&mut csprng);
    // signing_key.to_bytes().to_vec();
    // println!("d: {}", Base64UrlUnpadded::encode_string(&signing_key.to_bytes()));
    // println!("x: {}", Base64UrlUnpadded::encode_string(&signing_key.verifying_key().to_bytes()));

    let decoded = Base64UrlUnpadded::decode_vec(JWK_D).expect("should decode");
    let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
    let signing_key = SigningKey::from_bytes(&bytes);
    let sig: Signature = signing_key.sign(msg);

    sig.to_vec()
}
