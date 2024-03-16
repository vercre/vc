// Because we have a WASM web application there is no opportunity to use a key storage solution
// directly. Instead, we call a signer service.
//
// TODO: replace the hard-coded sample code with a call to a hosted signer service

use core::str;

use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::{Signer as EcdsaSigner, Verifier};
use ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::Secp256k1;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use vercre_wallet::signer::{SignerRequest, SignerResponse};

pub async fn request(op: &SignerRequest) -> Result<SignerResponse, Option<String>> {
    match op {
        SignerRequest::Sign(msg) => {
            let signature = match sign(msg) {
                Ok(signature) => signature,
                Err(err) => return Err(err),
            };
            Ok(SignerResponse::Signature(signature))
        }
        SignerRequest::Verification => {
            let ak = match verification() {
                Ok(ak) => ak,
                Err(err) => return Err(err),
            };
            Ok(SignerResponse::Verification {
                alg: ak.alg,
                kid: ak.kid,
            })
        }
    }
}

struct AlgAndKey {
    alg: String,
    kid: String,
}

/// Sample signing key structure for testing purposes.
#[derive(Serialize)]
pub struct SignKey {
    d: String,
    kty: String,
    crv: String,
    x: String,
    y: String,
}

// Elliptic curve signing key using the secp256k1 curve. To arrive at the hard-coded values for this
// key you can use the following code:
// let sk = k256::SecretKey::random(&mut OsRng);
// let j = sk.to_jwk_string();
// println!("jwk: {:#?}", j);
impl SignKey {
    fn new() -> Self {
        // jwkEs256k1Private
        Self {
            d: "CB6W6NKEuI4uiYiyM2CM4YzczOYXdx-ykAe5rlZaB-Q".to_string(),
            kty: "EC".to_string(),
            crv: "secp256k1".to_string(),
            x: "XFl4fd9n4qp2Gcc2_oqqUsI3uT63o3Jt0f54DiNOijw".to_string(),
            y: "IH_q19UKDu_jkIwtehWU7NiaXk7CaGoD-XRcuuqcgQ0".to_string(),
        }
    }
}

fn sign(msg: &[u8]) -> Result<Vec<u8>, Option<String>> {
    let hdr_b = serde_json::to_vec(&json!({"alg": "ES256K"})).expect("failed to serialize");
    let hdr_64 = Base64UrlUnpadded::encode_string(&hdr_b);
    let msg_64 = Base64UrlUnpadded::encode_string(msg);
    let mut payload = [hdr_64.as_bytes(), b".", msg_64.as_bytes()].concat();
    let digest: [u8; 32] = Sha256::digest(&payload).into();

    let sign_key = SignKey::new();
    let d_b = Base64UrlUnpadded::decode_vec(&sign_key.d).expect("failed to decode");
    let key: SigningKey<Secp256k1> = SigningKey::from_slice(&d_b).expect("failed to create key");
    let sig: Signature<Secp256k1> = key.sign(&digest);
    let encoded_sig = Base64UrlUnpadded::encode_string(&sig.to_bytes());

    payload.extend(b".");
    payload.extend(encoded_sig.as_bytes());
    Ok(payload.to_vec())
}

fn verification() -> Result<AlgAndKey, Option<String>> {
    let sign_key = SignKey::new();

    let mut sec1 = vec![0x04];
    let mut x = match Base64UrlUnpadded::decode_vec(&sign_key.x) {
        Ok(x) => x,
        Err(e) => return Err(Some(format!("Error decoding x coordinate: {e}"))),
    };
    sec1.append(&mut x);
    let mut y = match Base64UrlUnpadded::decode_vec(&sign_key.y) {
        Ok(y) => y,
        Err(e) => return Err(Some(format!("Error decoding x coordinate: {e}"))),
    };
    sec1.append(&mut y);
    // let vk = match VerifyingKey::from_sec1_bytes(&sec1) {
    //     Ok(vk) => vk,
    //     Err(e) => return Err(Some(format!("Error creating verifying key: {e}"))),
    // };
    let str_vk = match String::from_utf8(sec1) {
        Ok(str_vk) => str_vk,
        Err(e) => return Err(Some(format!("Error converting verifying key from bytes: {e}"))),
    };
    Ok(AlgAndKey {
        alg: "ES256K".to_string(),
        kid: str_vk,
    })
}
