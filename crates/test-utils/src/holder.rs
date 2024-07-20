use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Signer as _;
use openid::provider::Result;
use proof::signature::{Algorithm, Signer};

const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";
const WALLET_JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";

#[derive(Clone, Debug)]
pub struct Provider;
impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl Default for Provider {
    fn default() -> Self {
        Self::new()
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    fn verification_method(&self) -> String {
        format!("{}#0", holder_did())
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(WALLET_JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let signature: ed25519_dalek::Signature = signing_key.sign(msg);
        Ok(signature.to_vec())
    }
}

#[must_use]
pub fn holder_did() -> String {
    let jwk = serde_json::json!({
        "crv": "Ed25519",
        "kty": "OKP",
        "use": "sig",
        "x": JWK_X,
    });
    let jwk_str = jwk.to_string();
    let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

    // println!("did:jwk:{jwk_b64}");

    format!("did:jwk:{jwk_b64}")
}
