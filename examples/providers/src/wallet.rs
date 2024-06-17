use std::ops::Deref;
use std::str;

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use vercre_holder::provider::{Algorithm, Jwk, Signer, Verifier};

pub use crate::client::WALLET_CLIENT_ID as CLIENT_ID;
use crate::proof::Enclave;

const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

#[derive(Default, Clone, Debug)]
pub struct Provider(super::Provider);

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self(super::Provider::new())
    }
}

impl Deref for Provider {
    type Target = super::Provider;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    fn verification_method(&self) -> String {
        format!("{}#0", holder_did())
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = SigningKey::from_bytes(&bytes);
        let sig: Signature = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}

impl Verifier for Provider {
    fn deref_jwk(&self, did_url: impl AsRef<str>) -> anyhow::Result<Jwk> {
        Enclave::deref_jwk(did_url)
    }
}

#[must_use]
pub fn holder_did() -> String {
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
