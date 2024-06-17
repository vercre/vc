//! Sample Signer implementation. This is a hard-coded signer for example purposes only. Real
//! implementations should use a secure key store and secure signing methods.

use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use vercre_holder::provider::{Algorithm, Signer};

use super::Provider;

const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

impl Signer for Provider {
    /// Algorithm returns the algorithm used by the signer.
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    /// The verification method the verifier should use to verify the signer's
    /// signature. This is typically a DID URL + # + verification key ID.
    fn verification_method(&self) -> String {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": JWK_X,
        });
        let jwk_str = jwk.to_string();
        let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

        let holder_did = format!("did:jwk:{jwk_b64}");
        format!("{holder_did}#0")
    }

    /// Sign the payload.
    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = SigningKey::from_bytes(&bytes);
        let sig: Signature = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}
