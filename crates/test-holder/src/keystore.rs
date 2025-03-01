use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::jose::jwa::Algorithm;
use ed25519_dalek::Signer;

const HOLDER_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const HOLDER_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
const HOLDER_SECRET: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

#[derive(Default, Clone, Debug)]
pub struct Keystore;

impl Keystore {
    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(HOLDER_SECRET)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let signature: ed25519_dalek::Signature = signing_key.sign(msg);
        Ok(signature.to_vec())
    }

    pub fn public_key() -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(HOLDER_VERIFY_KEY)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
        Ok(verify_key.as_bytes().to_vec())
    }

    #[must_use]
    pub const fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    #[must_use]
    pub fn verification_method() -> String {
        format!("{HOLDER_DID}#{HOLDER_VERIFY_KEY}")
    }
}
