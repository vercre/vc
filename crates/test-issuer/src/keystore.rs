use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use credibil_infosec::jose::jwa::Algorithm;
use credibil_vc::openid::provider::Result;
use ed25519_dalek::{SecretKey, Signer, SigningKey};

#[derive(Default, Clone, Debug)]
pub struct Keystore;

const ISSUER_DID: &str = "did:web:demo.credibil.io";
const ISSUER_VERIFY_KEY: &str = "key-0";
const ISSUER_SECRET: &str = "cCxmHfFfIJvP74oNKjAuRC3zYoDMo0pFsAs19yKMowY";

impl Keystore {
    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        // let decoded = Base64UrlUnpadded::decode_vec(SECRET_KEY)?;
        // let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        // Ok(signing_key.sign(msg).to_vec())

        let decoded = Base64UrlUnpadded::decode_vec(ISSUER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
        Ok(signing_key.sign(msg).to_bytes().to_vec())
    }

    pub fn public_key() -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(ISSUER_SECRET)?;
        let secret_key: SecretKey =
            decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
        let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);

        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    #[must_use]
    pub const fn algorithm() -> Algorithm {
        Algorithm::EdDSA
    }

    #[must_use]
    pub fn verification_method() -> String {
        format!("{ISSUER_DID}#{ISSUER_VERIFY_KEY}")
    }
}

// #[derive(Default, Clone, Debug)]
// pub struct VerifierKeystore;

// const VERIFIER_DID: &str = "did:web:demo.credibil.io";
// const VERIFIER_VERIFY_KEY: &str = "key-0";
// const VERIFIER_SECRET: &str = "cCxmHfFfIJvP74oNKjAuRC3zYoDMo0pFsAs19yKMowY";

// impl VerifierKeystore {
//     pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
//         let decoded = Base64UrlUnpadded::decode_vec(VERIFIER_SECRET)?;
//         let secret_key: SecretKey =
//             decoded.try_into().map_err(|_| anyhow!("Invalid secret key"))?;
//         let signing_key: SigningKey = SigningKey::from_bytes(&secret_key);
//         Ok(signing_key.sign(msg).to_bytes().to_vec())
//     }

//     pub fn public_key() -> Result<Vec<u8>> {
//         let decoded = Base64UrlUnpadded::decode_vec(VERIFIER_VERIFY_KEY)?;
//         let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
//         let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
//         Ok(verify_key.as_bytes().to_vec())
//     }

//     #[must_use]
//     pub const fn algorithm() -> Algorithm {
//         Algorithm::EdDSA
//     }

//     #[must_use]
//     pub fn verification_method() -> String {
//         format!("{VERIFIER_DID}#{VERIFIER_VERIFY_KEY}")
//     }
// }

// const HOLDER_DID: &str = "did:key:z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
// const HOLDER_VERIFY_KEY: &str = "z6Mkj8Jr1rg3YjVWWhg7ahEYJibqhjBgZt1pDCbT4Lv7D4HX";
// const HOLDER_SECRET: &str = "8rmFFiUcTjjrL5mgBzWykaH39D64VD0mbDHwILvsu30";

// #[derive(Default, Clone, Debug)]
// pub struct HolderKeystore;

// impl HolderKeystore {
//     pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
//         let decoded = Base64UrlUnpadded::decode_vec(HOLDER_SECRET)?;
//         let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
//         let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
//         let signature: ed25519_dalek::Signature = signing_key.sign(msg);
//         Ok(signature.to_vec())
//     }

//     pub fn public_key() -> Result<Vec<u8>> {
//         let decoded = Base64UrlUnpadded::decode_vec(HOLDER_VERIFY_KEY)?;
//         let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
//         let verify_key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)?;
//         Ok(verify_key.as_bytes().to_vec())
//     }

//     #[must_use]
//     pub const fn algorithm() -> Algorithm {
//         Algorithm::EdDSA
//     }

//     #[must_use]
//     pub fn verification_method() -> String {
//         format!("{HOLDER_DID}#{HOLDER_VERIFY_KEY}")
//     }
// }
