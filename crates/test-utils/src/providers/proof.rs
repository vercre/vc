use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use ecdsa::signature::Signer as _;
use ecdsa::{Signature, SigningKey};
use k256::Secp256k1;
use openid4vc::endpoint::{PublicKeyJwk, Result};

pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
const ISSUER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
const SERVER_JWK_D: &str = "0Md3MhPaKEpnKAyKE498EdDFerD5NLeKJ5Rb-vC16Gs";

#[derive(Default, Clone, Debug)]
pub struct Enclave;

impl Enclave {
    pub fn verification_method() -> String {
        format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
    }

    pub fn try_sign(msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(SERVER_JWK_D)?;
        let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        let signature: Signature<Secp256k1> = signing_key.sign(msg);

        Ok(signature.to_vec())
    }

    // TODO: use vercre-did crate to dereference DID URL

    pub fn deref_jwk(did_url: &str) -> Result<PublicKeyJwk> {
        let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

        // if have long-form DID then try to extract key from metadata
        let did_parts = did.split(':').collect::<Vec<&str>>();

        // if DID is a JWK then return it
        if did.starts_with("did:jwk:") {
            let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
                .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
            return serde_json::from_slice::<PublicKeyJwk>(&decoded).map_err(anyhow::Error::from);
        }

        // HACK: for now, assume DID is long-form with delta operation containing public key
        // TODO: use vercre-did crate to dereference DID URL

        // DID should be long-form ION
        if did_parts.len() != 4 {
            bail!("Short-form DID's are not supported");
        }

        let decoded = Base64UrlUnpadded::decode_vec(did_parts[3])
            .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
        let ion_op = serde_json::from_slice::<serde_json::Value>(&decoded)?;

        let pk_val = ion_op
            .get("delta")
            .unwrap()
            .get("patches")
            .unwrap()
            .get(0)
            .unwrap()
            .get("document")
            .unwrap()
            .get("publicKeys")
            .unwrap()
            .get(0)
            .unwrap()
            .get("publicKeyJwk")
            .unwrap();

        serde_json::from_value(pk_val.clone()).map_err(anyhow::Error::from)
    }
}
