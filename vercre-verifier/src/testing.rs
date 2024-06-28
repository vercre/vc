use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use ecdsa::signature::Signer as _;
use ecdsa::{Signature, SigningKey};
use k256::Secp256k1;

use crate::provider::{
    Algorithm, Callback, Client, ClientMetadata, CredentialFormat, Jwk, Payload, Result, Signer,
    StateManager, Verifier, VpFormat,
};

const SERVER_JWK_D: &str = "0Md3MhPaKEpnKAyKE498EdDFerD5NLeKJ5Rb-vC16Gs";
// pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const VERIFIER_ID: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";

const VERIFIER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            state_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ClientMetadata for Provider {
    async fn metadata(&self, client_id: &str) -> Result<Client> {
        VERIFIER.get(client_id).ok_or(anyhow!("client not found")).cloned()
    }

    async fn register(&self, _: &Client) -> Result<Client> {
        unimplemented!("register not implemented")
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> Result<()> {
        self.state_store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.state_store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state_store.lock().expect("should lock").remove(key);
        Ok(())
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        format!("{VERIFIER_DID}#{VERIFY_KEY_ID}")
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(SERVER_JWK_D)?;
        let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        let signature: Signature<Secp256k1> = signing_key.sign(msg);
        Ok(signature.to_vec())
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<Jwk> {
        let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

        // if have long-form DID then try to extract key from metadata
        let did_parts = did.split(':').collect::<Vec<&str>>();

        // if DID is a JWK then return it
        if did.starts_with("did:jwk:") {
            let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
                .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
            return serde_json::from_slice::<Jwk>(&decoded).map_err(anyhow::Error::from);
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

impl Callback for Provider {
    async fn callback(&self, _: &Payload) -> Result<()> {
        Ok(())
    }
}

static VERIFIER: LazyLock<HashMap<String, Client>> = LazyLock::new(|| {
    let verifier = Client {
        client_id: "http://vercre.io".into(),
        client_name: Some("Verifier".into()),
        redirect_uris: Some(vec!["http://localhost:3000/callback".into()]),
        grant_types: None,
        response_types: Some(vec!["vp_token".into(), "id_token vp_token".into()]),
        vp_formats: Some(HashMap::from([
            (
                CredentialFormat::JwtVcJson,
                VpFormat {
                    alg: Some(vec!["ES256K".into()]),
                    proof_type: Some(vec!["JsonWebSignature2020".into()]),
                },
            ),
            (
                CredentialFormat::JwtVcJson,
                VpFormat {
                    alg: Some(vec!["ES256K".into()]),
                    proof_type: Some(vec!["JsonWebSignature2020".into()]),
                },
            ),
        ])),
        ..Client::default()
    };

    // Local verifier client for use when running end to end tests
    let mut local = verifier.clone();
    local.client_id = "http://localhost:8080".into();

    HashMap::from([(verifier.client_id.clone(), verifier), (local.client_id.clone(), local)])
});
