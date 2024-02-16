use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use ecdsa::signature::Signer as _;
use ecdsa::{Signature, SigningKey};
use k256::Secp256k1;
use vercre_core::callback::Payload;
use vercre_core::metadata::{self, VpFormat};
use vercre_core::{Algorithm, Callback, Client, Signer, StateManager};

pub const VERIFIER: &str = "http://credibil.io";
pub const VERIFIER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
const JWK_D: &str = "0Md3MhPaKEpnKAyKE498EdDFerD5NLeKJ5Rb-vC16Gs";

#[derive(Clone, Debug, Default)]
pub struct Provider {
    client: ClientStore,
    state_store: StateStore,
    callback: CallbackHook,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: ClientStore::new(),
            state_store: StateStore::new(),
            callback: CallbackHook::new(),
        }
    }
}

impl Client for Provider {
    async fn metadata(&self, client_id: &str) -> anyhow::Result<metadata::Client> {
        self.client.get(client_id)
    }

    async fn register(&self, _: &metadata::Client) -> anyhow::Result<metadata::Client> {
        unimplemented!("register not implemented")
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> anyhow::Result<()> {
        self.state_store.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        self.state_store.get(key)
    }

    async fn purge(&self, key: &str) -> anyhow::Result<()> {
        self.state_store.purge(key)
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        format!("{VERIFIER_DID}#{VERIFY_KEY_ID}")
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        let sig: Signature<Secp256k1> = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> anyhow::Result<()> {
        self.callback.callback(pl)
    }
}

//-----------------------------------------------------------------------------
// Verifier
//-----------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct ClientStore {
    clients: HashMap<String, metadata::Client>,
}

impl ClientStore {
    fn new() -> Self {
        let client_meta = metadata::Client {
            client_id: "http://credibil.io".to_string(),
            redirect_uris: Some(vec!["http://localhost:3000/callback".to_string()]),
            grant_types: Some(vec!["authorization_code".to_string()]),
            response_types: Some(vec!["vp_token".to_string(), "id_token vp_token".to_string()]),
            vp_formats: Some(HashMap::from([
                (
                    "jwt_vc_json".to_string(),
                    VpFormat {
                        alg: Some(vec!["ES256K".to_string()]),
                        proof_type: Some(vec!["JsonWebSignature2020".to_string()]),
                    },
                ),
                (
                    "jwt_vp_json".to_string(),
                    VpFormat {
                        alg: Some(vec!["ES256K".to_string()]),
                        proof_type: Some(vec!["JsonWebSignature2020".to_string()]),
                    },
                ),
                // (
                //     "ldp_vc".to_string(),
                //     VpFormat {
                //         alg: Some(vec!["ES256K".to_string()]),
                //         proof_type: Some(vec!["Ed25519Signature2018".to_string()]),
                //     },
                // ),
                // (
                //     "ldp_vp".to_string(),
                //     VpFormat {
                //         alg: Some(vec!["ES256K".to_string()]),
                //         proof_type: Some(vec!["Ed25519Signature2018".to_string()]),
                //     },
                // ),
            ])),
            ..Default::default()
        };

        let mut local_client = client_meta.clone();
        local_client.client_id = "http://localhost:8080".to_string();

        let clients = HashMap::from([
            (client_meta.client_id.clone(), client_meta),
            (local_client.client_id.clone(), local_client),
        ]);

        Self { clients }
    }

    fn get(&self, client_id: &str) -> anyhow::Result<metadata::Client> {
        let Some(client) = self.clients.get(client_id) else {
            return Err(anyhow!("verifier not found"));
        };
        Ok(client.clone())
    }
}

//-----------------------------------------------------------------------------
// StateStore
//-----------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
struct StateStore {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl StateStore {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> anyhow::Result<()> {
        self.store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        match self.store.lock().expect("should lock").get(key) {
            Some(data) => Ok(data.clone()),
            None => Err(anyhow!("no matching documents found")),
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    fn purge(&self, key: &str) -> anyhow::Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// Callback Hook
//-----------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct CallbackHook {
    _clients: Arc<Mutex<HashMap<String, String>>>,
}

impl CallbackHook {
    fn new() -> Self {
        Self {
            _clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self)]
    fn callback(&self, _: &Payload) -> anyhow::Result<()> {
        Ok(())
    }
}
