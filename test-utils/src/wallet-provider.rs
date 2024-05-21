pub mod wallet {
    use std::str;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signature, Signer, SigningKey};
    // pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

    const ALG: &str = "EdDSA";
    const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
    const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";

    // pub const HOLDER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
    // pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";

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
    pub fn alg() -> String {
        ALG.to_string()
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
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use vercre_wallet::callback::Payload;
use vercre_wallet::provider::{Algorithm, Callback, Client, Result, Signer, StateManager, Storer};
use vercre_wallet::GrantType;
use vercre_wallet::types;

#[derive(Default, Clone, Debug)]
pub struct Provider {
    callback: CallbackHook,
    client: ClientStore,
    state_store: StateStore,
    store: Store,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            callback: CallbackHook::new(),
            client: ClientStore::new(),
            state_store: StateStore::new(),
            store: Store::new(),
        }
    }
}

impl Client for Provider {
    async fn metadata(&self, client_id: &str) -> Result<types::Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client_meta: &types::Client) -> Result<types::Client> {
        self.client.add(client_meta)
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> Result<()> {
        self.callback.callback(pl)
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        wallet::kid()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Ok(wallet::sign(msg))
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> Result<()> {
        self.state_store.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.state_store.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state_store.purge(key)
    }

    async fn get_opt(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.state_store.get_opt(key)
    }
}

impl Storer for Provider {
    async fn save(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.store.save(key, data)
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        self.store.load(key)
    }

    async fn list(&self) -> Result<Vec<String>> {
        self.store.list()
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.store.remove(key)
    }
}

//-----------------------------------------------------------------------------
// ClientStore
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct ClientStore {
    clients: Arc<Mutex<HashMap<String, types::Client>>>,
}

impl ClientStore {
    fn new() -> Self {
        let client_id = wallet::did();

        let client = types::Client {
            client_id: client_id.clone(),
            redirect_uris: Some(vec![String::from("http://localhost:3000/callback")]),
            grant_types: Some(vec![GrantType::AuthorizationCode, GrantType::PreAuthorizedCode]),
            response_types: Some(vec![String::from("code")]),
            scope: Some(String::from("openid credential")),
            credential_offer_endpoint: Some(String::from("openid-credential-offer://")),

            ..Default::default()
        };

        Self {
            clients: Arc::new(Mutex::new(HashMap::from([(client_id, client)]))),
        }
    }

    fn get(&self, client_id: &str) -> Result<types::Client> {
        let Some(client) = self.clients.lock().expect("should lock").get(client_id).cloned() else {
            return Err(anyhow!("client not found for client_id: {client_id}"));
        };
        Ok(client)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn add(&self, client_meta: &types::Client) -> Result<types::Client> {
        let client_meta = types::Client {
            client_id: Uuid::new_v4().to_string(),
            ..client_meta.to_owned()
        };

        self.clients
            .lock()
            .expect("should lock")
            .insert(client_meta.client_id.to_string(), client_meta.clone());

        Ok(client_meta)
    }
}

//-----------------------------------------------------------------------------
// StateStore
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
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
    fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> Result<()> {
        self.store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    // fn put_opt(&self, key: &str, state: Vec<u8>, _: Option<DateTime<Utc>>) -> Result<()> {
    //     self.store.lock().expect("should lock").insert(key.to_string(), state);
    //     Ok(())
    // }

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    fn get_opt(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.store.lock().expect("should lock").get(key).cloned())
    }

    #[allow(clippy::unnecessary_wraps)]
    fn purge(&self, key: &str) -> Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// Storer
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct Store {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Store {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn save(&self, key: &str, data: Vec<u8>) -> Result<()> {
        self.store.lock().expect("should lock").insert(key.to_string(), data);
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.store.lock().expect("should lock").get(key).cloned())
    }

    fn list(&self) -> Result<Vec<String>> {
        Ok(self.store.lock().expect("should lock").keys().cloned().collect())
    }

    fn remove(&self, key: &str) -> Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// Callback Hook
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct CallbackHook {
    _clients: Arc<Mutex<HashMap<String, String>>>,
}

impl CallbackHook {
    fn new() -> Self {
        Self {
            _clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self, clippy::missing_const_for_fn)]
    fn callback(&self, _: &Payload) -> Result<()> {
        Ok(())
    }
}
