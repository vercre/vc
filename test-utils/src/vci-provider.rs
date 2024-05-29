use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use ecdsa::signature::Signer as _;
use ecdsa::{Signature, SigningKey};
use k256::Secp256k1;
use serde_json::Value;
use uuid::Uuid;
use vercre_vci::callback::Payload;
use vercre_vci::metadata::types::{self, CredentialDefinition};
use vercre_vci::provider::{
    Algorithm, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager,
};
use vercre_vci::{holder, GrantType};

use crate::wallet;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

pub const ISSUER: &str = "http://vercre.io";
pub const ISSUER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
const JWK_D: &str = "0Md3MhPaKEpnKAyKE498EdDFerD5NLeKJ5Rb-vC16Gs";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    client: ClientStore,
    issuer: IssuerStore,
    server: ServerStore,
    holder: HolderStore,
    state_store: StateStore,
    callback: CallbackHook,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: ClientStore::new(),
            issuer: IssuerStore::new(),
            server: ServerStore::new(),
            holder: HolderStore::new(),
            state_store: StateStore::new(),
            callback: CallbackHook::new(),
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

impl Issuer for Provider {
    async fn metadata(&self, issuer_id: &str) -> Result<types::Issuer> {
        self.issuer.get(issuer_id)
    }
}

impl Server for Provider {
    async fn metadata(&self, server_id: &str) -> Result<types::Server> {
        self.server.get(server_id)
    }
}

impl Holder for Provider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(&self, holder_id: &str, credential_configuration_id: &str) -> Result<bool> {
        self.holder.authorize(holder_id, credential_configuration_id)
    }

    async fn claims(
        &self, holder_id: &str, credential: &CredentialDefinition,
    ) -> Result<holder::Claims> {
        Ok(self.holder.get_claims(holder_id, credential))
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
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
        let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
        let sig: Signature<Secp256k1> = signing_key.sign(msg);
        Ok(sig.to_vec())
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> Result<()> {
        self.callback.callback(pl)
    }
}

//-----------------------------------------------------------------------------
// Client
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
// Holder
//-----------------------------------------------------------------------------
#[derive(Default, Clone, Debug)]
struct Person {
    given_name: &'static str,
    family_name: &'static str,
    email: &'static str,
    proficiency: &'static str,
    pending: bool,
}

#[derive(Default, Clone, Debug)]
struct HolderStore {
    holders: Arc<Mutex<HashMap<String, Person>>>,
}

impl HolderStore {
    fn new() -> Self {
        // issuer
        let holders = HashMap::from([
            (
                NORMAL_USER.to_string(),
                Person {
                    given_name: "Normal",
                    family_name: "Person",
                    email: "normal.user@example.com",
                    proficiency: "3",
                    pending: false,
                },
            ),
            (
                PENDING_USER.to_string(),
                Person {
                    given_name: "Pending",
                    family_name: "Person",
                    email: "pending.user@example.com",
                    proficiency: "1",
                    pending: true,
                },
            ),
        ]);

        Self {
            holders: Arc::new(Mutex::new(holders)),
        }
    }

    fn authorize(&self, holder_id: &str, _credential_configuration_id: &str) -> Result<bool> {
        if self.holders.lock().expect("should lock").get(holder_id).is_none() {
            return Err(anyhow!("no matching holder_id"));
        };
        Ok(true)
    }

    fn get_claims(&self, holder_id: &str, credential: &CredentialDefinition) -> holder::Claims {
        // get holder while allowing mutex to go out of scope and release
        // lock so we can take another lock for insert further down
        let holder = self.holders.lock().expect("should lock").get(holder_id).unwrap().clone();

        // populate requested claims for holder
        let mut claims = HashMap::new();

        if let Some(subj) = &credential.credential_subject {
            for k in subj.keys() {
                let v = match k.as_str() {
                    "givenName" => holder.given_name,
                    "familyName" => holder.family_name,
                    "email" => holder.email,
                    "proficiency" => holder.proficiency,
                    _ => continue,
                };

                claims.insert(k.to_string(), Value::from(v));
            }
        };

        // update holder's pending state to make Deferred Issuance work
        let mut updated = holder.clone();
        updated.pending = false;
        self.holders.lock().expect("should lock").insert(holder_id.to_string(), updated);

        holder::Claims {
            claims,
            pending: holder.pending,
        }
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

    fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    #[allow(clippy::unnecessary_wraps)]
    fn purge(&self, key: &str) -> Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// Issuer
//-----------------------------------------------------------------------------
#[derive(Default, Clone, Debug)]
struct IssuerStore {
    issuers: HashMap<String, types::Issuer>,
}

impl IssuerStore {
    fn new() -> Self {
        let issuer = types::Issuer::sample();

        Self {
            issuers: HashMap::from([
                (String::from("http://localhost:8080"), issuer.clone()),
                (issuer.credential_issuer.clone(), issuer),
            ]),
        }
    }

    fn get(&self, issuer_id: &str) -> Result<types::Issuer> {
        let Some(issuer) = self.issuers.get(issuer_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(issuer.clone())
    }
}

#[derive(Default, Clone, Debug)]
struct ServerStore {
    servers: HashMap<String, types::Server>,
}

impl ServerStore {
    fn new() -> Self {
        let server = types::Server::sample();
        Self {
            servers: HashMap::from([
                (String::from("http://localhost:8080"), server.clone()),
                (server.issuer.clone(), server),
            ]),
        }
    }

    fn get(&self, server_id: &str) -> Result<types::Server> {
        let Some(server) = self.servers.get(server_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(server.clone())
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
