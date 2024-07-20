use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid::provider::Result;
use openid::issuer::{Claims, Client, Issuer, Server};
use serde::Deserialize;
use serde_json::{Map, Value};
use uuid::Uuid;

// pub const NORMAL_USER: &str = "normal_user";
// pub const PENDING_USER: &str = "pending_user";
// pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

#[derive(Default, Clone, Debug)]
pub struct IssuerStore {
    issuers: HashMap<String, Issuer>,
}

impl IssuerStore {
    pub fn new() -> Self {
        let json = include_bytes!("issuer.json");
        let issuer: Issuer = serde_json::from_slice(json).expect("should serialize");

        Self {
            issuers: HashMap::from([
                ("http://localhost:8080".to_string(), issuer.clone()),
                (issuer.credential_issuer.clone(), issuer),
            ]),
        }
    }

    pub fn get(&self, issuer_id: &str) -> Result<Issuer> {
        let Some(issuer) = self.issuers.get(issuer_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(issuer.clone())
    }
}

#[derive(Default, Clone, Debug)]
pub struct ServerStore {
    servers: HashMap<String, Server>,
}

impl ServerStore {
    pub fn new() -> Self {
        let json = include_bytes!("server.json");
        let server: Server = serde_json::from_slice(json).expect("should serialize");

        Self {
            servers: HashMap::from([
                ("http://localhost:8080".to_string(), server.clone()),
                (server.oauth.issuer.clone(), server),
            ]),
        }
    }

    pub fn get(&self, server_id: &str) -> Result<Server> {
        let Some(server) = self.servers.get(server_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(server.clone())
    }
}

#[derive(Default, Clone, Debug)]
pub struct ClientStore {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl ClientStore {
    pub fn new() -> Self {
        let json = include_bytes!("client.json");
        let client: Client = serde_json::from_slice(json).expect("should serialize");

        // Local verifier client for use when running end to end tests
        let mut local = client.clone();
        local.oauth.client_id = "http://localhost:8080".into();

        Self {
            clients: Arc::new(Mutex::new(HashMap::from([
                (client.oauth.client_id.clone(), client),
                (local.oauth.client_id.clone(), local),
            ]))),
        }
    }

    pub fn get(&self, client_id: &str) -> Result<Client> {
        let Some(client) = self.clients.lock().expect("should lock").get(client_id).cloned() else {
            return Err(anyhow!("client not found for client_id: {client_id}"));
        };
        Ok(client)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn add(&self, client: &Client) -> Result<Client> {
        let mut client = client.clone();
        client.oauth.client_id = Uuid::new_v4().to_string();

        self.clients
            .lock()
            .expect("should lock")
            .insert(client.oauth.client_id.to_string(), client.clone());

        Ok(client)
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
struct Credential {
    claims: Map<String, Value>,
    pending: bool,
}

#[derive(Default, Clone, Debug)]
pub struct SubjectStore {
    subjects: Arc<Mutex<HashMap<String, HashMap<String, Credential>>>>,
}

impl SubjectStore {
    pub fn new() -> Self {
        let json = include_bytes!("subject.json");
        let subjects: HashMap<String, HashMap<String, Credential>> =
            serde_json::from_slice(json).expect("should serialize");

        Self {
            subjects: Arc::new(Mutex::new(subjects)),
        }
    }

    pub fn authorize(&self, holder_subject: &str, _credential_identifier: &str) -> Result<bool> {
        if self.subjects.lock().expect("should lock").get(holder_subject).is_none() {
            return Err(anyhow!("no matching holder_subject"));
        };
        Ok(true)
    }

    pub fn claims(&self, holder_subject: &str, credential_identifier: &str) -> Result<Claims> {
        // get claims for the given `holder_subject` and `credential_identifier`
        let mut subject =
            self.subjects.lock().expect("should lock").get(holder_subject).unwrap().clone();
        let mut credential = subject.get(credential_identifier).unwrap().clone();

        // update subject's pending state to make Deferred Issuance work
        let pending = credential.pending;
        credential.pending = false;
        subject.insert(credential_identifier.to_string(), credential.clone());
        self.subjects.lock().expect("should lock").insert(holder_subject.to_string(), subject);

        Ok(Claims {
            claims: credential.claims,
            pending,
        })
    }
}
