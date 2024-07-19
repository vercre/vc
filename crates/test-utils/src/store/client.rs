use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::issuer::{Client, GrantType, OAuthClient};
use uuid::Uuid;

pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

#[derive(Default, Clone, Debug)]
pub struct Store {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl Store {
    pub fn new() -> Self {
        let client = Client {
            oauth: OAuthClient {
                client_id: CLIENT_ID.into(),
                client_name: Some("Wallet".into()),
                redirect_uris: Some(vec!["http://localhost:3000/callback".into()]),
                grant_types: Some(vec![GrantType::AuthorizationCode, GrantType::PreAuthorizedCode]),
                response_types: Some(vec!["code".into()]),
                scope: Some("openid credential".into()),
                ..OAuthClient::default()
            },
            credential_offer_endpoint: Some("openid-credential-offer://".into()),
        };

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
