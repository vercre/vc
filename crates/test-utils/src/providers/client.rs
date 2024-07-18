use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::issuer::GrantType;
use openid::verifier::VpFormat;
use openid::{Client, CredentialFormat};
use uuid::Uuid;

pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";

#[derive(Default, Clone, Debug)]
pub struct Store {
    clients: Arc<Mutex<HashMap<String, Client>>>,
}

impl Store {
    pub fn new() -> Self {
        let wallet = Client {
            client_id: CLIENT_ID.into(),
            client_name: Some("Wallet".into()),
            redirect_uris: Some(vec!["http://localhost:3000/callback".into()]),
            grant_types: Some(vec![GrantType::AuthorizationCode, GrantType::PreAuthorizedCode]),
            response_types: Some(vec!["code".into()]),
            scope: Some("openid credential".into()),
            credential_offer_endpoint: Some("openid-credential-offer://".into()),
            ..Client::default()
        };
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
        let mut local = wallet.clone();
        local.client_id = "http://localhost:8080".into();

        Self {
            clients: Arc::new(Mutex::new(HashMap::from([
                (wallet.client_id.clone(), wallet),
                (verifier.client_id.clone(), verifier),
                (local.client_id.clone(), local),
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
    pub fn add(&self, client_meta: &Client) -> Result<Client> {
        let client_meta = Client {
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
