use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use uuid::Uuid;
use vercre_openid::provider::Result;
use vercre_openid::verifier::Verifier;

#[derive(Default, Clone, Debug)]
pub struct Store {
    verifiers: Arc<Mutex<HashMap<String, Verifier>>>,
}

impl Store {
    pub fn new() -> Self {
        let json = include_bytes!("verifier.json");
        let verifier: Verifier = serde_json::from_slice(json).expect("should serialize");

        Self {
            verifiers: Arc::new(Mutex::new(HashMap::from([(
                verifier.oauth.client_id.clone(),
                verifier,
            )]))),
        }
    }

    pub fn get(&self, client_id: &str) -> Result<Verifier> {
        let Some(client) = self.verifiers.lock().expect("should lock").get(client_id).cloned()
        else {
            return Err(anyhow!("client not found for client_id: {client_id}"));
        };
        Ok(client)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn add(&self, verifier: &Verifier) -> Result<Verifier> {
        let mut verifier = verifier.clone();
        verifier.oauth.client_id = Uuid::new_v4().to_string();

        self.verifiers
            .lock()
            .expect("should lock")
            .insert(verifier.oauth.client_id.to_string(), verifier.clone());

        Ok(verifier)
    }
}
