#![allow(missing_docs)]
mod issuer_client;
mod store;
mod verifier_client;

use std::collections::HashMap;
use std::str;
use std::sync::Arc;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use futures::lock::Mutex;
use vercre_holder::provider::{
    Algorithm, HolderProvider, PublicKeyJwk, Result, Signer, StateManager, Verifier,
};
use vercre_test_utils::store::keystore::{self, HolderKeystore};

#[derive(Clone, Debug)]
pub struct Provider {
    app_handle: tauri::AppHandle,
    state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Provider {
    #[must_use]
    pub fn new(
        app_handle: &tauri::AppHandle, state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ) -> Self {
        Self {
            app_handle: app_handle.clone(),
            state_store,
        }
    }
}

impl HolderProvider for Provider {}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> Result<()> {
        self.state_store.lock().await.insert(key.to_string(), state);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.state_store.lock().await.get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state_store.lock().await.remove(key);
        Ok(())
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        HolderKeystore::algorithm()
    }

    fn verification_method(&self) -> String {
        HolderKeystore::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        HolderKeystore::try_sign(msg)
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> anyhow::Result<PublicKeyJwk> {
        keystore::deref_jwk(did_url).await
    }
}
