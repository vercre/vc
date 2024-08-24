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
use serde::de::DeserializeOwned;
use serde::Serialize;
use vercre_holder::provider::{
    Algorithm, DidResolver, Document, HolderProvider, Result, Signer, StateStore,
};
use vercre_test_utils::store::keystore::HolderKeystore;
use vercre_test_utils::store::resolver;

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

impl StateStore for Provider {
    async fn put(&self, key: &str, state: impl Serialize, _: DateTime<Utc>) -> Result<()> {
        let state = serde_json::to_vec(&state)?;
        self.state_store.lock().await.insert(key.to_string(), state);
        Ok(())
    }

    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        let Some(state) = self.state_store.lock().await.get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(serde_json::from_slice(&state)?)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state_store.lock().await.remove(key);
        Ok(())
    }
}

impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
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
