#![allow(missing_docs)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use credibil_vc::openid::provider::Result;
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Default, Clone, Debug)]
pub struct Store {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Store {
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn put(&self, key: &str, state: impl Serialize, _: DateTime<Utc>) -> Result<()> {
        let state = serde_json::to_vec(&state)?;
        self.store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        let Some(state) = self.store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(serde_json::from_slice(&state)?)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn purge(&self, key: &str) -> Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}
