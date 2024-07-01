use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use endpoint::Result;

#[derive(Default, Clone, Debug)]
pub struct Store {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Store {
    pub fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> Result<()> {
        self.store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    pub fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn purge(&self, key: &str) -> Result<()> {
        self.store.lock().expect("should lock").remove(key);
        Ok(())
    }
}
