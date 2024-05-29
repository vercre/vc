use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use chrono::{DateTime, Utc};

use crate::callback::Payload;
use crate::provider::{Algorithm, Callback, Result, Signer, StateManager};
use crate::test_common::wallet;

#[derive(Default, Clone, Debug)]
pub struct Provider {
    callback: CallbackHook,
    state_store: StateStore,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            callback: CallbackHook::new(),
            state_store: StateStore::new(),
        }
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
