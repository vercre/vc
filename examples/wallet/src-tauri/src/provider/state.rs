use anyhow::anyhow;
use chrono::{DateTime, Utc};
use vercre_holder::provider::StateManager;

use crate::provider::Provider;

impl<R> StateManager for Provider<R>
where
    R: tauri::Runtime,
{
    async fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> anyhow::Result<()> {
        self.store.lock().await.insert(key.to_string(), state);
        Ok(())
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        println!("looking for stored state for key {key}");
        let Some(state) = self.store.lock().await.get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        println!("returning stored state for key {key}");
        Ok(state)
    }

    async fn purge(&self, key: &str) -> anyhow::Result<()> {
        self.store.lock().await.remove(key);
        Ok(())
    }
}
