use std::path::PathBuf;

use tauri_plugin_store::StoreExt;
use vercre_holder::credential::Credential;
use vercre_holder::provider::CredentialStorer;
use vercre_holder::Constraints;

use super::Provider;

const STORE: &str = "store.json";

/// Provider implementation
impl CredentialStorer for Provider {
    /// Save a `Credential` to the store. Overwrite any existing credential with
    /// the same ID. Create a new credential if one with the same ID does
    /// not exist.
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        let store = self.app_handle.store(PathBuf::from(STORE))?;
        let id = credential.id.clone();
        let val = serde_json::to_value(credential)?;
        log::debug!("saving credential: {id}: {val}");
        store.set(id, val);
        Ok(store.save()?)
    }

    /// Retrieve a `Credential` from the store with the given ID. Return None if
    /// no credential with the ID exists.
    async fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        let store = self.app_handle.store(PathBuf::from(STORE))?;
        match store.get(id) {
            Some(v) => Ok(Some(serde_json::from_value(v)?)),
            None => Ok(None),
        }
    }

    /// Find the credentials that match the the provided filter. If `filter` is
    /// None, return all credentials in the store.
    async fn find(&self, filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
        let store = self.app_handle.store(PathBuf::from(STORE))?;
        let list = store
            .values()
            .iter()
            .map(|v| serde_json::from_value(v.clone()).ok().unwrap())
            .collect::<Vec<Credential>>();

        let Some(constraints) = filter else {
            return Ok(list);
        };

        let filtered = list
            .iter()
            .filter(|cred| constraints.satisfied(&cred.vc).unwrap_or(false))
            .cloned()
            .collect::<Vec<Credential>>();

        Ok(filtered)
    }

    /// Remove the credential with the given ID from the store. Return an error
    /// if the credential does not exist.
    async fn remove(&self, id: &str) -> anyhow::Result<()> {
        let store = self.app_handle.store(PathBuf::from(STORE))?;
        if !store.delete(id) {
            anyhow::bail!("credential with ID {id} does not exist");
        }
        Ok(store.save()?)
    }
}
