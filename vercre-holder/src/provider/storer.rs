//! # Credential Storer
//!
//! Trait for the management of credential storage by the wallet client. Used by the wallet
//! endpoints.

use std::future::Future;

use vercre_exch::Constraints;

use crate::credential::Credential;
use crate::provider::Result;

/// `CredentialStorer` is used by wallet implementations to provide persistent storage of Verifiable
/// Credentials.
#[allow(clippy::module_name_repetitions)]
pub trait CredentialStorer: Send + Sync {
    /// Save a `Credential` to the store. Overwrite any existing credential with the same ID. Create
    /// a new credential if one with the same ID does not exist.
    fn save(&self, credential: &Credential) -> impl Future<Output = Result<()>> + Send;

    /// Retrieve a `Credential` from the store with the given ID. Return None if no credential with
    /// the ID exists.
    fn load(&self, id: &str) -> impl Future<Output = Result<Option<Credential>>> + Send;

    /// Find the credentials that match the the provided filter. If `filter` is None, return all
    /// credentials in the store.
    fn find(
        &self, filter: Option<Constraints>,
    ) -> impl Future<Output = Result<Vec<Credential>>> + Send;

    /// Remove the credential with the given ID from the store. Return an error if the credential
    /// does not exist.
    fn remove(&self, id: &str) -> impl Future<Output = Result<()>> + Send;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use super::*;

    struct TestCredentialStore {
        store: Store,
    }

    impl TestCredentialStore {
        fn new() -> Self {
            Self { store: Store::new() }
        }
    }

    impl CredentialStorer for TestCredentialStore {
        async fn save(&self, credential: &Credential) -> Result<()> {
            self.store.save(credential)?;
            Ok(())
        }

        async fn load(&self, id: &str) -> Result<Option<Credential>> {
            let cred = self.store.load(id)?;
            Ok(cred)
        }

        async fn find(&self, filter: Option<Constraints>) -> Result<Vec<Credential>> {
            let creds = self.store.find(filter)?;
            Ok(creds)
        }

        async fn remove(&self, id: &str) -> Result<()> {
            self.store.remove(id)?;
            Ok(())
        }
    }

    //-----------------------------------------------------------------------------
    // CredentialStorer
    //-----------------------------------------------------------------------------

    #[derive(Default, Clone, Debug)]
    struct Store {
        store: Arc<Mutex<HashMap<String, Credential>>>,
    }

    impl Store {
        fn new() -> Self {
            Self {
                store: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn save(&self, credential: &Credential) -> anyhow::Result<()> {
            let data = credential.clone();
            let key = credential.id.clone();
            self.store.lock().expect("should lock").insert(key.to_string(), data);
            Ok(())
        }

        fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
            Ok(self.store.lock().expect("should lock").get(id).cloned())
        }

        fn find(&self, _filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
            Ok(self.store.lock().expect("should lock").values().cloned().collect())
        }

        fn remove(&self, key: &str) -> anyhow::Result<()> {
            self.store.lock().expect("should lock").remove(key);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_credential_storer() {
        let store = TestCredentialStore::new();

        let credential = Credential {
            id: "test".to_string(),
            ..Default::default()
        };

        store.save(&credential).await.unwrap();

        let loaded = store.load("test").await.unwrap().unwrap();
        assert_eq!(loaded, credential);

        let all = store.find(None).await.unwrap();
        assert_eq!(all.len(), 1);

        store.remove("test").await.unwrap();

        let loaded = store.load("test").await.unwrap();
        assert!(loaded.is_none());
    }
}
