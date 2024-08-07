#![allow(missing_docs)]

use std::collections::HashMap;
use std::str;
use std::sync::{Arc, LazyLock};

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use futures::lock::Mutex;
// TODO: remove this import
use vercre_dif_exch::Constraints;
use vercre_holder::provider::{
    Algorithm, CredentialStorer, HolderProvider, IssuerClient, PublicKeyJwk, Result, Signer,
    StateManager, Verifier, VerifierClient,
};
use vercre_holder::{
    Credential, CredentialRequest, CredentialResponse, Logo, MetadataRequest, MetadataResponse,
    RequestObjectRequest, RequestObjectResponse, ResponseRequest, ResponseResponse, TokenRequest,
    TokenResponse,
};
use vercre_test_utils::store::keystore::{self, HolderKeystore};
use vercre_test_utils::{issuer, verifier};

static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
static VERIFIER_PROVIDER: LazyLock<verifier::Provider> = LazyLock::new(verifier::Provider::new);

#[derive(Clone, Debug)]
pub struct Provider {
    state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    cred_store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl Provider {
    #[must_use]
    pub fn new(_: &tauri::AppHandle, state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Self {
        Self {
            state_store,
            cred_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl HolderProvider for Provider {}

impl IssuerClient for Provider {
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let response = vercre_issuer::metadata(ISSUER_PROVIDER.clone(), req).await?;
        Ok(response)
    }

    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let response = vercre_issuer::token(ISSUER_PROVIDER.clone(), req).await?;
        Ok(response)
    }

    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> anyhow::Result<CredentialResponse> {
        let response = vercre_issuer::credential(ISSUER_PROVIDER.clone(), req).await?;
        Ok(response)
    }

    async fn get_logo(&self, _flow_id: &str, _logo_url: &str) -> anyhow::Result<Logo> {
        Ok(Logo::default())
    }
}

impl VerifierClient for Provider {
    async fn get_request_object(
        &self, _flow_id: &str, req: &str,
    ) -> anyhow::Result<RequestObjectResponse> {
        let parts = req.rsplitn(3, '/').collect::<Vec<&str>>();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("invalid request string"));
        }
        let request = RequestObjectRequest {
            client_id: parts[2].into(),
            state: parts[0].into(),
        };
        Ok(vercre_verifier::request_object(VERIFIER_PROVIDER.clone(), &request).await?)
    }

    async fn present(
        &self, _flow_id: &str, _uri: Option<&str>, req: &ResponseRequest,
    ) -> anyhow::Result<ResponseResponse> {
        Ok(vercre_verifier::response(VERIFIER_PROVIDER.clone(), req).await?)
    }
}

impl CredentialStorer for Provider {
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        self.cred_store.lock().await.insert(credential.clone().id, credential.clone());
        Ok(())
    }

    async fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        Ok(self.cred_store.lock().await.get(id).cloned())
    }

    async fn find(&self, filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
        let creds = self.cred_store.lock().await.values().cloned().collect();
        if filter.is_none() {
            return Ok(creds);
        }
        let mut matched: Vec<Credential> = vec![];
        let constraints = filter.expect("constraints exist");
        for cred in creds {
            match constraints.satisfied(&cred.vc) {
                Ok(true) => matched.push(cred.clone()),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(matched)
    }

    async fn remove(&self, id: &str) -> anyhow::Result<()> {
        self.cred_store.lock().await.remove(id);
        Ok(())
    }
}

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
