//! Provider implementation for tests

use std::collections::HashMap;
use std::str;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::Serialize;
// TODO: remove this import
use vercre_dif_exch::Constraints;
use vercre_holder::provider::{
    Algorithm, CredentialStorer, DidResolver, Document, HolderProvider, Issuer, Result, Signer,
    StateStore, Verifier,
};
use vercre_holder::{
    AuthorizationRequest, AuthorizationResponse, Credential, CredentialRequest, CredentialResponse,
    DeferredCredentialRequest, DeferredCredentialResponse, Logo, MetadataRequest, MetadataResponse,
    OAuthServerRequest, OAuthServerResponse, RequestObjectRequest, RequestObjectResponse,
    ResponseRequest, ResponseResponse, TokenRequest, TokenResponse,
};
use vercre_issuer::{NotificationRequest, NotificationResponse};
use test_utils::store::keystore::HolderKeystore;
use test_utils::store::{resolver, state};
use test_utils::{issuer, verifier};

#[derive(Default, Clone, Debug)]
#[allow(missing_docs)]
pub struct Provider {
    issuer: Option<issuer::Provider>,
    verifier: Option<verifier::Provider>,
    state: state::Store,
    cred_store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl Provider {
    #[must_use]
    #[allow(missing_docs)]
    pub fn new(issuer: Option<issuer::Provider>, verifier: Option<verifier::Provider>) -> Self {
        Self {
            issuer,
            verifier,
            state: state::Store::new(),
            cred_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl HolderProvider for Provider {}

impl Issuer for Provider {
    async fn metadata(&self, req: MetadataRequest) -> anyhow::Result<MetadataResponse> {
        let response = vercre_issuer::metadata(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn oauth_server(&self, req: OAuthServerRequest) -> anyhow::Result<OAuthServerResponse> {
        let response = vercre_issuer::oauth_server(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn authorization(
        &self, req: AuthorizationRequest,
    ) -> anyhow::Result<AuthorizationResponse> {
        let response = vercre_issuer::authorize(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn token(&self, req: TokenRequest) -> anyhow::Result<TokenResponse> {
        let response = vercre_issuer::token(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn credential(&self, req: CredentialRequest) -> anyhow::Result<CredentialResponse> {
        let response = vercre_issuer::credential(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn deferred(
        &self, req: DeferredCredentialRequest,
    ) -> anyhow::Result<DeferredCredentialResponse> {
        let response = vercre_issuer::deferred(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn logo(&self, _logo_url: &str) -> anyhow::Result<Logo> {
        Ok(Logo::default())
    }

    async fn notification(
        &self, _req: NotificationRequest,
    ) -> anyhow::Result<NotificationResponse> {
        Ok(NotificationResponse::default())
    }
}

impl Verifier for Provider {
    async fn request_object(&self, req: &str) -> anyhow::Result<RequestObjectResponse> {
        let parts = req.rsplitn(3, '/').collect::<Vec<&str>>();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("invalid request string"));
        }
        let request = RequestObjectRequest {
            client_id: parts[2].into(),
            id: parts[0].into(),
        };
        Ok(vercre_verifier::request_object(self.verifier.clone().unwrap(), &request).await?)
    }

    async fn present(
        &self, _uri: Option<&str>, req: &ResponseRequest,
    ) -> anyhow::Result<ResponseResponse> {
        Ok(vercre_verifier::response(self.verifier.clone().unwrap(), req).await?)
    }
}

impl CredentialStorer for Provider {
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        self.cred_store
            .lock()
            .expect("should lock")
            .insert(credential.clone().id, credential.clone());
        Ok(())
    }

    async fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        Ok(self.cred_store.lock().expect("should lock").get(id).cloned())
    }

    async fn find(&self, filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
        let creds = self.cred_store.lock().expect("should lock").values().cloned().collect();
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
        self.cred_store.lock().expect("should lock").remove(id);
        Ok(())
    }
}

impl StateStore for Provider {
    async fn put(&self, key: &str, state: impl Serialize, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get<T: DeserializeOwned>(&self, key: &str) -> Result<T> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl DidResolver for Provider {
    async fn resolve(&self, url: &str) -> anyhow::Result<Document> {
        resolver::resolve_did(url).await
    }
}

impl Signer for Provider {
    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        HolderKeystore::try_sign(msg)
    }

    async fn public_key(&self) -> Result<Vec<u8>> {
        HolderKeystore::public_key()
    }

    fn algorithm(&self) -> Algorithm {
        HolderKeystore::algorithm()
    }

    fn verification_method(&self) -> String {
        HolderKeystore::verification_method()
    }
}
