//! Example of a provider implementation for the holder. Used internally for testing.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use openid4vc::issuance::{
    CredentialDefinition, CredentialRequest, CredentialResponse, Issuer, MetadataRequest,
    MetadataResponse, TokenRequest, TokenResponse,
};
use openid4vc::presentation::{RequestObjectRequest, RequestObjectResponse, ResponseRequest, ResponseResponse};
use openid4vc::{Client, Server};
use provider::{
    Algorithm, Callback, Claims, ClientMetadata, IssuerMetadata, Jwk, Payload, ServerMetadata,
    Signer, StateManager, Subject, Verifier,
};
use providers::issuance::{Provider as ExampleIssuanceProvider, CREDENTIAL_ISSUER};
use providers::wallet::Provider as ExampleWalletProvider;
use vercre_exch::Constraints;
use vercre_holder::callback::{CredentialStorer, IssuerClient, VerifierClient};
use vercre_holder::credential::{Credential, Logo};

#[derive(Default, Debug, Clone)]
pub struct TestProvider {
    pub issuance_provider: ExampleIssuanceProvider,
    pub wallet_provider: ExampleWalletProvider,
    cred_store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl TestProvider {
    pub fn new() -> Self {
        Self {
            issuance_provider: ExampleIssuanceProvider::new(),
            wallet_provider: ExampleWalletProvider::new(),
            cred_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Callback for TestProvider {
    async fn callback(&self, _payload: &Payload) -> anyhow::Result<()> {
        Ok(())
    }
}

impl IssuerClient for TestProvider {
    async fn get_metadata(
        &self, _flow_id: &str, _req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let md = IssuerMetadata::metadata(&self.issuance_provider, CREDENTIAL_ISSUER).await?;
        Ok(MetadataResponse {
            credential_issuer: md,
        })
    }

    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let endpoint = vercre_issuer::Endpoint::new(self.issuance_provider.clone());
        let response = endpoint.token(req).await?;
        Ok(response)
    }

    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> anyhow::Result<CredentialResponse> {
        let endpoint = vercre_issuer::Endpoint::new(self.issuance_provider.clone());
        let response = endpoint.credential(req).await?;
        Ok(response)
    }

    async fn get_logo(&self, _flow_id: &str, _logo_url: &str) -> anyhow::Result<Logo> {
        Ok(Logo::default())
    }
}

impl VerifierClient for TestProvider {
    async fn get_request_object(
        &self, _flow_id: &str, req: &str,
    ) -> anyhow::Result<RequestObjectResponse> {
        let parts = req.rsplitn(3, '/').collect::<Vec<&str>>();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("invalid request string"));
        }
        let request = RequestObjectRequest {
            client_id: parts[0].into(),
            state: parts[2].into(),
        };
        let endpoint = vercre_verifier::Endpoint::new(self.issuance_provider.clone());
        let response = endpoint.request_object(&request).await?;
        Ok(response)
    }

    async fn present(
        &self, _flow_id: &str, _uri: &str, presentation: &ResponseRequest,
    ) -> anyhow::Result<ResponseResponse> {
        let endpoint = vercre_verifier::Endpoint::new(self.issuance_provider.clone());
        let response = endpoint.response(&presentation).await?;
        Ok(response)
    }
}

impl StateManager for TestProvider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> anyhow::Result<()> {
        StateManager::put(&self.issuance_provider, key, state, dt).await
    }

    async fn get(&self, key: &str) -> anyhow::Result<Vec<u8>> {
        StateManager::get(&self.issuance_provider, key).await
    }

    async fn purge(&self, key: &str) -> anyhow::Result<()> {
        StateManager::purge(&self.issuance_provider, key).await
    }
}

impl ClientMetadata for TestProvider {
    async fn metadata(&self, client_id: &str) -> anyhow::Result<Client> {
        ClientMetadata::metadata(&self.issuance_provider, client_id).await
    }

    async fn register(&self, client_meta: &Client) -> anyhow::Result<Client> {
        ClientMetadata::register(&self.issuance_provider, client_meta).await
    }
}

impl IssuerMetadata for TestProvider {
    async fn metadata(&self, issuer_id: &str) -> anyhow::Result<Issuer> {
        IssuerMetadata::metadata(&self.issuance_provider, issuer_id).await
    }
}

impl ServerMetadata for TestProvider {
    async fn metadata(&self, issuer_id: &str) -> anyhow::Result<Server> {
        ServerMetadata::metadata(&self.issuance_provider, issuer_id).await
    }
}

impl Subject for TestProvider {
    async fn authorize(
        &self, holder_subject: &str, credential_configuration_id: &str,
    ) -> anyhow::Result<bool> {
        Subject::authorize(&self.issuance_provider, holder_subject, credential_configuration_id)
            .await
    }

    async fn claims(
        &self, holder_subject: &str, credential: &CredentialDefinition,
    ) -> anyhow::Result<Claims> {
        Subject::claims(&self.issuance_provider, holder_subject, credential).await
    }
}

impl Signer for TestProvider {
    fn algorithm(&self) -> Algorithm {
        Signer::algorithm(&self.wallet_provider)
    }

    fn verification_method(&self) -> String {
        Signer::verification_method(&self.wallet_provider)
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Signer::try_sign(&self.wallet_provider, msg).await
    }
}

impl Verifier for TestProvider {
    async fn deref_jwk(&self, did_url: &str) -> anyhow::Result<Jwk> {
        Verifier::deref_jwk(&self.wallet_provider, did_url).await
    }
}

impl CredentialStorer for TestProvider {
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        let data = credential.clone();
        let key = credential.id.clone();
        self.cred_store.lock().expect("should lock").insert(key.to_string(), data);
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

#[tokio::test]
async fn test_credential_storer() {
    let store = TestProvider::new();

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
