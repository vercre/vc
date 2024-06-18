//! Example of a provider implementation for the holder. Used internally for testing.

use chrono::{DateTime, Utc};
use openid4vc::issuance::{
    CredentialDefinition, CredentialRequest, CredentialResponse, Issuer, MetadataRequest,
    MetadataResponse, TokenRequest, TokenResponse,
};
use openid4vc::{Client, Server};
use provider::{
    Algorithm, Callback, Claims, ClientMetadata, IssuerMetadata, Payload, ServerMetadata, Signer,
    StateManager, Subject,
};
use providers::issuance::{Provider as ExampleIssuanceProvider, CREDENTIAL_ISSUER};
use providers::wallet::Provider as ExampleWalletProvider;
use vercre_holder::callback::IssuerClient;
use vercre_holder::credential::Logo;

#[derive(Default, Debug, Clone)]
pub struct TestProvider {
    pub issuance_provider: ExampleIssuanceProvider,
    pub wallet_provider: ExampleWalletProvider,
}

impl TestProvider {
    pub fn new() -> Self {
        Self {
            issuance_provider: ExampleIssuanceProvider::new(),
            wallet_provider: ExampleWalletProvider::new(),
        }
    }
}

impl Callback for TestProvider {
    async fn callback(&self, _payload: &Payload) -> anyhow::Result<()> {
        println!("Callback from TestProvider");
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
