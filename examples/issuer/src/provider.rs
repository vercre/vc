use chrono::{DateTime, Utc};
use test_utils::store::proof::Keystore;
use test_utils::store::{issuance, state};
use vercre_issuer::provider::{
    Algorithm, Claims, Client, ClientMetadata, Issuer, IssuerMetadata, PublicKeyJwk, Result,
    Server, ServerMetadata, Signer, StateManager, Subject, Verifier,
};

#[derive(Default, Clone, Debug)]
pub struct Provider {
    pub client: issuance::ClientStore,
    pub issuer: issuance::IssuerStore,
    pub server: issuance::ServerStore,
    pub subject: issuance::SubjectStore,
    pub state: state::Store,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: issuance::ClientStore::new(),
            issuer: issuance::IssuerStore::new(),
            server: issuance::ServerStore::new(),
            subject: issuance::SubjectStore::new(),
            state: state::Store::new(),
        }
    }
}

impl vercre_issuer::provider::Provider for Provider {}

impl ClientMetadata for Provider {
    async fn metadata(&self, client_id: &str) -> Result<Client> {
        self.client.get(client_id)
    }

    async fn register(&self, client: &Client) -> Result<Client> {
        self.client.add(client)
    }
}

impl IssuerMetadata for Provider {
    async fn metadata(&self, issuer_id: &str) -> Result<Issuer> {
        self.issuer.get(issuer_id)
    }
}

impl ServerMetadata for Provider {
    async fn metadata(&self, server_id: &str) -> Result<Server> {
        self.server.get(server_id)
    }
}

impl Subject for Provider {
    /// Authorize issuance of the specified credential for the holder.
    async fn authorize(&self, holder_subject: &str, credential_identifier: &str) -> Result<bool> {
        self.subject.authorize(holder_subject, credential_identifier)
    }

    async fn claims(&self, holder_subject: &str, credential_identifier: &str) -> Result<Claims> {
        self.subject.claims(holder_subject, credential_identifier)
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        //format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
        Keystore::verification_method()
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Keystore::try_sign(msg)
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<PublicKeyJwk> {
        Keystore::deref_jwk(did_url).await
    }
}
