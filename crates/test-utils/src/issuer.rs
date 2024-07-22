use chrono::{DateTime, Utc};
use openid::issuer::{
    Claims, Client, ClientMetadata, Issuer, IssuerMetadata, Result, Server, ServerMetadata,
    StateManager, Subject,
};
use proof::jose::jwk::PublicKeyJwk;
use proof::signature::{Algorithm, Signer, Verifier};

use crate::store::proof::Keystore;
use crate::store::{issuance, state};

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

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

impl openid::issuer::Provider for Provider {}

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
        Keystore::algorithm()
    }

    fn verification_method(&self) -> String {
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

// impl Signature for Provider {
//     fn algorithm(&self) -> Algorithm {
//         Keystore::algorithm()
//     }

//     fn verification_method(&self) -> String {
//         Keystore::verification_method()
//     }

//     async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
//         Keystore::try_sign(msg)
//     }

//     async fn try_verify(&self, msg: &[u8]) -> Result<PublicKeyJwk> {
//         Keystore::try_sign(msg)
//     }
// }
