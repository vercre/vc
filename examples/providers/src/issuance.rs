use std::ops::Deref;

use chrono::{DateTime, Utc};
use vercre_issuer::provider::{
    Algorithm, Callback, Claims, Client, ClientMetadata, CredentialDefinition, Issuer,
    IssuerMetadata, Jwk, Payload, Result, Server, ServerMetadata, Signer, StateManager, Subject,
    Verifier,
};

use crate::logic::proof::{Enclave, Entity};

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";

const ISSUER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";

#[derive(Default, Clone, Debug)]
pub struct Provider(super::Provider);

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self(super::Provider::new())
    }
}

impl Deref for Provider {
    type Target = super::Provider;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
    async fn authorize(
        &self, holder_subject: &str, credential_configuration_id: &str,
    ) -> Result<bool> {
        self.subject.authorize(holder_subject, credential_configuration_id)
    }

    async fn claims(
        &self, holder_subject: &str, credential: &CredentialDefinition,
    ) -> Result<Claims> {
        Ok(self.subject.get_claims(holder_subject, credential))
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
        format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
    }

    async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        Enclave::try_sign(&Entity::Issuer, msg)
    }
}

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> Result<Jwk> {
        Enclave::deref_jwk(did_url)
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> Result<()> {
        self.callback.callback(pl)
    }
}
