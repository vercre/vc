use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::verifier::{CredentialFormat, Verifier, VpFormat};
use openid::OAuthClient;
use uuid::Uuid;

#[derive(Default, Clone, Debug)]
pub struct Store {
    verifiers: Arc<Mutex<HashMap<String, Verifier>>>,
}

impl Store {
    pub fn new() -> Self {
        let verifier = Verifier {
            oauth: OAuthClient {
                client_id: "http://vercre.io".into(),
                client_name: Some("Verifier".into()),
                redirect_uris: Some(vec!["http://localhost:3000/callback".into()]),
                grant_types: None,
                response_types: Some(vec!["vp_token".into(), "id_token vp_token".into()]),
                ..OAuthClient::default()
            },
            vp_formats: Some(HashMap::from([
                (
                    CredentialFormat::JwtVcJson,
                    VpFormat {
                        alg: Some(vec!["ES256K".into()]),
                        proof_type: Some(vec!["JsonWebSignature2020".into()]),
                    },
                ),
                (
                    CredentialFormat::JwtVcJson,
                    VpFormat {
                        alg: Some(vec!["ES256K".into()]),
                        proof_type: Some(vec!["JsonWebSignature2020".into()]),
                    },
                ),
            ])),
        };

        // Local verifier client for use when running end to end tests

        Self {
            verifiers: Arc::new(Mutex::new(HashMap::from([(
                verifier.oauth.client_id.clone(),
                verifier,
            )]))),
        }
    }

    pub fn get(&self, client_id: &str) -> Result<Verifier> {
        let Some(client) = self.verifiers.lock().expect("should lock").get(client_id).cloned()
        else {
            return Err(anyhow!("client not found for client_id: {client_id}"));
        };
        Ok(client)
    }

    #[allow(clippy::unnecessary_wraps)]
    pub fn add(&self, verifier: &Verifier) -> Result<Verifier> {
        let mut verifier = verifier.clone();
        verifier.oauth.client_id = Uuid::new_v4().to_string();

        self.verifiers
            .lock()
            .expect("should lock")
            .insert(verifier.oauth.client_id.to_string(), verifier.clone());

        Ok(verifier)
    }
}
