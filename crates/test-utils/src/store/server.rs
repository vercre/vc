use std::collections::HashMap;

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::issuer::{GrantType, Server};
use openid::OAuthServer;

#[derive(Default, Clone, Debug)]
pub struct Store {
    servers: HashMap<String, Server>,
}

impl Store {
    pub fn new() -> Self {
        let server = Server {
            oauth: OAuthServer {
                issuer: "http://vercre.io".into(),
                authorization_endpoint: "/auth".into(),
                token_endpoint: "/token".into(),
                scopes_supported: Some(vec!["openid".into()]),
                response_types_supported: vec!["code".into()],
                response_modes_supported: Some(vec!["query".into()]),
                grant_types_supported: Some(vec![
                    GrantType::AuthorizationCode,
                    GrantType::PreAuthorizedCode,
                ]),
                code_challenge_methods_supported: Some(vec!["S256".into()]),
                jwks_uri: None,
                registration_endpoint: None,
                token_endpoint_auth_methods_supported: None,
                token_endpoint_auth_signing_alg_values_supported: None,
                service_documentation: None,
                ui_locales_supported: None,
                op_policy_uri: None,
                op_tos_uri: None,
                revocation_endpoint: None,
                revocation_endpoint_auth_methods_supported: None,
                revocation_endpoint_auth_signing_alg_values_supported: None,
                introspection_endpoint: None,
                introspection_endpoint_auth_methods_supported: None,
                introspection_endpoint_auth_signing_alg_values_supported: None,
                signed_metadata: None,
            },
            pre_authorized_grant_anonymous_access_supported: true,
        };
        Self {
            servers: HashMap::from([
                ("http://localhost:8080".into(), server.clone()),
                (server.oauth.issuer.clone(), server),
            ]),
        }
    }

    pub fn get(&self, server_id: &str) -> Result<Server> {
        let Some(server) = self.servers.get(server_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(server.clone())
    }
}
