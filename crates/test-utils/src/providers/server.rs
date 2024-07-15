use std::collections::HashMap;

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::Server;

#[derive(Default, Clone, Debug)]
pub struct Store {
    servers: HashMap<String, Server>,
}

impl Store {
    pub fn new() -> Self {
        let server = Server::sample();
        Self {
            servers: HashMap::from([
                ("http://localhost:8080".into(), server.clone()),
                (server.issuer.clone(), server),
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
