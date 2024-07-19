use std::collections::HashMap;

use anyhow::anyhow;
use openid::endpoint::Result;
use openid::issuer::Issuer;

#[derive(Default, Clone, Debug)]
pub struct Store {
    issuers: HashMap<String, Issuer>,
}

impl Store {
    pub fn new() -> Self {
        let issuer = crate::sample::sample_issuer();

        Self {
            issuers: HashMap::from([
                ("http://localhost:8080".to_string(), issuer.clone()),
                (issuer.credential_issuer.clone(), issuer),
            ]),
        }
    }

    pub fn get(&self, issuer_id: &str) -> Result<Issuer> {
        let Some(issuer) = self.issuers.get(issuer_id) else {
            return Err(anyhow!("issuer not found"));
        };
        Ok(issuer.clone())
    }
}
