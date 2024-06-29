use std::collections::HashMap;

use anyhow::anyhow;
use openid4vc::issuance::Issuer;
use provider::Result;

#[derive(Default, Clone, Debug)]
pub struct Store {
    issuers: HashMap<String, Issuer>,
}

impl Store {
    pub fn new() -> Self {
        let issuer = Issuer::sample();

        Self {
            issuers: HashMap::from([
                ("http://localhost:8080".into(), issuer.clone()),
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
