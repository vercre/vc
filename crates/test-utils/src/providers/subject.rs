use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid4vc::endpoint::{Claims, Result};
use openid4vc::issuance::ClaimDefinition;
use serde_json::Value;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

type ClaimSet = HashMap<String, Value>;

#[derive(Default, Clone, Debug)]
pub struct Store {
    subjects: Arc<Mutex<HashMap<String, ClaimSet>>>,
}

impl Store {
    pub fn new() -> Self {
        // issuer
        let subjects = HashMap::from([
            (
                NORMAL_USER.into(),
                HashMap::from([
                    ("givenName".to_string(), Value::from("Normal")),
                    ("familyName".to_string(), Value::from("Person")),
                    ("email".to_string(), Value::from("normal.user@example.com")),
                    ("proficiency".to_string(), Value::from("3")),
                    ("pending".to_string(), Value::from(false)),
                ]),
            ),
            (
                PENDING_USER.into(),
                HashMap::from([
                    ("givenName".to_string(), Value::from("Pending")),
                    ("familyName".to_string(), Value::from("Person")),
                    ("email".to_string(), Value::from("pending.user@example.com")),
                    ("proficiency".to_string(), Value::from("1")),
                    ("pending".to_string(), Value::from(true)),
                ]),
            ),
        ]);

        Self {
            subjects: Arc::new(Mutex::new(subjects)),
        }
    }

    pub fn authorize(&self, holder_subject: &str, _credential_identifier: &str) -> Result<bool> {
        if self.subjects.lock().expect("should lock").get(holder_subject).is_none() {
            return Err(anyhow!("no matching holder_subject"));
        };
        Ok(true)
    }

    pub fn claims(
        &self, holder_subject: &str, _credential_identifier: &str,
        credential_subject: Option<HashMap<String, ClaimDefinition>>,
    ) -> Result<Claims> {
        // get holder subject while allowing mutex to go out of scope and release
        // lock so we can take another lock for insert further down
        let subject =
            self.subjects.lock().expect("should lock").get(holder_subject).unwrap().clone();

        // populate requested claims for subject
        let mut claims = HashMap::new();
        if let Some(subj) = &credential_subject {
            for claim_name in subj.keys() {
                if let Some(v) = subject.get(claim_name) {
                    claims.insert(claim_name.to_string(), v.clone());
                }
            }
        };

        // update subject's pending state to make Deferred Issuance work
        let mut updated = subject.clone();
        updated.insert("pending".to_string(), Value::from(false));
        self.subjects.lock().expect("should lock").insert(holder_subject.to_string(), updated);

        // return populated claims
        let pending = subject.get("pending").unwrap().as_bool().unwrap();
        Ok(Claims { claims, pending })
    }
}
