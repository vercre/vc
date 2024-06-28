use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid4vc::issuance::CredentialDefinition;
use provider::{Claims, Result};
use serde_json::Value;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

#[derive(Default, Clone, Debug)]
struct Person {
    given_name: &'static str,
    family_name: &'static str,
    email: &'static str,
    proficiency: &'static str,
    pending: bool,
}

#[derive(Default, Clone, Debug)]
pub struct Store {
    subjects: Arc<Mutex<HashMap<String, Person>>>,
}

impl Store {
    pub fn new() -> Self {
        // issuer
        let subjects = HashMap::from([
            (
                NORMAL_USER.into(),
                Person {
                    given_name: "Normal",
                    family_name: "Person",
                    email: "normal.user@example.com",
                    proficiency: "3",
                    pending: false,
                },
            ),
            (
                PENDING_USER.into(),
                Person {
                    given_name: "Pending",
                    family_name: "Person",
                    email: "pending.user@example.com",
                    proficiency: "1",
                    pending: true,
                },
            ),
        ]);

        Self {
            subjects: Arc::new(Mutex::new(subjects)),
        }
    }

    pub fn authorize(
        &self, holder_subject: &str, _credential_configuration_id: &str,
    ) -> Result<bool> {
        if self.subjects.lock().expect("should lock").get(holder_subject).is_none() {
            return Err(anyhow!("no matching holder_subject"));
        };
        Ok(true)
    }

    pub fn get_claims(
        &self, holder_subject: &str, credential: &CredentialDefinition,
    ) -> Result<Claims> {
        // get holder subject while allowing mutex to go out of scope and release
        // lock so we can take another lock for insert further down
        let subject =
            self.subjects.lock().expect("should lock").get(holder_subject).unwrap().clone();

        // populate requested claims for subject
        let mut claims = HashMap::new();

        if let Some(subj) = &credential.credential_subject {
            for k in subj.keys() {
                let v = match k.as_str() {
                    "givenName" => subject.given_name,
                    "familyName" => subject.family_name,
                    "email" => subject.email,
                    "proficiency" => subject.proficiency,
                    _ => continue,
                };

                claims.insert(k.to_string(), Value::from(v));
            }
        };

        // update subject's pending state to make Deferred Issuance work
        let mut updated = subject.clone();
        updated.pending = false;
        self.subjects.lock().expect("should lock").insert(holder_subject.to_string(), updated);

        Ok(Claims {
            claims,
            pending: subject.pending,
        })
    }
}
