use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use openid4vc::endpoint::{Claims, Result};
use serde_json::Value;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

type ClaimSet = HashMap<String, Value>;

#[derive(Default, Clone, Debug)]
struct Credential {
    claims: ClaimSet,
    pending: bool,
}

#[derive(Default, Clone, Debug)]
pub struct Store {
    subjects: Arc<Mutex<HashMap<String, HashMap<String, Credential>>>>,
}

impl Store {
    pub fn new() -> Self {
        let subjects = HashMap::from([
            (
                NORMAL_USER.into(),
                HashMap::from([(
                    "EmployeeID_JWT".into(),
                    Credential {
                        claims: HashMap::from([
                            ("givenName".to_string(), Value::from("Normal")),
                            ("familyName".to_string(), Value::from("Person")),
                            ("email".to_string(), Value::from("normal.user@example.com")),
                            ("proficiency".to_string(), Value::from("3")),
                        ]),
                        pending: false,
                    },
                )]),
            ),
            (
                PENDING_USER.into(),
                HashMap::from([(
                    "EmployeeID_JWT".into(),
                    Credential {
                        claims: HashMap::from([
                            ("givenName".to_string(), Value::from("Pending")),
                            ("familyName".to_string(), Value::from("Person")),
                            ("email".to_string(), Value::from("pending.user@example.com")),
                            ("proficiency".to_string(), Value::from("1")),
                        ]),
                        pending: true,
                    },
                )]),
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

    pub fn claims(&self, holder_subject: &str, credential_identifier: &str) -> Result<Claims> {
        // get claims for the given `holder_subject` and `credential_identifier`
        let mut subject =
            self.subjects.lock().expect("should lock").get(holder_subject).unwrap().clone();
        let mut credential = subject.get(credential_identifier).unwrap().clone();

        // update subject's pending state to make Deferred Issuance work
        let pending = credential.pending;
        credential.pending = false;
        subject.insert(credential_identifier.to_string(), credential.clone());
        self.subjects.lock().expect("should lock").insert(holder_subject.to_string(), subject);

        Ok(Claims {
            claims: credential.claims,
            pending,
        })
    }
}
