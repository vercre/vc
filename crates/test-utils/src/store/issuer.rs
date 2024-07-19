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
        const ISSUER_URI: &str = "http://vercre.io";

        let issuer_json = serde_json::json!({
            "credential_issuer": ISSUER_URI,
            "credential_endpoint": format!("{ISSUER_URI}/credential"),
            "batch_credential_endpoint": format!("{ISSUER_URI}/batch"),
            "deferred_credential_endpoint": format!("{ISSUER_URI}/deferred"),
            "display": {
                "name": "Vercre",
                "locale": "en-NZ"
            },
            "credential_configurations_supported": {
                "EmployeeID_JWT": {
                    "format": "jwt_vc_json",
                    "scope": "EmployeeIDCredential",
                    "cryptographic_binding_methods_supported": ["did:jwk", "did:ion"],
                    "credential_signing_alg_values_supported": ["ES256K", "EdDSA"],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
                        }
                    },
                    "display": [{
                        "name": "Employee ID",
                        "description": "Vercre employee ID credential",
                        "locale": "en-NZ",
                        "logo":  {
                            "uri": "https://vercre.github.io/assets/employee.png",
                            "alt_text": "Vercre Logo",
                        },
                        "text_color": "#ffffff",
                        "background_color": "#323ed2",
                        "background_image": {
                            "uri": "https://vercre.github.io/assets/vercre-background.png",
                            "alt_text": "Vercre Background",
                        },
                    }],
                    "credential_definition": {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://www.w3.org/2018/credentials/examples/v1",
                        ],
                        "type": [
                            "VerifiableCredential",
                            "EmployeeIDCredential"
                        ],
                        "credentialSubject": {
                            "email": {
                                "mandatory": true,
                                "value_type":  "string",
                                "display": [{
                                    "name": "Email",
                                    "locale": "en-NZ",
                                }],
                            },
                            "familyName": {
                                "mandatory": true,
                                "value_type":  "string",
                                "display": [{
                                    "name": "Family name",
                                    "locale": "en-NZ",
                                }],
                            },
                            "givenName": {
                                "mandatory": true,
                                "value_type": "string",
                                "display": [{
                                    "name": "Given name",
                                    "locale": "en-NZ",
                                }],
                            }
                        }
                    }
                },
                "Developer_JWT": {
                    "format": "jwt_vc_json",
                    "scope": "DeveloperCredential",
                    "cryptographic_binding_methods_supported": ["did:jwk", "did:ion"],
                    "credential_signing_alg_values_supported": ["ES256K", "EdDSA"],
                    "proof_types_supported": {
                        "jwt": {
                            "proof_signing_alg_values_supported": ["ES256K", "EdDSA"]
                        }
                    },
                    "display": [{
                        "name": "Developer",
                        "description": "Vercre certified developer credential",
                        "locale": "en-NZ",
                        "logo":  {
                            "uri": "https://vercre.github.io/assets/developer.png",
                            "alt_text": "Vercre Logo",
                        },
                        "text_color": "#ffffff",
                        "background_color": "#010100",
                        "background_image": {
                            "uri": "https://vercre.github.io/assets/vercre-background.png",
                            "alt_text": "Vercre Background",
                        },
                    }],
                    "credential_definition":  {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://www.w3.org/2018/credentials/examples/v1",
                        ],
                        "type": [
                            "VerifiableCredential",
                            "DeveloperCredential"
                        ],
                        "credentialSubject": {
                            "proficiency": {
                                "mandatory": true,
                                "value_type":  "number",
                                "display": [{
                                    "name": "Proficiency",
                                    "locale": "en-NZ",
                                }],
                            },
                            "familyName": {
                                "mandatory": true,
                                "value_type":  "string",
                                "display": [{
                                    "name": "Family name",
                                    "locale": "en-NZ",
                                }],
                            },
                            "givenName": {
                                "mandatory": true,
                                "value_type": "string",
                                "display": [{
                                    "name": "Given name",
                                    "locale": "en-NZ",
                                }],
                            }
                        }
                    }
                }
            }
        });

        let issuer: Issuer = serde_json::from_value(issuer_json).expect("should serialize");

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
