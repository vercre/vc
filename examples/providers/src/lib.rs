#![allow(missing_docs)]

mod callback;
mod client;
pub mod issuance;
mod issuer;
pub mod presentation;
mod proof;
mod server;
mod state;
mod subject;
pub mod wallet;

pub const NORMAL_USER: &str = "normal_user";
pub const PENDING_USER: &str = "pending_user";

pub const CREDENTIAL_ISSUER: &str = "http://vercre.io";
pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    client: client::Store,
    issuer: issuer::Store,
    server: server::Store,
    subject: subject::Store,
    state: state::Store,
    callback: callback::Hook,
}

impl Provider {
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: client::Store::new(),
            issuer: issuer::Store::new(),
            server: server::Store::new(),
            subject: subject::Store::new(),
            state: state::Store::new(),
            callback: callback::Hook::new(),
        }
    }
}

// impl ClientMetadata for Provider {
//     async fn metadata(&self, client_id: &str) -> Result<Client> {
//         self.client.get(client_id)
//     }

//     async fn register(&self, client_meta: &Client) -> Result<Client> {
//         self.client.add(client_meta)
//     }
// }

// impl IssuerMetadata for Provider {
//     async fn metadata(&self, issuer_id: &str) -> Result<Issuer> {
//         self.issuer.get(issuer_id)
//     }
// }

// impl ServerMetadata for Provider {
//     async fn metadata(&self, server_id: &str) -> Result<Server> {
//         self.server.get(server_id)
//     }
// }

// impl Subject for Provider {
//     /// Authorize issuance of the specified credential for the holder.
//     async fn authorize(
//         &self, holder_subject: &str, credential_configuration_id: &str,
//     ) -> Result<bool> {
//         self.subject.authorize(holder_subject, credential_configuration_id)
//     }

//     async fn claims(
//         &self, holder_subject: &str, credential: &CredentialDefinition,
//     ) -> Result<Claims> {
//         Ok(self.subject.get_claims(holder_subject, credential))
//     }
// }

// impl StateManager for Provider {
//     async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> Result<()> {
//         self.state.put(key, state, dt)
//     }

//     async fn get(&self, key: &str) -> Result<Vec<u8>> {
//         self.state.get(key)
//     }

//     async fn purge(&self, key: &str) -> Result<()> {
//         self.state.purge(key)
//     }
// }

// impl Signer for Provider {
//     fn algorithm(&self) -> Algorithm {
//         Algorithm::ES256K
//     }

//     fn verification_method(&self) -> String {
//         format!("{ISSUER_DID}#{VERIFY_KEY_ID}")
//     }

//     async fn try_sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
//         let decoded = Base64UrlUnpadded::decode_vec(JWK_D)?;
//         let signing_key: SigningKey<Secp256k1> = SigningKey::from_slice(&decoded)?;
//         let sig: Signature<Secp256k1> = signing_key.sign(msg);
//         Ok(sig.to_vec())
//     }
// }

// impl Verifier for Provider {
//     fn deref_jwk(&self, did_url: impl AsRef<str>) -> anyhow::Result<Jwk> {
//         let did =
//             did_url.as_ref().split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

//         // if have long-form DID then try to extract key from metadata
//         let did_parts = did.split(':').collect::<Vec<&str>>();

//         // if DID is a JWK then return it
//         if did.starts_with("did:jwk:") {
//             let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
//                 .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
//             return serde_json::from_slice::<Jwk>(&decoded).map_err(anyhow::Error::from);
//         }

//         // DID should be long-form ION
//         if did_parts.len() != 4 {
//             bail!("Short-form DID's are not supported");
//         }

//         let decoded = Base64UrlUnpadded::decode_vec(did_parts[3])
//             .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
//         let ion_op = serde_json::from_slice::<serde_json::Value>(&decoded)?;

//         let pk_val = ion_op
//             .get("delta")
//             .unwrap()
//             .get("patches")
//             .unwrap()
//             .get(0)
//             .unwrap()
//             .get("document")
//             .unwrap()
//             .get("publicKeys")
//             .unwrap()
//             .get(0)
//             .unwrap()
//             .get("publicKeyJwk")
//             .unwrap();

//         Ok(serde_json::from_value(pk_val.clone())?)
//     }
// }

// impl Callback for Provider {
//     async fn callback(&self, pl: &Payload) -> Result<()> {
//         self.callback.callback(pl)
//     }
// }
