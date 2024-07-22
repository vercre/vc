use std::collections::HashMap;
use std::str;
use std::sync::{Arc, Mutex};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
// TODO: remove this import
use dif_exch::Constraints;
use ecdsa::signature::Signer as _;
use test_utils::store::state;
use test_utils::{issuer, verifier};
use vercre_holder::provider::{
    Algorithm, CredentialStorer, HolderProvider, IssuerClient, PublicKeyJwk, Result, Signer,
    StateManager, Verifier, VerifierClient,
};
use vercre_holder::{
    Credential, CredentialRequest, CredentialResponse, Logo, MetadataRequest, MetadataResponse,
    RequestObjectRequest, RequestObjectResponse, ResponseRequest, ResponseResponse, TokenRequest,
    TokenResponse,
};

const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";
const WALLET_JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";

#[derive(Default, Clone, Debug)]
pub struct Provider {
    issuer: Option<issuer::Provider>,
    verifier: Option<verifier::Provider>,
    state: state::Store,
    cred_store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl Provider {
    #[must_use]
    pub fn new(issuer: Option<issuer::Provider>, verifier: Option<verifier::Provider>) -> Self {
        Self {
            issuer,
            verifier,
            state: state::Store::new(),
            cred_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl HolderProvider for Provider {}

impl IssuerClient for Provider {
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let response = vercre_issuer::metadata(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let response = vercre_issuer::token(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> anyhow::Result<CredentialResponse> {
        let response = vercre_issuer::credential(self.issuer.clone().unwrap(), req).await?;
        Ok(response)
    }

    async fn get_logo(&self, _flow_id: &str, _logo_url: &str) -> anyhow::Result<Logo> {
        Ok(Logo::default())
    }
}

impl VerifierClient for Provider {
    async fn get_request_object(
        &self, _flow_id: &str, req: &str,
    ) -> anyhow::Result<RequestObjectResponse> {
        let parts = req.rsplitn(3, '/').collect::<Vec<&str>>();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("invalid request string"));
        }
        let request = RequestObjectRequest {
            client_id: parts[2].into(),
            state: parts[0].into(),
        };
        Ok(vercre_verifier::request_object(self.verifier.clone().unwrap(), &request).await?)
    }

    async fn present(
        &self, _flow_id: &str, _uri: Option<&str>, req: &ResponseRequest,
    ) -> anyhow::Result<ResponseResponse> {
        Ok(vercre_verifier::response(self.verifier.clone().unwrap(), req).await?)
    }
}

impl CredentialStorer for Provider {
    async fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        self.cred_store
            .lock()
            .expect("should lock")
            .insert(credential.clone().id, credential.clone());
        Ok(())
    }

    async fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        Ok(self.cred_store.lock().expect("should lock").get(id).cloned())
    }

    async fn find(&self, filter: Option<Constraints>) -> anyhow::Result<Vec<Credential>> {
        let creds = self.cred_store.lock().expect("should lock").values().cloned().collect();
        if filter.is_none() {
            return Ok(creds);
        }
        let mut matched: Vec<Credential> = vec![];
        let constraints = filter.expect("constraints exist");
        for cred in creds {
            match constraints.satisfied(&cred.vc) {
                Ok(true) => matched.push(cred.clone()),
                Ok(false) => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(matched)
    }

    async fn remove(&self, id: &str) -> anyhow::Result<()> {
        self.cred_store.lock().expect("should lock").remove(id);
        Ok(())
    }
}

impl StateManager for Provider {
    async fn put(&self, key: &str, state: Vec<u8>, dt: DateTime<Utc>) -> Result<()> {
        self.state.put(key, state, dt)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        self.state.get(key)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state.purge(key)
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EdDSA
    }

    fn verification_method(&self) -> String {
        format!("{}#0", holder_did())
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = Base64UrlUnpadded::decode_vec(WALLET_JWK_D)?;
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&bytes);
        let signature: ed25519_dalek::Signature = signing_key.sign(msg);
        Ok(signature.to_vec())
    }
}

use test_utils::store::proof::Keystore;

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> anyhow::Result<PublicKeyJwk> {
        Keystore::deref_jwk(did_url).await
    }
}

#[must_use]
pub fn holder_did() -> String {
    let jwk = serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "x": JWK_X,
    });
    let jwk_str = jwk.to_string();
    let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());

    format!("did:jwk:{jwk_b64}")
}
