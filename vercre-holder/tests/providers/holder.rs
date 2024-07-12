use std::collections::HashMap;
use std::str;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail};
use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
// TODO: remove this import
use dif_exch::Constraints;
use ecdsa::signature::Signer as _;
use test_utils::{issuer, verifier};
use vercre_holder::credential::{Credential, Logo};
use vercre_holder::issuance::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
use vercre_holder::presentation::{
    RequestObjectRequest, RequestObjectResponse, ResponseRequest, ResponseResponse,
};
use vercre_holder::provider::{
    Algorithm, CredentialStorer, IssuerClient, PublicKeyJwk, Result, Signer, StateManager,
    Verifier, VerifierClient,
};

const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";
const WALLET_JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";

// static ISSUER_PROVIDER: LazyLock<issuer::Provider> = LazyLock::new(issuer::Provider::new);
// static VERIFIER_PROVIDER: LazyLock<verifier::Provider> = LazyLock::new(verifier::Provider::new);

#[derive(Default, Clone, Debug)]
pub struct Provider {
    issuer: Option<issuer::Provider>,
    verifier: Option<verifier::Provider>,
    state_store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    cred_store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl Provider {
    #[must_use]
    pub fn new(issuer: Option<issuer::Provider>, verifier: Option<verifier::Provider>) -> Self {
        Self {
            issuer,
            verifier,
            state_store: Arc::new(Mutex::new(HashMap::new())),
            cred_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl IssuerClient for Provider {
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> anyhow::Result<MetadataResponse> {
        let endpoint = vercre_issuer::Endpoint::new(self.issuer.clone().unwrap());
        let response = endpoint.metadata(req).await?;
        Ok(response)
    }

    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> anyhow::Result<TokenResponse> {
        let endpoint = vercre_issuer::Endpoint::new(self.issuer.clone().unwrap());
        let response = endpoint.token(req).await?;
        Ok(response)
    }

    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> anyhow::Result<CredentialResponse> {
        let endpoint = vercre_issuer::Endpoint::new(self.issuer.clone().unwrap());
        let response = endpoint.credential(req).await?;
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
        let endpoint = vercre_verifier::Endpoint::new(self.verifier.clone().unwrap());
        Ok(endpoint.request_object(&request).await?)
    }

    async fn present(
        &self, _flow_id: &str, _uri: Option<&str>, req: &ResponseRequest,
    ) -> anyhow::Result<ResponseResponse> {
        let endpoint = vercre_verifier::Endpoint::new(self.verifier.clone().unwrap());
        Ok(endpoint.response(req).await?)
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
    async fn put(&self, key: &str, state: Vec<u8>, _: DateTime<Utc>) -> Result<()> {
        self.state_store.lock().expect("should lock").insert(key.to_string(), state);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let Some(state) = self.state_store.lock().expect("should lock").get(key).cloned() else {
            return Err(anyhow!("state not found for key: {key}"));
        };
        Ok(state)
    }

    async fn purge(&self, key: &str) -> Result<()> {
        self.state_store.lock().expect("should lock").remove(key);
        Ok(())
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

impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> anyhow::Result<PublicKeyJwk> {
        let did = did_url.split('#').next().ok_or_else(|| anyhow!("Unable to parse DID"))?;

        // if have long-form DID then try to extract key from metadata
        let did_parts = did.split(':').collect::<Vec<&str>>();

        // if DID is a JWK then return it
        if did.starts_with("did:jwk:") {
            let decoded = Base64UrlUnpadded::decode_vec(did_parts[2])
                .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
            return serde_json::from_slice::<PublicKeyJwk>(&decoded).map_err(anyhow::Error::from);
        }

        // HACK: for now, assume DID is long-form with delta operation containing public key
        // TODO: use vercre-did crate to dereference DID URL

        // DID should be long-form ION
        if did_parts.len() != 4 {
            bail!("Short-form DID's are not supported");
        }

        let decoded = Base64UrlUnpadded::decode_vec(did_parts[3])
            .map_err(|e| anyhow!("Unable to decode DID: {e}"))?;
        let ion_op = serde_json::from_slice::<serde_json::Value>(&decoded)?;

        let pk_val = ion_op
            .get("delta")
            .unwrap()
            .get("patches")
            .unwrap()
            .get(0)
            .unwrap()
            .get("document")
            .unwrap()
            .get("publicKeys")
            .unwrap()
            .get(0)
            .unwrap()
            .get("publicKeyJwk")
            .unwrap();

        serde_json::from_value(pk_val.clone()).map_err(anyhow::Error::from)
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
