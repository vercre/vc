//! # Example Provider
//! 
//! The `vercre-wallet::Endpoint` requires a provider that implments a number of traits to provide
//! capabilities and callbacks for the wallet's issuance and presentation flows. This module has a
//! sample provider that is useful for self-contained testing (no external services are required),
//! and as an example of how to implement the required traits.

mod wallet {
    use std::str;

    use base64ct::{Base64UrlUnpadded, Encoding};
    use ed25519_dalek::{Signature, Signer, SigningKey};
    pub const CLIENT_ID: &str = "96bfb9cb-0513-7d64-5532-bed74c48f9ab";
    
    //const ALG: &str = "EdDSA";
    const JWK_D: &str = "Y1KNbzOcX112pXI3v6sFvcr8uBLw4Pc2ciZTWdZx-As";
    const JWK_X: &str = "3Lg9yviAmTDCuVOyLXI3lq9S2pHm73yr3wwAkjwCAhw";
    
    // pub const HOLDER_DID: &str ="did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ";
    // pub const VERIFY_KEY_ID: &str = "publicKeyModel1Id";
    
    #[must_use]
    pub fn did() -> String {
        let jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "X25519",
            "use": "enc",
            "x": JWK_X,
        });
        let jwk_str = jwk.to_string();
        let jwk_b64 = Base64UrlUnpadded::encode_string(jwk_str.as_bytes());
    
        format!("did:jwk:{jwk_b64}")
    }
    
    #[must_use]
    pub fn kid() -> String {
        format!("{}#0", did())
    }
    
    // #[must_use]
    // pub fn alg() -> String {
    //     ALG.to_string()
    // }
    
    /// Sign the provided message.
    ///
    /// # Panics
    #[must_use]
    pub fn sign(msg: &[u8]) -> Vec<u8> {
        // let mut csprng = OsRng;
        // let signing_key: Ed25519SigningKey = Ed25519SigningKey::generate(&mut csprng);
        // signing_key.to_bytes().to_vec();
        // println!("d: {}", Base64UrlUnpadded::encode_string(&signing_key.to_bytes()));
        // println!("x: {}", Base64UrlUnpadded::encode_string(&signing_key.verifying_key().to_bytes()));
    
        let decoded = Base64UrlUnpadded::decode_vec(JWK_D).expect("should decode");
        let bytes: [u8; 32] = decoded.as_slice().try_into().expect("should convert ");
        let signing_key = SigningKey::from_bytes(&bytes);
        let sig: Signature = signing_key.sign(msg);
    
        sig.to_vec()
    }
}

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use vercre_core::vci::{
    CredentialRequest, CredentialResponse, MetadataRequest, MetadataResponse, TokenRequest,
    TokenResponse,
};
use vercre_core::vp::{RequestObjectRequest, RequestObjectResponse, ResponseRequest};

use crate::callback::Payload;
use crate::credential::{Credential, Logo};
use crate::issuance;
use crate::presentation;
use crate::provider::{
    Algorithm, Callback, Constraints, CredentialConfiguration, CredentialStorer, IssuanceInput,
    IssuanceListener, IssuerClient, PresentationInput, PresentationListener, Result, Signer,
    TxCode, VerifierClient,
};

/// Sample provider. Used internally for testing and as an example of how to implement the super
/// trait needed for the wallet endpoints.
#[derive(Default, Clone, Debug)]
pub struct Provider {
    callback: CallbackHook,
    credential_store: CredentialStore,
}

impl Provider {
    /// Constructor
    #[must_use]
    pub fn new() -> Self {
        Self {
            callback: CallbackHook::new(),
            credential_store: CredentialStore::new(),
        }
    }
}

impl Callback for Provider {
    async fn callback(&self, pl: &Payload) -> Result<()> {
        self.callback.callback(pl)
    }
}

impl CredentialStorer for Provider {
    async fn save(&self, credential: &Credential) -> Result<()> {
        self.credential_store.save(credential);
        Ok(())
    }

    async fn load(&self, id: &str) -> Result<Option<Credential>> {
        Ok(self.credential_store.load(id))
    }

    async fn find(&self, _filter: Option<Constraints>) -> Result<Vec<Credential>> {
        Ok(self.credential_store.get_all())
    }

    async fn remove(&self, id: &str) -> Result<()> {
        self.credential_store.remove(id)
    }
}

// TODO: provide a mechanism for returning a rejection to test that path through the flow
impl IssuanceInput for Provider {
    async fn accept(
        &self, _flow_id: &str, _config: &HashMap<String, CredentialConfiguration>,
    ) -> bool {
        true
    }

    async fn pin(&self, _flow_id: &str, tx_code: &TxCode) -> String {
        let len = Some(tx_code.length);
        len.map_or_else(
            || "1234".into(),
            |n| {
                let mut code = String::new();
                for i in 0..n.unwrap() {
                    code.push_str(&i.to_string());
                }
                code
            },
        )
    }
}

impl IssuanceListener for Provider {
    fn notify(&self, flow_id: &str, status: issuance::Status) {
        println!("{flow_id}: {status:?}");
    }
}

/// Here we use the example VCI provider and invoke the endpoint API directly, but in a real
/// implementation this would be an HTTP request (or other transport) to the issuance service.
impl IssuerClient for Provider {
    async fn get_metadata(
        &self, _flow_id: &str, req: &MetadataRequest,
    ) -> Result<MetadataResponse> {
        use providers::issuance::Provider as IssuanceProvider;
        let provider = IssuanceProvider::new();
        let response = vercre_vci::Endpoint::new(provider).metadata(req).await?;
        Ok(response)
    }

    async fn get_token(&self, _flow_id: &str, req: &TokenRequest) -> Result<TokenResponse> {
        use providers::issuance::Provider as IssuanceProvider;
        let provider = IssuanceProvider::new();
        let response = vercre_vci::Endpoint::new(provider).token(req).await?;
        Ok(response)
    }

    async fn get_credential(
        &self, _flow_id: &str, req: &CredentialRequest,
    ) -> Result<CredentialResponse> {
        use providers::issuance::Provider as IssuanceProvider;
        let provider = IssuanceProvider::new();
        let response = vercre_vci::Endpoint::new(provider).credential(req).await?;
        Ok(response)
    }

    async fn get_logo(&self, _flow_id: &str, _logo_url: &str) -> Result<Logo> {
        Ok(Logo::sample())
    }
}

// TODO: provide a mechanism for returning a rejection to test that path through the flow
impl PresentationInput for Provider {
    async fn authorize(&self, _flow_id: &str, _credentials: Vec<Credential>) -> bool {
        true
    }
}

impl PresentationListener for Provider {
    fn notify(&self, flow_id: &str, status: presentation::Status) {
        println!("{flow_id}: {status:?}");
    }
}

impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Algorithm::ES256K
    }

    fn verification_method(&self) -> String {
        wallet::kid()
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(wallet::sign(msg))
    }
}

/// Here we use the example VP provider and invoke the endpoint API directly, but in a real
/// implementation this would be an HTTP request (or other transport) to the presentation service.
#[allow(clippy::module_name_repetitions)]
impl VerifierClient for Provider {
    async fn get_request_object(
        &self, _flow_id: &str, req: &str,
    ) -> Result<RequestObjectResponse> {
        use providers::presentation::Provider as PresentationProvider;
        let provider = PresentationProvider::new();

        // Here we unpack the URI into a request object but a typical implementation would just
        // make a request directly to the URI.
        // The URI is of the form client_id/request/state_key
        let parts: Vec<&str> = req.split('/').collect();
        let state = parts[parts.len() - 1].to_string();
        let request = RequestObjectRequest {
            client_id: wallet::CLIENT_ID.to_string(),
            state,
        };

        let response = vercre_vp::Endpoint::new(provider).request_object(&request).await?;
        Ok(response)
    }

    async fn present(
        &self, _flow_id: &str, _uri: &str, presentation: &ResponseRequest,
    ) -> Result<()> {
        use providers::presentation::Provider as PresentationProvider;
        let provider = PresentationProvider::new();
        vercre_vp::Endpoint::new(provider).response(presentation).await?;
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// CredentialStore
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct CredentialStore {
    store: Arc<Mutex<HashMap<String, Credential>>>,
}

impl CredentialStore {
    fn new() -> Self {
        Self {
            store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn save(&self, credential: &Credential) {
        let key = credential.id.clone();
        self.store.lock().expect("should lock").insert(key, credential.clone());
    }

    fn load(&self, id: &str) -> Option<Credential> {
        self.store.lock().expect("should lock").get(id).cloned()
    }

    fn get_all(&self) -> Vec<Credential> {
        let store = self.store.lock().expect("should lock");
        store.values().cloned().collect()
    }

    fn remove(&self, id: &str) -> anyhow::Result<()> {
        self.store.lock().expect("should lock").remove(id).ok_or_else(|| anyhow!("not found"))?;
        Ok(())
    }
}

//-----------------------------------------------------------------------------
// Callback Hook
//-----------------------------------------------------------------------------

#[derive(Default, Clone, Debug)]
struct CallbackHook {
    _clients: Arc<Mutex<HashMap<String, String>>>,
}

impl CallbackHook {
    fn new() -> Self {
        Self {
            _clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[allow(clippy::unnecessary_wraps, clippy::unused_self, clippy::missing_const_for_fn)]
    fn callback(&self, _: &Payload) -> Result<()> {
        Ok(())
    }
}
