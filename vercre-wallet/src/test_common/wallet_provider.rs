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
use crate::test_common::wallet;

#[derive(Default, Clone, Debug)]
pub struct Provider {
    callback: CallbackHook,
    credential_store: CredentialStore,
}

impl Provider {
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
        self.credential_store.save(credential)
    }

    async fn load(&self, id: &str) -> Result<Option<Credential>> {
        self.credential_store.load(id)
    }

    async fn find(&self, _filter: Option<Constraints>) -> Result<Vec<Credential>> {
        self.credential_store.get_all()
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
        if let Some(len) = tx_code.length {
            let mut code = String::new();
            for i in 0..len {
                code.push_str(&i.to_string());
            }
            code
        } else {
            "1234".to_string()
        }
    }
}

impl IssuanceListener for Provider {
    fn notify(&self, flow_id: &str, status: issuance::Status) {
        println!("{}: {:?}", flow_id, status);
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
        println!("{}: {:?}", flow_id, status);
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

    fn save(&self, credential: &Credential) -> anyhow::Result<()> {
        let key = credential.id.clone();
        self.store.lock().expect("should lock").insert(key.to_string(), credential.clone());
        Ok(())
    }

    fn load(&self, id: &str) -> anyhow::Result<Option<Credential>> {
        Ok(self.store.lock().expect("should lock").get(id).cloned())
    }

    fn get_all(&self) -> anyhow::Result<Vec<Credential>> {
        let store = self.store.lock().expect("should lock");
        Ok(store.values().cloned().collect())
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
