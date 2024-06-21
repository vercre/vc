use std::collections::HashMap;
use std::sync::Arc;

use futures::lock::Mutex;
use providers::wallet::Provider as ExampleWalletProvider;
use vercre_holder::provider::{Algorithm, Jwk, Signer, Verifier};

pub mod issuer_client;
pub mod state;
pub mod store;
pub mod verifier_client;

#[derive(Clone, Debug)]
#[allow(clippy::struct_field_names)]
pub struct Provider {
    app_handle: tauri::AppHandle,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    wallet_provider: ExampleWalletProvider,
}

impl Provider {
    /// Create a new capability provider.
    #[must_use]
    pub fn new(app_handle: tauri::AppHandle, store: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Self {
        Self {
            app_handle,
            store,
            wallet_provider: ExampleWalletProvider::new(),
        }
    }
}

/// Hardcoded implementation of the `Signer` trait. **Do not use in production**
impl Signer for Provider {
    fn algorithm(&self) -> Algorithm {
        Signer::algorithm(&self.wallet_provider)
    }

    fn verification_method(&self) -> String {
        Signer::verification_method(&self.wallet_provider)
    }

    async fn try_sign(&self, msg: &[u8]) -> anyhow::Result<Vec<u8>> {
        Signer::try_sign(&self.wallet_provider, msg).await
    }
}

/// Hardcoded implementation of the `Verifier` trait. **Do not use in production**
impl Verifier for Provider {
    async fn deref_jwk(&self, did_url: &str) -> anyhow::Result<Jwk> {
        Verifier::deref_jwk(&self.wallet_provider, did_url).await
    }
}
