use std::collections::HashMap;
use std::sync::Arc;

use futures::lock::Mutex;
use vercre_holder::provider::{Callback, Payload};

pub mod issuer_client;
pub mod signer;
pub mod state;
pub mod store;

#[derive(Clone, Debug)]
pub struct Provider {
    app_handle: tauri::AppHandle,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl Provider {
    /// Create a new capability provider.
    #[must_use]
    pub const fn new(app_handle: tauri::AppHandle, store: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Self {
        Self { app_handle, store }
    }
}

/// Provide a benign implementation of the `Callback` trait that is not needed for this example.
impl Callback for Provider {
    async fn callback(&self, _pl: &Payload) -> anyhow::Result<()> {
        Ok(())
    }
}
