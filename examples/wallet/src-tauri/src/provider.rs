use std::collections::HashMap;
use std::sync::Arc;

use futures::lock::Mutex;
use vercre_holder::provider::{Callback, Payload};

pub mod issuer_client;
pub mod signer;
pub mod state;
pub mod store;

#[derive(Clone, Debug)]
pub struct Provider<R>
where
    R: tauri::Runtime,
{
    app_handle: tauri::AppHandle<R>,
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl<R> Provider<R>
where
    R: tauri::Runtime,
{
    /// Create a new credential store provider with a handle to the Tauri application.
    #[must_use]
    pub fn new(
        app_handle: tauri::AppHandle<R>, store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    ) -> Self {
        Self { app_handle, store }
    }
}

/// Provide a benign implementation of the `Callback` trait that is not needed for this example.
impl<R> Callback for Provider<R>
where
    R: tauri::Runtime,
{
    async fn callback(&self, _pl: &Payload) -> anyhow::Result<()> {
        Ok(())
    }
}
