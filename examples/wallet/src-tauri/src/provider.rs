use vercre_holder::callback;
use vercre_holder::provider::Callback;

pub mod issuer_client;
pub mod store;

#[derive(Clone, Debug)]
pub struct Provider<R>
where
    R: tauri::Runtime,
{
    app_handle: tauri::AppHandle<R>,
}

impl<R> Provider<R>
where
    R: tauri::Runtime,
{
    /// Create a new credential store provider with a handle to the Tauri application.
    #[must_use]
    pub const fn new(app_handle: tauri::AppHandle<R>) -> Self {
        Self { app_handle }
    }
}

/// Provide a benign implementation of the `Callback` trait that is not needed for this example.
impl<R> Callback for Provider<R>
where
    R: tauri::Runtime,
{
    async fn callback(&self, _pl: &callback::Payload) -> anyhow::Result<()> {
        Ok(())
    }
}
