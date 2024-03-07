use serde::Serialize;
use thiserror::Error;

// TODO: improve error handling

/// Error codes
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Tauri(#[from] tauri::Error),

    #[error(transparent)]
    Http(#[from] tauri_plugin_http::reqwest::Error),

    #[error("HTTP configuration error")]
    HttpConfig(String),

    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

// manually implement serde::Serialize
impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(self.to_string().as_ref())
    }
}
