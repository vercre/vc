//! # Dynamic Client Registration Endpoint

use tracing::instrument;

use super::state::State;
use crate::openid::issuer::{Provider, RegistrationRequest, RegistrationResponse};
use crate::openid::provider::StateStore;
use crate::openid::{Error, Result};

/// Registration request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn register(
    provider: impl Provider, request: RegistrationRequest,
) -> Result<RegistrationResponse> {
    verify(&provider, &request).await?;
    process(&provider, request).await
}

async fn verify(provider: &impl Provider, request: &RegistrationRequest) -> Result<()> {
    tracing::debug!("register::verify");

    // verify state is still accessible (has not expired)
    match StateStore::get::<State>(provider, &request.access_token).await {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::ServerError(format!("State not found: {e}"))),
    }
}

async fn process(
    provider: &impl Provider, request: RegistrationRequest,
) -> Result<RegistrationResponse> {
    tracing::debug!("register::process");

    let Ok(client_meta) = provider.register(&request.client_metadata).await else {
        return Err(Error::ServerError("Registration failed".into()));
    };

    Ok(RegistrationResponse {
        client_metadata: client_meta,
    })
}
