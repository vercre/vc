//! # Dynamic Client Registration Endpoint

use tracing::instrument;

use crate::oid4vci::endpoint::Request;
use crate::oid4vci::provider::Provider;
use crate::oid4vci::state::State;
use crate::oid4vci::types::{RegistrationRequest, RegistrationResponse};
use crate::oid4vci::{Error, Result};
use crate::openid::provider::StateStore;

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

impl Request for RegistrationRequest {
    type Response = RegistrationResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        register(provider.clone(), self)
    }
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
