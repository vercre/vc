//! # Credential Offer Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created
//! Credential Offer.
//!
//! The Credential Offer is created by the Issuer when calling the `Create
//! Offer` endpoint to create an Credential Offer. Instead of sending the Offer
//! to the Wallet, the Issuer sends a response containing a
//! `credential_offer_uri` which can be used to retrieve the saved Credential
//! Offer.
//!
//! Per the [JWT VC Issuance Profile], the Credential Offer MUST be returned as
//! an encoded JWT.
//!
//! [JWT VC Issuance Profile]: (https://identity.foundation/jwt-vc-issuance-profile)

use tracing::instrument;

use crate::oid4vci::endpoint::Request;
use crate::oid4vci::provider::{Provider, StateStore};
use crate::oid4vci::state::{Stage, State};
use crate::oid4vci::types::{CredentialOfferRequest, CredentialOfferResponse};
use crate::oid4vci::{Error, Result};

/// Endpoint for the Wallet to request the Issuer's Credential Offer when
/// engaged in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn credential_offer(
    provider: impl Provider, request: CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    process(&provider, request).await
}

impl Request for CredentialOfferRequest {
    type Response = CredentialOfferResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        credential_offer(provider.clone(), self)
    }
}

async fn process(
    provider: &impl Provider, request: CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    tracing::debug!("credential_offer::process");

    // retrieve and then purge Credential Offer from state
    let state = StateStore::get::<State>(provider, &request.id)
        .await
        .map_err(|e| Error::ServerError(format!("issue fetching state: {e}")))?;
    StateStore::purge(provider, &request.id)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    if state.is_expired() {
        return Err(Error::InvalidRequest("state expired".into()));
    }

    let Stage::Pending(credential_offer) = state.stage.clone() else {
        return Err(Error::InvalidRequest("no credential offer found".into()));
    };

    // verify client_id (perhaps should use 'verify' method?)
    if credential_offer.credential_issuer != request.credential_issuer {
        return Err(Error::InvalidRequest("credential_issuer mismatch".into()));
    }

    Ok(CredentialOfferResponse { credential_offer })
}
