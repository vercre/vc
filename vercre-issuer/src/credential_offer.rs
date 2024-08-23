//! # Credential Offer Endpoint
//!
//! This endpoint is used by the Wallet to retrieve a previously created
//! Credential Offer.
//!
//! The Credential Offer is created by the Issuer when calling the `Create Offer`
//! endpoint to create an Credential Offer. Instead of sending the Offer to the Wallet,
//! the Issuer sends a response containing a `credential_offer_uri` which can be used
//! to retrieve the saved Credential Offer.
//!
//! Per the [JWT VC Issuance Profile], the Credential Offer MUST be returned as an
//! encoded JWT.
//!
//! [JWT VC Issuance Profile]: (https://identity.foundation/jwt-vc-issuance-profile)

use tracing::instrument;
use vercre_openid::issuer::{
    CredentialOfferRequest, CredentialOfferResponse, Provider, StateStore,
};
use vercre_openid::{Error, Result};

use crate::state::State;

/// Endpoint for the Wallet to request the Issuer's Credential Offer when engaged
/// in a cross-device flow.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn credential_offer(
    provider: impl Provider, request: &CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    process(provider, request).await
}

async fn process(
    provider: impl Provider, request: &CredentialOfferRequest,
) -> Result<CredentialOfferResponse> {
    tracing::debug!("credential_offer::process");

    // retrieve Credential Offer from state
    let buf = StateStore::get(&provider, &request.id)
        .await
        .map_err(|e| Error::ServerError(format!("issue fetching state: {e}")))?;
    let state = State::try_from(buf)
        .map_err(|e| Error::ServerError(format!("issue deserializing state: {e}")))?;

    let Some(credential_offer) = state.credential_offer else {
        return Err(Error::InvalidRequest("no credential offer found".into()));
    };

    // verify client_id (perhaps should use 'verify' method?)
    if credential_offer.credential_issuer != request.credential_issuer {
        return Err(Error::InvalidRequest("credential_issuer mismatch".into()));
    }

    Ok(CredentialOfferResponse { credential_offer })
}

#[cfg(test)]
mod tests {
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_openid::issuer::{CreateOfferRequest, OfferType, SendType};
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};

    use super::*;

    #[tokio::test]
    async fn request_jwt() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();
        let create_req = CreateOfferRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            credential_configuration_ids: vec!["EmployeeID_JWT".to_string()],
            subject_id: Some(NORMAL_USER.to_string()),
            pre_authorize: false,
            tx_code_required: true,
            send_type: SendType::ByRef,
        };
        let create_resp =
            crate::create_offer(provider.clone(), &create_req).await.expect("should create offer");

        let OfferType::Uri(uri) = create_resp.offer_type else {
            panic!("no URI found in response");
        };
        let Some(id) = uri.strip_prefix(&format!("{CREDENTIAL_ISSUER}/credential_offer/")) else {
            panic!("should have prefix");
        };

        let offer_req = CredentialOfferRequest {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            id: id.to_string(),
        };
        let offer_resp =
            credential_offer(provider.clone(), &offer_req).await.expect("response is valid");

        assert_snapshot!("offer", offer_resp,  {
            ".credential_offer.grants.authorization_code.issuer_state" => "[issuer_state]",
        });
    }
}