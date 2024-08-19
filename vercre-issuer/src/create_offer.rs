//! # Invoke Endpoint
//!
//! The Invoke endpoint is used to initiate Pre-authorized credential issuance flow.
//! Credential Issuers can use this endpoint to generate a Credential Offer which can
//! be used to initiate issuance with a Wallet.
//!
//! When a Credential Issuer is already interacting with a user and wishes to initate a
//! Credential issuance, they can 'send' the user's Wallet a Credential Offer.
//!
//! The diagram illustrates this Credential Issuer initiated flow:
//!
//! ```text
//! +--------------+   +-----------+                                    +-------------------+
//! | User         |   |   Wallet  |                                    | Credential Issuer |
//! +--------------+   +-----------+                                    +-------------------+
//!         |                |                                                    |
//!         |                |  (1) User provides  information required           |
//!         |                |      for the issuance of a certain Credential      |
//!         |-------------------------------------------------------------------->|
//!         |                |                                                    |
//!         |                |  (2) Credential Offer (Pre-Authorized Code)        |
//!         |                |<---------------------------------------------------|
//!         |                |  (3) Obtains Issuer's Credential Issuer metadata   |
//!         |                |<-------------------------------------------------->|
//!         |   interacts    |                                                    |
//!         |--------------->|                                                    |
//!         |                |                                                    |
//!         |                |  (4) Token Request (Pre-Authorized Code, pin)      |
//!         |                |--------------------------------------------------->|
//!         |                |      Token Response (access_token)                 |
//!         |                |<---------------------------------------------------|
//!         |                |                                                    |
//!         |                |  (5) Credential Request (access_token, proof(s))   |
//!         |                |--------------------------------------------------->|
//!         |                |      Credential Response                           |
//!         |                |      (credential(s))                               |
//!         |                |<---------------------------------------------------|
//! ```
//!
//! While JSON-based, the Offer can be sent to the Wallet's Credential Offer Handler URL
//! as an HTTP GET request, an HTTP redirect, or a QR code.
//!
//! Below is a non-normative example of a Credential Offer Object for a Pre-Authorized
//! Code Step (with a credential type reference):
//!
//! ```json
//! {
//!     "credential_issuer": "https://credential-issuer.example.com",
//!     "credential_configuration_ids": [
//!         "UniversityDegree_LDP_VC"
//!     ],
//!     "grants": {
//!         "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
//!             "pre-authorized_code": "adhjhdjajkdkhjhdj",
//!             "tx_code": {
//!                 "input_mode":"numeric",
//!                 "length":6,
//!                 "description":"Please provide the one-time code that was sent via e-mail"
//!             }
//!        }
//!     }
//! }
//! ```
//!
//! See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint>

use chrono::Utc;
use tracing::instrument;
use vercre_core::gen;
use vercre_openid::issuer::{
    AuthorizationCodeGrant, CreateOfferRequest, CreateOfferResponse, CredentialOffer,
    CredentialOfferType, Grants, Metadata, PreAuthorizedCodeGrant, Provider, StateStore, TxCode,
};
use vercre_openid::{Error, Result};

use crate::state::{Expire, PreAuthorized, State, Step};

/// Invoke request handler generates and returns a Credential Offer.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn create_offer(
    provider: impl Provider, request: &CreateOfferRequest,
) -> Result<CreateOfferResponse> {
    verify(provider.clone(), request).await?;
    process(provider, request).await
}

async fn verify(provider: impl Provider, request: &CreateOfferRequest) -> Result<()> {
    tracing::debug!("create_offer::verify");

    let issuer_meta = Metadata::issuer(&provider, &request.credential_issuer)
        .await
        .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?;

    // credential_issuer required
    if request.credential_issuer.is_empty() {
        return Err(Error::InvalidRequest("no credential_issuer specified".into()));
    };

    // credentials required
    if request.credential_configuration_ids.is_empty() {
        return Err(Error::InvalidRequest("no credentials requested".into()));
    };

    // requested credential is supported
    for cred_id in &request.credential_configuration_ids {
        if !issuer_meta.credential_configurations_supported.contains_key(cred_id) {
            return Err(Error::UnsupportedCredentialType(
                "requested credential is unsupported".into(),
            ));
        };
    }

    // subject_id is required
    if request.subject_id.is_none() {
        return Err(Error::InvalidRequest("no subject_id specified".into()));
    };

    Ok(())
}

// Process the request.
async fn process(
    provider: impl Provider, request: &CreateOfferRequest,
) -> Result<CreateOfferResponse> {
    tracing::debug!("create_offer::process");

    let mut state = State {
        expires_at: Utc::now() + Expire::Authorized.duration(),
        credential_identifiers: request.credential_configuration_ids.clone(),
        subject_id: request.subject_id.clone(),
        ..State::default()
    };

    let mut pre_auth_grant = None;
    let mut auth_grant = None;
    let mut tx_code = None;

    if request.pre_authorize {
        // -------------------------
        // Pre-authorized Code Grant
        // -------------------------
        let pre_auth_code = gen::auth_code();

        let tx_code_def = if request.tx_code_required {
            Some(TxCode {
                input_mode: Some("numeric".into()),
                length: Some(6),
                description: Some("Please provide the one-time code received".into()),
            })
        } else {
            None
        };

        pre_auth_grant = Some(PreAuthorizedCodeGrant {
            pre_authorized_code: pre_auth_code.clone(),
            tx_code: tx_code_def,
            ..PreAuthorizedCodeGrant::default()
        });

        if request.tx_code_required {
            tx_code = Some(gen::tx_code());
        }

        // save state by pre-auth_code
        state.current_step = Step::PreAuthorized(PreAuthorized {
            tx_code: tx_code.clone(),
        });

        StateStore::put(&provider, &pre_auth_code, state.to_vec()?, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;
    } else {
        // -------------------------
        // Authorization Code Grant
        // -------------------------
        let issuer_state = gen::state_key();

        auth_grant = Some(AuthorizationCodeGrant {
            issuer_state: Some(issuer_state.clone()),
            authorization_server: None,
        });
        StateStore::put(&provider, &issuer_state, state.to_vec()?, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;
    }

    // if request.device_flow == DeviceFlow::CrossDevice {
    //     req_obj.response_mode = Some("direct_post".into());
    //     req_obj.client_id = format!("{}/post", request.client_id);
    //     req_obj.response_uri = Some(format!("{}/post", request.client_id));
    //     response.request_uri = Some(format!("{}/request/{state_key}", request.client_id));
    // } else {
    //     req_obj.client_id = format!("{}/callback", request.client_id);
    //     response.request_object = Some(req_obj.clone());
    // }

    // TODO: add support for `credential_offer_uri`
    Ok(CreateOfferResponse {
        credential_offer: CredentialOfferType::Object(CredentialOffer {
            credential_issuer: request.credential_issuer.clone(),
            credential_configuration_ids: request.credential_configuration_ids.clone(),
            grants: Some(Grants {
                authorization_code: auth_grant,
                pre_authorized_code: pre_auth_grant,
            }),
        }),
        tx_code,
    })
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};

    use super::*;

    #[tokio::test]
    async fn pre_authorize() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();

        // create offer to 'send' to the app
        let body = json!({
            "credential_configuration_ids": ["EmployeeID_JWT"],
            "subject_id": NORMAL_USER,
            "pre-authorize": true,
            "tx_code_required": true,
            "send_offer": "by_value"
        });

        let mut request =
            serde_json::from_value::<CreateOfferRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();
        let response = create_offer(provider.clone(), &request).await.expect("response is ok");
        assert_snapshot!("create_offer", &response, {
            ".credential_offer.grants.authorization_code.issuer_state" => "[state]",
            ".credential_offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
            ".tx_code" => "[tx_code]"
        });

        // check redacted fields
        let CredentialOfferType::Object(offer) = response.credential_offer else {
            panic!("expected CredentialOfferType::Object");
        };
        assert_let!(Some(grants), &offer.grants);
        assert_let!(Some(pre_auth_code), &grants.pre_authorized_code);
        assert!(grants.pre_authorized_code.is_some());

        // compare response with saved state
        let pre_auth_code = &pre_auth_code.pre_authorized_code; //as_ref().expect("has state");
        let buf = StateStore::get(&provider, pre_auth_code).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_snapshot!("state", &state, {
            ".expires_at" => "[expires_at]",
            ".current_step.tx_code" => "[tx_code]"
        });

        assert_let!(Step::PreAuthorized(auth_state), &state.current_step);
        assert_eq!(auth_state.tx_code, response.tx_code);
    }
}
