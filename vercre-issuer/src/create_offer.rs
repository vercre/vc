//! # Invoke Endpoint
//!
//! The Invoke endpoint is used to initiate Pre-authorized credential issuance
//! flow. Credential Issuers can use this endpoint to generate a Credential
//! Offer which can be used to initiate issuance with a Wallet.
//!
//! When a Credential Issuer is already interacting with a user and wishes to
//! initate a Credential issuance, they can 'send' the user's Wallet a
//! Credential Offer.
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
//! While JSON-based, the Offer can be sent to the Wallet's Credential Offer
//! Handler URL as an HTTP GET request, an HTTP redirect, or a QR code.
//!
//! Below is a non-normative example of a Credential Offer Object for a
//! Pre-Authorized Code Stage (with a credential type reference):
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
    AuthorizationCodeGrant, AuthorizationDetail, AuthorizationDetailType, CreateOfferRequest,
    CreateOfferResponse, CredentialAuthorization, CredentialOffer, Grants, Metadata, OfferType,
    PreAuthorizedCodeGrant, Provider, SendType, StateStore, Subject, TxCode,
};
use vercre_openid::{Error, Result};

use crate::state::{AuthorizedItem, Expire, ItemType, Offer, PreAuthorization, Stage, State};

/// Invoke request handler generates and returns a Credential Offer.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn create_offer(
    provider: impl Provider, request: CreateOfferRequest,
) -> Result<CreateOfferResponse> {
    verify(&provider, &request).await?;
    process(&provider, request).await
}

async fn verify(provider: &impl Provider, request: &CreateOfferRequest) -> Result<()> {
    tracing::debug!("create_offer::verify");

    let issuer_meta = Metadata::issuer(provider, &request.credential_issuer)
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
    if request.pre_authorize && request.subject_id.is_none() {
        return Err(Error::InvalidRequest(
            "`subject_id` must be specified for pre-authorization".into(),
        ));
    };

    Ok(())
}

// Process the request.
async fn process(
    provider: &impl Provider, request: CreateOfferRequest,
) -> Result<CreateOfferResponse> {
    tracing::debug!("create_offer::process");

    let authorized_items = authorize(provider, &request).await?;
    let credential_offer = credential_offer(&request);
    let tx_code =
        if request.pre_authorize && request.tx_code_required { Some(gen::tx_code()) } else { None };

    // offer type and corresponding state key
    let (offer_type, state_key) = if request.send_type == SendType::ByVal {
        let state_key = state_key(&credential_offer)?;
        (OfferType::Object(credential_offer.clone()), state_key)
    } else {
        let state_key = gen::state_key();
        (
            OfferType::Uri(format!("{}/credential_offer/{state_key}", request.credential_issuer)),
            state_key,
        )
    };

    // save state
    let state_stage = if request.send_type == SendType::ByVal && request.pre_authorize {
        Stage::PreAuthorized(PreAuthorization {
            items: authorized_items,
            tx_code: tx_code.clone(),
        })
    } else {
        Stage::Offered(Offer {
            credential_offer,
            items: authorized_items,
            tx_code: tx_code.clone(),
        })
    };
    let state = State {
        expires_at: Utc::now() + Expire::Authorized.duration(),
        subject_id: request.subject_id,
        stage: state_stage,
    };
    StateStore::put(provider, &state_key, &state, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    // return response
    Ok(CreateOfferResponse { offer_type, tx_code })
}

/// Authorize requested credentials for the subject.
async fn authorize(
    provider: &impl Provider, request: &CreateOfferRequest,
) -> Result<Vec<AuthorizedItem>> {
    // skip authorization if not pre-authorized
    if !request.pre_authorize {
        return Ok(vec![]);
    }

    let Some(subject_id) = &request.subject_id else {
        return Err(Error::InvalidRequest(
            "`subject_id` must be set for pre-authorized offers".into(),
        ));
    };

    let mut authorized = vec![];

    for config_id in request.credential_configuration_ids.clone() {
        let identifiers = Subject::authorize(provider, subject_id, &config_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue authorizing holder: {e}")))?;

        authorized.push(AuthorizedItem {
            item: ItemType::AuthorizationDetail(AuthorizationDetail {
                type_: AuthorizationDetailType::OpenIdCredential,
                credential: CredentialAuthorization::ConfigurationId {
                    credential_configuration_id: config_id.clone(),
                    claims: None,
                },
                locations: None,
            }),
            credential_configuration_id: config_id.clone(),
            credential_identifiers: identifiers,
        });
    }

    Ok(authorized)
}

/// Extract `pre_authorized_code` or `issuer_state` from `CredentialOffer` to
/// use as state key.
pub fn state_key(credential_offer: &CredentialOffer) -> Result<String> {
    // get pre-authorized code as state key
    let Some(grants) = &credential_offer.grants else {
        return Err(Error::ServerError("no grants".into()));
    };

    if let Some(pre_auth_code) = &grants.pre_authorized_code {
        return Ok(pre_auth_code.pre_authorized_code.clone());
    };

    if let Some(authorization_code) = &grants.authorization_code {
        let Some(issuer_state) = &authorization_code.issuer_state else {
            return Err(Error::ServerError("no issuer_state".into()));
        };
        return Ok(issuer_state.clone());
    };

    Err(Error::ServerError("no grants".into()))
}

/// Create `CredentialOffer`
fn credential_offer(request: &CreateOfferRequest) -> CredentialOffer {
    let grants = if request.pre_authorize {
        let tx_code_def = if request.tx_code_required {
            Some(TxCode {
                input_mode: Some("numeric".into()),
                length: Some(6),
                description: Some("Please provide the one-time code received".into()),
            })
        } else {
            None
        };

        Grants {
            authorization_code: None,
            pre_authorized_code: Some(PreAuthorizedCodeGrant {
                pre_authorized_code: gen::auth_code(),
                tx_code: tx_code_def,
                authorization_server: None,
            }),
        }
    } else {
        Grants {
            authorization_code: Some(AuthorizationCodeGrant {
                issuer_state: Some(gen::state_key()),
                authorization_server: None,
            }),
            pre_authorized_code: None,
        }
    };

    CredentialOffer {
        credential_issuer: request.credential_issuer.clone(),
        credential_configuration_ids: request.credential_configuration_ids.clone(),
        grants: Some(grants),
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use vercre_macros::create_offer_request;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;
    extern crate self as vercre_issuer;

    #[tokio::test]
    async fn pre_authorized() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // create offer to 'send' to the app
        let request = create_offer_request!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "credential_configuration_ids": ["EmployeeID_JWT"],
            "subject_id": NORMAL_USER,
            "pre_authorize": true,
            "tx_code_required": true,
            "send_type": SendType::ByVal,
        });

        let response = create_offer(provider.clone(), request).await.expect("response is ok");

        assert_snapshot!("create_offer:pre-authorized:response", &response, {
            ".credential_offer.grants.authorization_code.issuer_state" => "[state]",
            ".credential_offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
            ".tx_code" => "[tx_code]"
        });

        // check redacted fields
        let OfferType::Object(offer) = response.offer_type else {
            panic!("expected CredentialOfferType::Object");
        };
        assert_let!(Some(grants), &offer.grants);
        assert_let!(Some(pre_auth_code), &grants.pre_authorized_code);
        assert!(grants.pre_authorized_code.is_some());

        // compare response with saved state
        let pre_auth_code = &pre_auth_code.pre_authorized_code; //as_ref().expect("has state");
        let state = StateStore::get::<State>(&provider, pre_auth_code).await.expect("state exists");

        assert_snapshot!("create_offer:pre-authorized:state", &state, {
            ".expires_at" => "[expires_at]",
            ".stage.tx_code" => "[tx_code]"
        });

        assert_let!(Stage::PreAuthorized(auth_state), &state.stage);
        assert_eq!(auth_state.tx_code, response.tx_code);
    }
}
