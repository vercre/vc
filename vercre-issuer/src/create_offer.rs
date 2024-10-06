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
    CreateOfferResponse, CredentialAuthorization, CredentialOffer, GrantType, Grants, Metadata,
    OfferType, PreAuthorizedCodeGrant, Provider, SendType, StateStore, Subject, TxCode,
};
use vercre_openid::{Error, Result};

use crate::state::{AuthorizedItem, Expire, ItemType, Offer, Stage, State};

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
        .map_err(|e| Error::ServerError(format!("issue getting issuer metadata: {e}")))?;
    let server_meta = Metadata::server(provider, &request.credential_issuer, None)
        .await
        .map_err(|e| Error::ServerError(format!("issue getting issuer metadata: {e}")))?;

    // `credential_issuer` required
    if request.credential_issuer.is_empty() {
        return Err(Error::InvalidRequest("no `credential_issuer` specified".into()));
    };

    // credentials required
    if request.credential_configuration_ids.is_empty() {
        return Err(Error::InvalidRequest("no credentials requested".into()));
    };

    // are requested credential(s) is supported
    for cred_id in &request.credential_configuration_ids {
        if !issuer_meta.credential_configurations_supported.contains_key(cred_id) {
            return Err(Error::UnsupportedCredentialType(
                "requested credential is unsupported".into(),
            ));
        };
    }

    // TODO: check requested `grant_types` are supported by OAuth Client
    if let Some(grant_types) = &request.grant_types {
        // check requested `grant_types` are supported by OAuth Server
        if let Some(supported_grants) = &server_meta.oauth.grant_types_supported {
            for gt in grant_types {
                if !supported_grants.contains(gt) {
                    return Err(Error::UnsupportedGrantType("unsupported grant type".into()));
                };
            }
        };

        // subject_id is required for pre-authorized offers
        if grant_types.contains(&GrantType::PreAuthorizedCode) && request.subject_id.is_none() {
            return Err(Error::InvalidRequest(
                "`subject_id` is required for pre-authorization".into(),
            ));
        };
    }

    Ok(())
}

// Process the request.
async fn process(
    provider: &impl Provider, request: CreateOfferRequest,
) -> Result<CreateOfferResponse> {
    tracing::debug!("create_offer::process");

    let grant_types = request.grant_types.clone().unwrap_or_default();
    let credential_offer = credential_offer(&request);
    let tx_code = if grant_types.contains(&GrantType::PreAuthorizedCode) && request.tx_code_required
    {
        Some(gen::tx_code())
    } else {
        None
    };

    // save offer details to state
    if grant_types.contains(&GrantType::PreAuthorizedCode)
        || grant_types.contains(&GrantType::AuthorizationCode)
    {
        let auth_items = if grant_types.contains(&GrantType::PreAuthorizedCode) {
            Some(authorize(provider, &request).await?)
        } else {
            None
        };
        let state_key = state_key(credential_offer.grants.as_ref())?;

        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: request.subject_id.clone(),
            stage: Stage::Offered(Offer {
                items: auth_items,
                tx_code: tx_code.clone(),
            }),
        };
        StateStore::put(provider, &state_key, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;
    }

    // respond with Offer object or uri?
    if request.send_type == SendType::ByVal {
        Ok(CreateOfferResponse {
            offer_type: OfferType::Object(credential_offer.clone()),
            tx_code: tx_code.clone(),
        })
    } else {
        let uri_token = gen::uri_token();

        // save offer to state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: request.subject_id,
            stage: Stage::Pending(credential_offer),
        };
        StateStore::put(provider, &uri_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(CreateOfferResponse {
            offer_type: OfferType::Uri(format!(
                "{}/credential_offer/{uri_token}",
                request.credential_issuer
            )),
            tx_code,
        })
    }
}

/// Authorize requested credentials for the subject.
async fn authorize(
    provider: &impl Provider, request: &CreateOfferRequest,
) -> Result<Vec<AuthorizedItem>> {
    // skip authorization if not pre-authorized

    let mut authorized = vec![];
    let subject_id = request.subject_id.clone().unwrap_or_default();

    for config_id in request.credential_configuration_ids.clone() {
        let identifiers = Subject::authorize(provider, &subject_id, &config_id)
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
pub fn state_key(grants: Option<&Grants>) -> Result<String> {
    // get pre-authorized code as state key
    let Some(grants) = grants else {
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

    Err(Error::ServerError("no state key".into()))
}

/// Create `CredentialOffer`
fn credential_offer(request: &CreateOfferRequest) -> CredentialOffer {
    let auth_code = gen::auth_code();
    let grant_types = request.grant_types.clone().unwrap_or_default();

    let mut grants = Grants {
        authorization_code: None,
        pre_authorized_code: None,
    };

    if grant_types.contains(&GrantType::PreAuthorizedCode) {
        let tx_code_def = if request.tx_code_required {
            Some(TxCode {
                input_mode: Some("numeric".into()),
                length: Some(6),
                description: Some("Please provide the one-time code received".into()),
            })
        } else {
            None
        };

        grants.pre_authorized_code = Some(PreAuthorizedCodeGrant {
            pre_authorized_code: auth_code.clone(),
            tx_code: tx_code_def,
            authorization_server: None,
        });
    }

    if grant_types.contains(&GrantType::AuthorizationCode) {
        grants.authorization_code = Some(AuthorizationCodeGrant {
            // issuer_state: Some(gen::issuer_state()),
            issuer_state: Some(auth_code),
            authorization_server: None,
        });
    }

    let grants = if grants.authorization_code.is_some() || grants.pre_authorized_code.is_some() {
        Some(grants)
    } else {
        None
    };

    CredentialOffer {
        credential_issuer: request.credential_issuer.clone(),
        credential_configuration_ids: request.credential_configuration_ids.clone(),
        grants,
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_test_utils::issuer::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;

    #[tokio::test]
    async fn pre_authorized() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // create offer to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "credential_configuration_ids": ["EmployeeID_JWT"],
            "subject_id": NORMAL_USER,
            "grant_types": ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
            "tx_code_required": true,
            "send_type": SendType::ByVal,
        });
        let request = serde_json::from_value(value).expect("request is valid");
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

        assert_let!(Stage::Offered(auth_state), &state.stage);
        assert_eq!(auth_state.tx_code, response.tx_code);
    }
}
