//! # Authorize Endpoint
//!
//! The authorize endpoint is used by the holder when initiating an issuance
//! (that is, it is not initiated by the issuer). The endpoint is used to
//! request authorization for one or more credentials and, optionally, claims
//! contained by those credentials. If authorization is granted by the issuer,
//! the response can be used to request a token that can be exchanged for the
//! credentials.
//!
//! The endpoint is also used in the case where the issuer initiates the flow
//! but in the offer, inidicates to the holder that authorization is required.

use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_core::stringify;
use vercre_issuer::{AuthorizationDetail, AuthorizationRequest, AuthorizationResponse, MetadataRequest, TokenRequest};

use super::{Issuance, Status};
use crate::issuance::token::AuthorizedCredentials;
use crate::provider::{HolderProvider, Issuer, StateStore};

/// `AuthorizeRequest` is the request to the `authorize` endpoint to initiate an
/// issuance flow or respond to an issuer-initiated offer that requires
/// authorization.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[allow(clippy::module_name_repetitions)]
pub struct AuthorizeRequest {
    /// Parameters dependent on the initiator of the issuance flow.
    pub initiator: Initiator,

    /// The client's redirection endpoint as previously established during the
    /// client registration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirect_uri: Option<String>,

    /// Authorization Details may used to convey the details about credentials
    /// the Wallet wants to obtain.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "stringify::option")]
    pub authorization_details: Option<Vec<AuthorizationDetail>>,

    /// The Credential Issuer's identifier to allow the Authorization Server to
    /// differentiate between Issuers. [RFC8707]: The target resource to which
    /// access is being requested. MUST be an absolute URI.
    ///
    /// [RFC8707]: (https://www.rfc-editor.org/rfc/rfc8707)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,

    /// Identifies a pre-existing Credential Issuer processing context. A value
    /// for this parameter may be passed in the Credential Offer to the
    /// Wallet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_state: Option<String>,
}

/// Initiator of the issuance flow determines the fields required in the
/// authorization request.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Initiator {
    /// Wallet-initiated issuance flow.
    Wallet {
        /// Wallet client identifier. This is used by the issuance service to
        /// issue an access token so should be unique to the holder's
        /// agent. Care should be taken to ensure this is not shared
        /// across holders in the case of headless, multi-tenant agents.
        client_id: String,

        /// Identifier (URL) of the credential issuer.
        issuer: String,

        /// Credential Issuers MAY support requesting authorization to issue a
        /// credential using OAuth 2.0 scope values.
        /// A scope value and its mapping to a credential type is defined by the
        /// Issuer. A description of scope value semantics or machine readable
        /// definitions could be defined in Issuer metadata. For example,
        /// mapping a scope value to an authorization details object.
        #[serde(skip_serializing_if = "Option::is_none")]
        scope: Option<String>,

        /// A Holder identifier provided by the Wallet. It must have meaning to the
        /// Credential Issuer in order that credentialSubject claims can be
        /// populated.
        subject_id: String,
    },

    /// Issuer-initiated issuance flow.
    Issuer {
        /// The issuance flow identifier.
        issuance_id: String,
    },
}

/// Makes an authorization request to the issuer to describe the credential(s)
/// and claims the holder wants to obtain.
///
/// Initiates an issuance flow in the case of a wallet-initiated flow, or
/// carries out the authorization step in the case of an issuer-initiated flow
/// that requires authorization.
#[instrument(level = "debug", skip(provider))]
pub async fn authorize(
    provider: impl HolderProvider, request: &AuthorizeRequest,
) -> anyhow::Result<AuthorizedCredentials> {
    tracing::debug!("Endpoint::authorize");

    // If the request is issuer-initiated, retrieve the issuance flow state,
    // otherwise create a new one.
    let mut issuance = match &request.initiator {
        Initiator::Issuer{ issuance_id } => match StateStore::get(&provider, issuance_id).await {
            Ok(issuance) => issuance,
            Err(e) => {
                tracing::error!(target: "Endpoint::authorize", ?e);
                return Err(e);
            }
        },
        Initiator::Wallet{ client_id, issuer, subject_id, .. } => {
            // Create a new issuance flow.
            let mut issuance = Issuance::new(client_id);
            issuance.subject_id.clone_from(subject_id);

            // Attach issuer metadata to state
            let md_request = MetadataRequest {
                credential_issuer: issuer.clone(),
                languages: None, /* The wallet client should provide any specific languages
                                  * required. */
            };
            let md_response = match Issuer::get_metadata(&provider, &issuance.id, md_request).await
            {
                Ok(md) => md,
                Err(e) => {
                    tracing::error!(target: "Endpoint::authorize", ?e);
                    return Err(e);
                }
            };
            issuance.issuer = md_response.credential_issuer;

            issuance
        }
    };
    issuance.accepted.clone_from(&request.authorization_details);

    // Request authorization from the issuer.
    let authorization_request = authorization_request(&issuance, request);
    let auth_response = match Issuer::get_authorization(
        &provider,
        &issuance.id,
        authorization_request,
    )
    .await
    {
        Ok(auth) => auth,
        Err(e) => {
            tracing::error!(target: "Endpoint::authorize", ?e);
            return Err(e);
        }
    };
    issuance.status = Status::Authorized;

    // Construct a token request using the authorization response and request an
    // access token from the issuer.
    token_request(&issuance, request, &auth_response);

    todo!()
}

/// Construct an authorization request.
fn authorization_request(_issuance: &Issuance, _request: &AuthorizeRequest) -> AuthorizationRequest {
    todo!()
}

/// Construct a token request.
fn token_request(
    _issuance: &Issuance, _auth_request: &AuthorizeRequest, _auth_response: &AuthorizationResponse,
) -> TokenRequest {
    todo!()
}
