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

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::instrument;
use vercre_core::pkce;
use vercre_issuer::{
    AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest, AuthorizationResponse,
    CredentialAuthorization, CredentialDefinition, FormatIdentifier, GrantType, ProfileClaims,
    RequestObject, TokenGrantType, TokenRequest,
};

use super::{Issuance, Status};
use crate::issuance::token::{authorized_credentials, AuthorizedCredentials};
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
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
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

        /// A Holder identifier provided by the Wallet. It must have meaning to
        /// the Credential Issuer in order that credentialSubject claims
        /// can be populated.
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
/// On receiving an authorization response, this function will immediately make
/// a token request to the issuer, so the holder's agent (wallet) can make
/// credential requests directly after calling this function.
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
    // and check the flow status. Otherwise, create a new flow state.
    let mut issuance = match &request.initiator {
        Initiator::Issuer { issuance_id } => {
            match StateStore::get::<Issuance>(&provider, issuance_id).await {
                Ok(issuance) => {
                    // The grants must support authorized flow.
                    //
                    // If there are no grants on the offer, look up auth server
                    // metadata to determine the suppored grants.
                    if let Some(grants) = issuance.offer.grants.clone() {
                        if grants.authorization_code.is_none()
                            || issuance.status != Status::Accepted
                        {
                            let e = anyhow!("invalid issuance state. Must be accepted and support authorization issuance flow");
                            tracing::error!(target: "Endpoint::authorize", ?e);
                            return Err(e);
                        }
                    } else {
                        let Some(grant_types) =
                            &issuance.authorization_server.oauth.grant_types_supported
                        else {
                            let e = anyhow!("no grants in offer is not supported");
                            tracing::error!(target: "Endpoint::authorize", ?e);
                            return Err(e);
                        };
                        if !grant_types.contains(&GrantType::AuthorizationCode)
                            || issuance.status != Status::Accepted
                        {
                            let e = anyhow!("invalid issuance state. Must be accepted and support authorization issuance flow");
                            tracing::error!(target: "Endpoint::authorize", ?e);
                            return Err(e);
                        }
                    };
                    issuance
                }
                Err(e) => {
                    tracing::error!(target: "Endpoint::authorize", ?e);
                    return Err(e);
                }
            }
        }
        Initiator::Wallet {
            client_id,
            issuer,
            subject_id,
            scope,
        } => {
            // Verify the wallet is making a scope-based request or an
            // authorization details request, not both.
            if request.authorization_details.is_some() && scope.is_some() {
                let e = anyhow!(
                    "wallet-initiated issuance should use authorization details or scope, not both"
                );
                tracing::error!(target: "Endpoint::authorize", ?e);
                return Err(e);
            }

            // Create a new issuance flow.
            let mut issuance = Issuance::new(client_id);
            issuance.subject_id.clone_from(subject_id);
            issuance.set_issuer(&provider, issuer).await.map_err(|e| {
                tracing::error!(target: "Endpoint::authorize", ?e);
                e
            })?;
            issuance.scope.clone_from(scope);
            issuance
        }
    };
    issuance.accepted.clone_from(&request.authorization_details);

    // PKCE pair
    let verifier = pkce::code_verifier();
    issuance.code_challenge = Some(pkce::code_challenge(&verifier));
    issuance.code_verifier = Some(verifier);

    // Construct an authorization request.
    let authorization_request = authorization_request(&issuance, request).map_err(|e| {
        tracing::error!(target: "Endpoint::authorize", ?e);
        e
    })?;
    // Request authorization from the issuer.
    let auth_response =
        Issuer::authorization(&provider, authorization_request).await.map_err(|e| {
            tracing::error!(target: "Endpoint::authorize", ?e);
            e
        })?;

    // Construct a token request using the authorization response and request an
    // access token from the issuer.
    let token_request = token_request(&issuance, request, &auth_response);
    issuance.token = Issuer::token(&provider, token_request).await.map_err(|e| {
        tracing::error!(target: "Endpoint::authorize", ?e);
        e
    })?;
    issuance.status = Status::TokenReceived;

    let mut response = AuthorizedCredentials {
        issuance_id: issuance.id.clone(),
        authorized: None,
    };
    if let Some(auth_details) = issuance.token.authorization_details.clone() {
        if !auth_details.is_empty() {
            // Get the authorized credentials.
            let authorized = authorized_credentials(&auth_details, &issuance).map_err(|e| {
                tracing::error!(target: "Endpoint::token", ?e);
                e
            })?;
            response.authorized = Some(authorized);
        }
    }

    // Stash the state for the next step.
    if let Err(e) =
        StateStore::put(&provider, &issuance.id, &issuance, DateTime::<Utc>::MAX_UTC).await
    {
        tracing::error!(target: "Endpoint::accept", ?e);
        return Err(e);
    };

    Ok(response)
}

/// Construct an authorization request.
fn authorization_request(
    issuance: &Issuance, request: &AuthorizeRequest,
) -> anyhow::Result<AuthorizationRequest> {
    let Some(code_challenge) = issuance.code_challenge.clone() else {
        return Err(anyhow!("missing code challenge"));
    };
    let issuer_state = match request.initiator {
        Initiator::Issuer { .. } => {
            if let Some(grants) = issuance.offer.grants.clone() {
                grants
                    .authorization_code
                    .as_ref()
                    .and_then(|auth_code| auth_code.issuer_state.clone())
            } else {
                None
            }
        }
        Initiator::Wallet { .. } => None,
    };

    let scope = match &request.initiator {
        Initiator::Issuer { .. } => None,
        Initiator::Wallet { scope, .. } => scope.clone(),
    };

    // If the request contains None for authorization details, the wallet wants
    // all credentials on offer. For the authorization endpoint, we will need
    // to explicitly build the authorization details.
    let auth_details = match scope {
        Some(_) => None,
        None => Some(authorization_details(issuance, request).map_err(|e| {
            tracing::error!(target: "Endpoint::authorize", ?e);
            e
        })?),
    };

    let Some(code_challenge_methods) =
        issuance.authorization_server.oauth.code_challenge_methods_supported.clone()
    else {
        return Err(anyhow!("code challenge methods missing from authorization server metadata"));
    };

    Ok(AuthorizationRequest::Object(RequestObject {
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        response_type: issuance.authorization_server.oauth.response_types_supported[0].clone(),
        client_id: issuance.client_id.clone(),
        redirect_uri: request.redirect_uri.clone(),
        state: Some(issuance.id.clone()),
        code_challenge,
        code_challenge_method: code_challenge_methods[0].clone(),
        authorization_details: auth_details,
        scope,
        resource: Some(issuance.issuer.credential_issuer.clone()),
        subject_id: issuance.subject_id.clone(),
        // TODO: support this
        wallet_issuer: None,
        user_hint: Some(issuance.id.clone()),
        issuer_state,
    }))
}

/// Construct a token request.
fn token_request(
    issuance: &Issuance, auth_request: &AuthorizeRequest, auth_response: &AuthorizationResponse,
) -> TokenRequest {
    TokenRequest {
        credential_issuer: issuance.issuer.credential_issuer.clone(),
        client_id: Some(issuance.client_id.clone()),
        grant_type: TokenGrantType::AuthorizationCode {
            code: auth_response.code.clone(),
            redirect_uri: auth_request.redirect_uri.clone(),
            code_verifier: issuance.code_verifier.clone(),
        },
        authorization_details: issuance.accepted.clone(),
        // TODO: support this
        client_assertion: None,
    }
}

/// Construct authorization details from the issuance flow state.
fn authorization_details(
    issuance: &Issuance, request: &AuthorizeRequest,
) -> anyhow::Result<Vec<AuthorizationDetail>> {
    if issuance.accepted.is_some() {
        return Ok(issuance.accepted.clone().unwrap());
    }
    if matches!(request.initiator, Initiator::Wallet { .. }) {
        return Err(anyhow!("authorization details are required for wallet-initiated issuance"));
    }
    let mut auth_details = Vec::new();
    let creds_supported = &issuance.issuer.credential_configurations_supported;
    for cfg_id in &issuance.offer.credential_configuration_ids {
        let Some(credential_config) = creds_supported.get(cfg_id) else {
            return Err(anyhow!("unsupported credential type in offer"));
        };
        let claims: Option<ProfileClaims> =
            credential_config.format.claims().map(|claims| match &credential_config.format {
                FormatIdentifier::JwtVcJson(w3c)
                | FormatIdentifier::LdpVc(w3c)
                | FormatIdentifier::JwtVcJsonLd(w3c) => ProfileClaims::W3c(CredentialDefinition {
                    credential_subject: w3c.credential_definition.credential_subject.clone(),
                    ..Default::default()
                }),
                FormatIdentifier::IsoMdl(_) => ProfileClaims::IsoMdl(claims),
                FormatIdentifier::VcSdJwt(_) => ProfileClaims::SdJwt(claims),
            });
        auth_details.push(AuthorizationDetail {
            type_: AuthorizationDetailType::OpenIdCredential,
            credential: CredentialAuthorization::ConfigurationId {
                credential_configuration_id: cfg_id.clone(),
                claims,
            },
            ..Default::default()
        });
    }
    Ok(auth_details)
}
