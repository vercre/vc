//! # Token Endpoint
//!
//! The Token Endpoint issues an Access Token and, optionally, a Refresh Token
//! in exchange for the Authorization Code that client obtained in a successful
//! Authorization Response. It is used in the same manner as defined in
//! [RFC6749](https://tools.ietf.org/html/rfc6749#section-5.1) and follows the
//! recommendations given in [I-D.ietf-oauth-security-topics].
//!
//! The authorization server MUST include the HTTP "Cache-Control" response
//! header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-store" in any response containing tokens,
//! credentials, or other sensitive information, as well as the "Pragma"
//! response header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-cache".

// TODO: verify `client_assertion` JWT, when set

use std::collections::HashMap;
use std::fmt::Debug;

use chrono::Utc;
use tracing::instrument;

use crate::core::{generate, pkce};
use crate::oauth::GrantType;
use crate::oid4vci::endpoint::Request;
use crate::oid4vci::provider::{Metadata, Provider, StateStore};
use crate::oid4vci::state::{Authorized, AuthorizedItem, Expire, ItemType, Stage, State, Token};
use crate::oid4vci::types::{
    AuthorizationCredential, AuthorizationDetail, AuthorizedDetail, Issuer, TokenGrantType,
    TokenRequest, TokenResponse, TokenType,
};
use crate::oid4vci::{Error, Result};

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn token(provider: impl Provider, request: TokenRequest) -> Result<TokenResponse> {
    // restore state
    let state_key = match &request.grant_type {
        TokenGrantType::AuthorizationCode { code, .. } => code,
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => pre_authorized_code,
    };

    // RFC 6749 requires a particular error here
    let Ok(state) = StateStore::get(&provider, state_key).await else {
        return Err(Error::InvalidGrant("authorization code is invalid".into()));
    };

    // authorization code is one-time use
    StateStore::purge(&provider, state_key)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging authorizaiton state: {e}")))?;

    let ctx = Context { state };

    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

impl Request for TokenRequest {
    type Response = TokenResponse;

    fn handle(
        self, _credential_issuer: &str, provider: &impl Provider,
    ) -> impl Future<Output = Result<Self::Response>> + Send {
        token(provider.clone(), self)
    }
}

#[derive(Debug)]
struct Context {
    state: State,
}

impl Context {
    // Verify the token request.
    async fn verify(&self, provider: &impl Provider, request: &TokenRequest) -> Result<()> {
        tracing::debug!("token::verify");

        if self.state.is_expired() {
            return Err(Error::InvalidRequest("authorization state expired".into()));
        }

        // TODO: support optional authorization issuers
        let Ok(server) = Metadata::server(provider, &request.credential_issuer, None).await else {
            return Err(Error::InvalidRequest("unknown authorization server".into()));
        };
        let Some(grant_types_supported) = &server.oauth.grant_types_supported else {
            return Err(Error::ServerError("authorization server grant types not set".into()));
        };

        // grant_type
        match &request.grant_type {
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Stage::Offered(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };
                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::PreAuthorizedCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".into()));
                }

                // anonymous access allowed?
                if request.client_id.as_ref().is_none()
                    || request.client_id.as_ref().is_some_and(String::is_empty)
                        && !server.pre_authorized_grant_anonymous_access_supported
                {
                    return Err(Error::InvalidClient("anonymous access is not supported".into()));
                }

                // tx_code (PIN)
                if tx_code != &auth_state.tx_code {
                    return Err(Error::InvalidGrant("invalid `tx_code` provided".into()));
                }
            }
            TokenGrantType::AuthorizationCode {
                redirect_uri,
                code_verifier,
                ..
            } => {
                let Stage::Authorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };

                // grant_type supported?
                if !grant_types_supported.contains(&GrantType::AuthorizationCode) {
                    return Err(Error::InvalidGrant("unsupported `grant_type`".into()));
                }

                // client_id is the same as the one used to obtain the authorization code
                if request.client_id.is_none() {
                    return Err(Error::InvalidRequest("`client_id` is missing".into()));
                }
                if request.client_id.as_ref() != Some(&auth_state.client_id) {
                    return Err(Error::InvalidClient(
                        "`client_id` differs from authorized one".into(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &auth_state.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "`redirect_uri` differs from authorized one".into(),
                    ));
                }

                // verifier matches challenge received in authorization request
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("`code_verifier` is missing".into()));
                };
                if pkce::code_challenge(verifier) != auth_state.code_challenge {
                    return Err(Error::AccessDenied("`code_verifier` is invalid".into()));
                }
            }
        }

        if let Some(client_id) = &request.client_id {
            // client metadata
            let Ok(client) = Metadata::client(provider, client_id).await else {
                return Err(Error::InvalidClient("invalid `client_id`".into()));
            };
            // Client and server must support the same scopes.
            if let Some(client_scope) = &client.oauth.scope {
                if let Some(server_scopes) = &server.oauth.scopes_supported {
                    let scopes: Vec<&str> = client_scope.split_whitespace().collect();
                    if !scopes.iter().all(|s| server_scopes.contains(&(*s).to_string())) {
                        return Err(Error::InvalidRequest("client scope not supported".into()));
                    }
                } else {
                    return Err(Error::InvalidRequest("server supported scopes not set".into()));
                }
            } else {
                return Err(Error::InvalidRequest("client scope not set".into()));
            }
        }

        Ok(())
    }

    // TODO: add `client_assertion` JWT verification

    // Exchange authorization/pre-authorized code for access token.
    async fn process(
        &self, provider: &impl Provider, request: TokenRequest,
    ) -> Result<TokenResponse> {
        tracing::debug!("token::process");

        let (authorization_details, authorized) = match &request.grant_type {
            TokenGrantType::PreAuthorizedCode { .. } => {
                let Stage::Offered(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };
                let Some(auth_items) = &auth_state.items else {
                    return Err(Error::ServerError("no authorized items".into()));
                };

                // get the subset of requested credentials from those previously authorized
                let retained_items = retain_details(provider, &request, auth_items).await?;
                let authorized_details = authorized_details(&retained_items);
                let authorized = authorized_credentials(&retained_items);
                (authorized_details, authorized)
            }
            TokenGrantType::AuthorizationCode { .. } => {
                let Stage::Authorized(auth_state) = &self.state.stage else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };
                let authorized_details = authorized_details(&auth_state.items);
                let authorized = authorized_credentials(&auth_state.items);
                (authorized_details, authorized)
            }
        };

        let access_token = generate::token();
        let c_nonce = generate::nonce();

        // update state
        let mut state = self.state.clone();
        state.stage = Stage::Validated(Token {
            access_token: access_token.clone(),
            credentials: authorized,
            c_nonce: c_nonce.clone(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
        });
        StateStore::put(provider, &access_token, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        // return response
        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: Expire::Access.duration().num_seconds(),
            authorization_details,
        })
    }
}

// Filter previously authorized DetailItems by requested
// `authorization_details`.
async fn retain_details(
    provider: &impl Provider, request: &TokenRequest, items: &[AuthorizedItem],
) -> Result<Vec<AuthorizedItem>> {
    // no `authorization_details` in request, return all previously authorized
    let Some(req_auth_dets) = request.authorization_details.as_ref() else {
        return Ok(items.to_vec());
    };

    let Ok(issuer) = Metadata::issuer(provider, &request.credential_issuer).await else {
        return Err(Error::InvalidRequest("unknown authorization server".into()));
    };

    // filter by requested authorization_details
    let mut retained = vec![];

    for detail in req_auth_dets {
        // check requested `authorization_detail` has been previously authorized
        let mut found = false;
        for item in items {
            if let ItemType::AuthorizationDetail(ad) = &item.item {
                if ad.credential == detail.credential {
                    verify_claims(&issuer, detail)?;
                    retained.push(item.clone());
                    found = true;
                    break;
                }
            }
        }

        if !found {
            // we're here if requested `authorization_detail` has not been authorized
            return Err(Error::AccessDenied("requested credential has not been authorized".into()));
        }
    }

    Ok(retained)
}

// Verify requested claims exist as supported claims and all mandatory claims
// have been requested.
fn verify_claims(issuer: &Issuer, detail: &AuthorizationDetail) -> Result<()> {
    // verify requested claims
    let config_id = match &detail.credential {
        AuthorizationCredential::ConfigurationId {
            credential_configuration_id,
        } => credential_configuration_id,
        AuthorizationCredential::Format(fmt) => issuer
            .credential_configuration_id(fmt)
            .map_err(|e| Error::ServerError(format!("issuer issue: {e}")))?,
    };

    // check claims are supported and include all mandatory claims
    if let Some(requested) = &detail.claims {
        let config =
            issuer.credential_configurations_supported.get(config_id).ok_or_else(|| {
                Error::InvalidAuthorizationDetails("invalid `credential_configuration_id`".into())
            })?;
        config
            .verify_claims(requested)
            .map_err(|e| Error::InvalidAuthorizationDetails(e.to_string()))?;
    }

    Ok(())
}

fn authorized_details(items: &[AuthorizedItem]) -> Option<Vec<AuthorizedDetail>> {
    // convert retained detail_items to Authorized token response
    // + state Authorized
    let mut authorization_details = vec![];

    for item in items {
        if let ItemType::AuthorizationDetail(ad) = &item.item {
            authorization_details.push(AuthorizedDetail {
                authorization_detail: ad.clone(),
                credential_identifiers: item.credential_identifiers.clone(),
            });
        }
    }

    if authorization_details.is_empty() {
        return None;
    }
    Some(authorization_details)
}

fn authorized_credentials(items: &[AuthorizedItem]) -> HashMap<String, Authorized> {
    let mut authorized = HashMap::new();

    for item in items {
        for identifier in &item.credential_identifiers {
            authorized.insert(
                identifier.clone(),
                Authorized {
                    credential_identifier: identifier.clone(),
                    credential_configuration_id: item.credential_configuration_id.clone(),
                    claim_ids: None,
                },
            );
        }
    }

    authorized
}
