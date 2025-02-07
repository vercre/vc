//! # Authorization Endpoint
//!
//! The Authorization Endpoint is used by Wallets to request access to the
//! Credential Endpoint, that is, to request issuance of a Credential. The
//! endpoint is used in the same manner as defined in [RFC6749].
//!
//! Wallets can request authorization for issuance of a Credential using
//! `authorization_details` (as defined in [RFC9396]) or `scope` parameters (or
//! both).
//!
//! ## Authorization Requests
//!
//! - One (and only one) of `credential_configuration_id` or `format` is
//!   REQUIRED.
//! - `credential_definition` is OPTIONAL.

//! ## Example
//!
//! with `credential_configuration_id`:
//!
//! ```json
//! "authorization_details":[
//!    {
//!       "type": "openid_credential",
//!       "credential_configuration_id": "UniversityDegreeCredential"
//!    }
//! ]
//! ```
//!
//! with `format`:
//!
//! ```json
//! "authorization_details":[
//!     {
//!         "type": "openid_credential",
//!         "format": "vc+sd-jwt",
//!         "vct": "SD_JWT_VC_example_in_OpenID4VCI"
//!     }
//! ]
//! ```
//!
//! **VC Signed as a JWT, Not Using JSON-LD**
//!
//! - `credential_definition` is OPTIONAL.
//!   - `type` is OPTIONAL.
//!   - `credentialSubject` is OPTIONAL.
//!
//! ```json
// ! "authorization_details":[
// !     {
// !         "type": "openid_credential",
// !         "credential_configuration_id": "UniversityDegreeCredential",
// !         "credential_definition": {
// !             "credentialSubject": {
// !                 "given_name": {},
// !                 "family_name": {},
// !                 "degree": {}
// !             }
// !         }
// !     }
// ! ]
//! ```
//! 
//! [RFC6749]: (https://www.rfc-editor.org/rfc/rfc6749.html)
//! [RFC9396]: (https://www.rfc-editor.org/rfc/rfc9396)

use std::collections::HashMap;
use std::fmt::Debug;
use std::vec;

use chrono::Utc;
use tracing::instrument;

use super::state::{Authorization, AuthorizedItem, Expire, ItemType, Stage, State};
use crate::core::gen;
use crate::openid::issuer::{
    AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest, AuthorizationResponse,
    Claim, CredentialAuthorization, Issuer, Metadata, ProfileClaims, Provider, RequestObject,
    Subject,
};
use crate::openid::oauth::GrantType;
use crate::openid::provider::StateStore;
use crate::openid::{Error, Result};

/// Authorization request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn authorize(
    provider: impl Provider, request: AuthorizationRequest,
) -> Result<AuthorizationResponse> {
    // request object or URI (Pushed Authorization Request)
    let mut is_par = false;
    let request = match request {
        AuthorizationRequest::Object(request) => request,
        AuthorizationRequest::Uri(uri) => {
            is_par = true;
            let state: State = StateStore::get(&provider, &uri.request_uri)
                .await
                .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;
            let Stage::PushedAuthorization(par) = &state.stage else {
                return Err(Error::InvalidRequest("invalid state".into()));
            };

            if par.expires_at < Utc::now() {
                return Err(Error::InvalidRequest("`request_uri` has expired".into()));
            }
            par.request.clone()
        }
    };

    // get issuer metadata
    let Ok(issuer) = Metadata::issuer(&provider, &request.credential_issuer).await else {
        return Err(Error::InvalidRequest("invalid `credential_issuer`".into()));
    };

    let mut ctx = Context {
        issuer,
        is_par,
        ..Context::default()
    };
    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug, Default)]
pub struct Context {
    pub issuer: Issuer,
    pub auth_dets: HashMap<String, AuthorizationDetail>,
    pub scope_items: HashMap<String, String>,
    pub claims: Option<HashMap<String, Claim>>,
    pub is_par: bool,
}

impl Context {
    pub async fn verify(
        &mut self, provider: &impl Provider, request: &RequestObject,
    ) -> Result<()> {
        tracing::debug!("authorize::verify");

        // client and server metadata
        let Ok(client) = Metadata::client(provider, &request.client_id).await else {
            return Err(Error::InvalidClient("invalid `client_id`".into()));
        };
        // TODO: support authorization issuers
        let Ok(server) = Metadata::server(provider, &request.credential_issuer, None).await else {
            return Err(Error::InvalidRequest("invalid `credential_issuer`".into()));
        };

        // If the server requires pushed authorization requests, the request
        // must be a PAR.
        if let Some(must_be_par) = server.oauth.require_pushed_authorization_requests {
            if must_be_par && !self.is_par {
                return Err(Error::InvalidRequest(
                    "pushed authorization request is required".into(),
                ));
            }
        }

        // Requested `response_type` must be supported by the authorization server.
        if !server.oauth.response_types_supported.contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported by server".into(),
            ));
        }

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

        // 'authorization_code' grant_type allowed (client and server)?
        let client_grant_types = client.oauth.grant_types.unwrap_or_default();
        if !client_grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(Error::UnauthorizedClient(
                "authorization_code grant not supported for client".into(),
            ));
        }
        let server_grant_types = server.oauth.grant_types_supported.unwrap_or_default();
        if !server_grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(Error::InvalidRequest(
                "authorization_code grant not supported by server".into(),
            ));
        }

        // is holder identified (authenticated)?
        if request.subject_id.is_empty() {
            return Err(Error::InvalidRequest("missing holder subject".into()));
        }

        // does offer `subject_id`  match request `subject_id`?
        if let Some(issuer_state) = &request.issuer_state {
            let state: State = StateStore::get(provider, issuer_state)
                .await
                .map_err(|e| Error::ServerError(format!("issue getting state: {e}")))?;

            if state.is_expired() {
                return Err(Error::InvalidRequest("issuer state expired".into()));
            }

            if state.subject_id.as_ref() != Some(&request.subject_id) {
                return Err(Error::InvalidRequest(
                    "request `subject_id` does not match offer".into(),
                ));
            }
        }

        // has a credential been requested?
        if request.authorization_details.is_none() && request.scope.is_none() {
            return Err(Error::InvalidRequest("no credentials requested".into()));
        }

        // verify authorization_details
        if let Some(authorization_details) = &request.authorization_details {
            self.verify_authorization_details(authorization_details)?;
        }
        // verify scope
        if let Some(scope) = &request.scope {
            self.verify_scope(scope)?;
        }

        // redirect_uri
        let Some(redirect_uri) = &request.redirect_uri else {
            return Err(Error::InvalidRequest("no `redirect_uri` specified".into()));
        };
        let Some(redirect_uris) = client.oauth.redirect_uris else {
            return Err(Error::ServerError("`redirect_uri`s not set for client".into()));
        };
        if !redirect_uris.contains(redirect_uri) {
            return Err(Error::InvalidRequest("`redirect_uri` is not registered".into()));
        }

        // response_type
        if !client.oauth.response_types.unwrap_or_default().contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported for client".into(),
            ));
        }
        if !server.oauth.response_types_supported.contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "`response_type` not supported by server".into(),
            ));
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server.oauth.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&request.code_challenge_method) {
            return Err(Error::InvalidRequest("unsupported `code_challenge_method`".into()));
        }
        if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
            return Err(Error::InvalidRequest(
                "code_challenge must be between 43 and 128 characters".into(),
            ));
        }

        Ok(())
    }

    // Verify Credentials requested in `authorization_details` are supported.
    // N.B. has side effect of saving valid `authorization_detail` objects into
    // context for later use.
    fn verify_authorization_details(
        &mut self, authorization_details: &[AuthorizationDetail],
    ) -> Result<()> {
        // check each credential requested is supported by the issuer
        for auth_det in authorization_details {
            if auth_det.type_ != AuthorizationDetailType::OpenIdCredential {
                return Err(Error::InvalidAuthorizationDetails(
                    "invalid authorization_details type".into(),
                ));
            }

            // verify requested claims
            let (config_id, claims) = match &auth_det.credential {
                CredentialAuthorization::ConfigurationId {
                    credential_configuration_id,
                    claims: profile,
                } => {
                    (credential_configuration_id, profile.as_ref().and_then(ProfileClaims::claims))
                }
                CredentialAuthorization::Format(fmt) => {
                    let credential_configuration_id =
                        self.issuer.credential_configuration_id(fmt).map_err(|e| {
                            Error::ServerError(format!(
                                "issue getting `credential_configuration_id`: {e}"
                            ))
                        })?;
                    (credential_configuration_id, fmt.claims())
                }
            };

            // check claims are supported and include all mandatory claims
            if let Some(requested) = &claims {
                let Some(config) = self.issuer.credential_configurations_supported.get(config_id)
                else {
                    return Err(Error::InvalidAuthorizationDetails(
                        "invalid credential_configuration_id".into(),
                    ));
                };
                config
                    .verify_claims(requested)
                    .map_err(|e| Error::InvalidRequest(e.to_string()))?;
            }

            self.auth_dets.insert(config_id.clone(), auth_det.clone());
            self.claims = claims;
        }

        Ok(())
    }

    // Verify Credentials requested in `scope` are supported.
    // N.B. has side effect of saving valid scope items into context for later use.
    fn verify_scope(&mut self, scope: &str) -> Result<()> {
        if let Some(item) = scope.split_whitespace().next() {
            let mut scope_map = HashMap::new();

            // find supported configurations that has the requested scope
            for (config_id, cred_cfg) in &self.issuer.credential_configurations_supported {
                // `authorization_details` credential request takes precedence `scope` request
                if self.auth_dets.contains_key(config_id) {
                    continue;
                }

                // save scope item + credential_configuration_id
                if cred_cfg.scope == Some(item.to_string()) {
                    scope_map.insert(config_id.to_string(), item.to_string());
                }
            }

            if scope_map.is_empty() {
                return Err(Error::InvalidScope(format!("scope item {item} is unsupported")));
            }
            self.scope_items.extend(scope_map);
        }

        Ok(())
    }

    // Authorize Wallet request:
    // - check which requested `credential_configuration_id`s the holder is
    //   authorized for
    // - save related auth_dets/scope items in state
    async fn process(
        &self, provider: &impl Provider, request: RequestObject,
    ) -> Result<AuthorizationResponse> {
        tracing::debug!("authorize::process");

        // authorization_detail
        let mut authorized_items = vec![];
        for (config_id, auth_det) in &self.auth_dets {
            let identifiers = Subject::authorize(provider, &request.subject_id, config_id)
                .await
                .map_err(|e| Error::AccessDenied(format!("issue authorizing subject: {e}")))?;

            authorized_items.push(AuthorizedItem {
                item: ItemType::AuthorizationDetail(auth_det.clone()),
                credential_configuration_id: config_id.clone(),
                credential_identifiers: identifiers.clone(),
            });
        }

        // scope
        for (config_id, scope_item) in &self.scope_items {
            let identifiers = Subject::authorize(provider, &request.subject_id, config_id)
                .await
                .map_err(|e| Error::AccessDenied(format!("issue authorizing holder: {e}")))?;

            authorized_items.push(AuthorizedItem {
                item: ItemType::Scope(scope_item.clone()),
                credential_configuration_id: config_id.clone(),
                credential_identifiers: identifiers.clone(),
            });
        }

        // return an error if holder is not authorized for any requested credentials
        if authorized_items.is_empty() {
            return Err(Error::AccessDenied(
                "holder is not authorized for requested credentials".into(),
            ));
        }

        // save authorization state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: Some(request.subject_id),
            stage: Stage::Authorized(Authorization {
                code_challenge: request.code_challenge,
                code_challenge_method: request.code_challenge_method,
                items: authorized_items,
                client_id: request.client_id,
                redirect_uri: request.redirect_uri.clone(),
            }),
        };

        let code = gen::auth_code();
        StateStore::put(provider, &code, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving authorization state: {e}")))?;

        // remove offer state
        if let Some(issuer_state) = &request.issuer_state {
            StateStore::purge(provider, issuer_state)
                .await
                .map_err(|e| Error::ServerError(format!("issue purging offer state: {e}")))?;
        }

        Ok(AuthorizationResponse {
            code,
            state: request.state,
            redirect_uri: request.redirect_uri.unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use insta::assert_yaml_snapshot as assert_snapshot;
    use rstest::rstest;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use test_utils::snapshot;

    use super::*;
    // extern crate self as vercre_issuer;

    #[rstest]
    #[case::configuration_id("configuration_id", configuration_id)]
    #[case::format("format", format_w3c)]
    #[case::scope("scope", scope)]
    #[case::claims("claims", claims)]
    #[should_panic(expected = "ok")]
    #[case::claims_err("claims_err", claims_err)]
    #[should_panic(expected = "ok")]
    #[case::response_type_err("response_type_err", response_type_err)]
    async fn authorize_tests(#[case] name: &str, #[case] value: fn() -> Value) {
        test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // execute request
        let request = serde_json::from_value(value()).expect("should deserialize");
        let response = authorize(provider.clone(), request).await.expect("ok");
        assert_snapshot!("authorize:configuration_id:response", &response, {
            ".code" =>"[code]",
        });

        // check saved state
        let state =
            StateStore::get::<State>(&provider, &response.code).await.expect("state exists");
        assert_snapshot!(format!("authorize:{name}:state"), state, {
            ".expires_at" => "[expires_at]",
            ".**.credentialSubject" => insta::sorted_redaction(),
            ".**.credentialSubject.address" => insta::sorted_redaction(),
        });
    }

    fn configuration_id() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "EmployeeID_JWT",
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn format_w3c() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ]
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn scope() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "scope": "EmployeeIDCredential",
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn claims() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "EmployeeID_JWT",
                "credential_definition": {
                    "credentialSubject": {
                        "email": {},
                        "given_name": {},
                        "family_name": {},
                        "address": {
                            "street_address": {},
                            "locality": {}
                        }
                    }
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn claims_err() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "format": "jwt_vc_json",
                "credential_definition": {
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ],
                    "credentialSubject": {
                        "given_name": {},
                        "family_name": {},
                        "employee_id": {}
                    }
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn response_type_err() -> Value {
        json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "response_type": "vp_token",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&Sha256::digest("ABCDEF12345")),
            "code_challenge_method": "S256",
            "authorization_details": [{
                "type": "openid_credential",
                "credential_configuration_id": "EmployeeID_JWT",
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }
}
