//! # Authorization Endpoint
//!
//! The Authorization Endpoint is used by Wallets to request access to the Credential
//! Endpoint, that is, to request issuance of a Credential. The endpoint is used in
//! the same manner as defined in [RFC6749].
//!
//! Wallets can request authorization for issuance of a Credential using
//! `authorization_details` (as defined in [RFC9396]) or `scope` parameters (or both).
//!
//! ## Authorization Requests
//!
//! - One (and only one) of `credential_configuration_id` or `format` is REQUIRED.
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

// TODO: add support for "ldp_vc" format
// TODO: add support for "jwt_vc_json-ld" format
// TODO: add support for "vc+sd-jwt" format
// LATER: add support for "mso_mdoc" format

use std::collections::HashMap;
use std::fmt::Debug;
use std::vec;

use chrono::Utc;
use tracing::instrument;
use vercre_core::gen;
use vercre_openid::issuer::{
    AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest, AuthorizationResponse,
    AuthorizationSpec, Authorized, ClaimEntry, ConfigurationId, Format, FormatProfile, GrantType,
    Issuer, Metadata, Provider, StateStore, Subject,
};
use vercre_openid::{Error, Result};

// use crate::shell;
use crate::state::{Authorization, Expire, State, Step};

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
    // get issuer metadata
    let Ok(issuer) = Metadata::issuer(&provider, &request.credential_issuer).await else {
        return Err(Error::InvalidClient("invalid `credential_issuer`".into()));
    };

    let mut ctx = Context {
        issuer,
        ..Context::default()
    };
    ctx.verify(&provider, &request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug, Default)]
struct Context {
    issuer: Issuer,
    auth_dets: HashMap<String, AuthorizationDetail>,
    scope_items: HashMap<String, String>,
    claims: Option<HashMap<String, ClaimEntry>>,
}

impl Context {
    async fn verify(
        &mut self, provider: &impl Provider, request: &AuthorizationRequest,
    ) -> Result<()> {
        tracing::debug!("authorize::verify");

        // client and server metadata
        let Ok(client) = Metadata::client(provider, &request.client_id).await else {
            return Err(Error::InvalidClient("invalid `client_id`".into()));
        };
        let Ok(server) = Metadata::server(provider, &request.credential_issuer).await else {
            return Err(Error::ServerError("invalid `credential_issuer`".into()));
        };

        // 'authorization_code' grant_type allowed (client and server)?
        let client_grant_types = client.oauth.grant_types.unwrap_or_default();
        if !client_grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(Error::InvalidGrant(
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
                .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;

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
            return Err(Error::InvalidRequest("no redirect_uri specified".into()));
        };
        let Some(redirect_uris) = client.oauth.redirect_uris else {
            return Err(Error::InvalidRequest("no redirect_uris specified for client".into()));
        };
        if !redirect_uris.contains(redirect_uri) {
            return Err(Error::InvalidRequest("request redirect_uri is not registered".into()));
        }

        // response_type
        if !client.oauth.response_types.unwrap_or_default().contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "the response_type not supported by client".into(),
            ));
        }
        if !server.oauth.response_types_supported.contains(&request.response_type) {
            return Err(Error::UnsupportedResponseType(
                "response_type not supported by server".into(),
            ));
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server.oauth.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&request.code_challenge_method) {
            return Err(Error::InvalidRequest("unsupported code_challenge_method".into()));
        }
        if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
            return Err(Error::InvalidRequest(
                "code_challenge must be between 43 and 128 characters".into(),
            ));
        }

        Ok(())
    }

    // Verify Credentials requested in `authorization_details` are supported.
    // N.B. has side effect of saving valid `authorization_detail` objects into context
    // for later use.
    fn verify_authorization_details(
        &mut self, authorization_details: &[AuthorizationDetail],
    ) -> Result<()> {
        let supported = &self.issuer.credential_configurations_supported;

        // check each credential requested is supported by the issuer
        for auth_det in authorization_details {
            if auth_det.type_ != AuthorizationDetailType::OpenIdCredential {
                return Err(Error::InvalidRequest("invalid authorization_details type".into()));
            }

            // verify requested credentials are supported
            match &auth_det.specification {
                AuthorizationSpec::ConfigurationId(ConfigurationId::Definition {
                    credential_configuration_id,
                    credential_definition,
                }) => {
                    //  find supported credential by `credential_configuration_id`
                    if !supported.contains_key(credential_configuration_id) {
                        return Err(Error::InvalidRequest(
                            "unsupported credential_configuration_id".into(),
                        ));
                    }

                    // verify requested claims are supported
                    if let Some(requested_cd) = credential_definition
                        && let Some(claims) = &requested_cd.credential_subject
                    {
                        let supported_cd =
                            &supported[credential_configuration_id].credential_definition;
                        Self::verify_claims(claims, &supported_cd.credential_subject)?;
                        self.claims = Some(claims.clone());
                    }

                    // save `credential_configuration_id` for later use
                    self.auth_dets.insert(credential_configuration_id.clone(), auth_det.clone());
                }
                AuthorizationSpec::Format(Format::JwtVcJson {
                    credential_definition,
                }) => {
                    //  find supported credential by `format` and `type`
                    let Some((config_id, _)) = supported.iter().find(|(_, v)| {
                        v.format == FormatProfile::JwtVcJson
                            && v.credential_definition.type_ == credential_definition.type_
                    }) else {
                        return Err(Error::InvalidRequest(
                            "unsupported credential `format` or `type`".into(),
                        ));
                    };

                    // verify requested claims are supported
                    if let Some(claims) = &credential_definition.credential_subject {
                        let supported_cd = &supported[config_id].credential_definition;
                        Self::verify_claims(claims, &supported_cd.credential_subject)?;
                        self.claims = Some(claims.clone());
                    }

                    // save `credential_configuration_id` for later use
                    self.auth_dets.insert(config_id.clone(), auth_det.clone());
                }
                AuthorizationSpec::ConfigurationId(ConfigurationId::Claims { .. }) => {
                    todo!("ConfigurationId::Claims");
                }
                AuthorizationSpec::Format(Format::LdpVc { .. }) => {
                    todo!("Format::LdpVc");
                }
                AuthorizationSpec::Format(Format::JwtVcJsonLd { .. }) => {
                    todo!("Format::JwtVcJsonLd");
                }
                AuthorizationSpec::Format(Format::MsoDoc { .. }) => {
                    todo!("Format::MsoDoc");
                }
                AuthorizationSpec::Format(Format::VcSdJwt { .. }) => {
                    todo!("Format::VcSdJwt");
                }
            };
        }

        Ok(())
    }

    fn verify_claims(
        requested: &HashMap<String, ClaimEntry>, supported: &Option<HashMap<String, ClaimEntry>>,
    ) -> Result<()> {
        let Some(supp_claims) = &supported else {
            return Ok(());
        };

        for key in requested.keys() {
            if !supp_claims.contains_key(key) {
                return Err(Error::InvalidRequest(format!("{key} claim is not supported")));
            }
        }

        Ok(())
    }

    // Verify Credentials requested in `scope` are supported.
    // N.B. has side effect of saving valid scope items into context for later use.
    fn verify_scope(&mut self, scope: &str) -> Result<()> {
        'verify_scope: for item in scope.split_whitespace() {
            for (config_id, cred_cfg) in &self.issuer.credential_configurations_supported {
                // `authorization_details` credential request  takes precedence `scope` request
                if self.auth_dets.contains_key(config_id) {
                    continue;
                }

                if cred_cfg.scope == Some(item.to_string()) {
                    // save scope item by `credential_configuration_id` for later use
                    self.scope_items.insert(config_id.to_string(), item.to_string());
                    continue 'verify_scope;
                }
            }

            return Err(Error::InvalidRequest("scope item {item} is unsupported".into()));
        }

        Ok(())
    }

    // Authorize Wallet request:
    // - check which requested `credential_configuration_id`s the holder is
    //   authorized for
    // - save related auth_dets/scope items in state
    async fn process(
        &self, provider: &impl Provider, request: AuthorizationRequest,
    ) -> Result<AuthorizationResponse> {
        tracing::debug!("authorize::process");

        // for Credentials requested using `authorization_detail`
        let mut authzd_detail = vec![];
        let mut credentials = HashMap::new();

        for (config_id, auth_det) in &self.auth_dets {
            let identifiers =
                Subject::authorize(provider, &request.subject_id, config_id, self.claims.clone())
                    .await
                    .map_err(|e| Error::ServerError(format!("issue authorizing subject: {e}")))?;

            authzd_detail.push(Authorized {
                authorization_detail: auth_det.clone(),
                credential_identifiers: identifiers.clone(),
            });

            for identifier in &identifiers {
                credentials.insert(identifier.clone(), config_id.clone());
            }
        }

        // for Credentials requested using `scope`
        // FIXME: add `credential_identifiers` to Authorized state
        let mut authzd_scope = vec![];
        for (config_id, scope_item) in &self.scope_items {
            let identifiers = Subject::authorize(provider, &request.subject_id, config_id, None)
                .await
                .map_err(|e| Error::ServerError(format!("issue authorizing holder: {e}")))?;

            authzd_scope.push(scope_item.clone());

            for identifier in &identifiers {
                credentials.insert(identifier.clone(), config_id.clone());
            }
        }

        let authorized = if authzd_detail.is_empty() { None } else { Some(authzd_detail) };

        let scope = if authzd_scope.is_empty() { None } else { Some(authzd_scope.join(" ")) };

        // return an error if holder is not authorized for any requested credentials
        if authorized.is_none() && scope.is_none() {
            return Err(Error::AccessDenied(
                "holder is not authorized for requested credentials".into(),
            ));
        }

        // save authorization state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            credentials: Some(credentials),
            subject_id: Some(request.subject_id),
            current_step: Step::Authorization(Authorization {
                code_challenge: request.code_challenge,
                code_challenge_method: request.code_challenge_method,
                authorized,
                scope,
                client_id: request.client_id,
                redirect_uri: request.redirect_uri.clone(),
            }),
            ..State::default()
        };

        let code = gen::auth_code();
        StateStore::put(provider, &code, &state, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;

        // remove offer state
        if let Some(issuer_state) = &request.issuer_state {
            StateStore::purge(provider, issuer_state)
                .await
                .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;
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
    use sha2::{Digest, Sha256};
    use vercre_macros::authorization_request;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;

    #[rstest]
    #[case("configuration_id", configuration_id)]
    #[case("credential_definition", credential_definition)]
    #[case("format", format)]
    #[case("scope", scope)]
    async fn request(#[case] name: &str, #[case] f: fn() -> AuthorizationRequest) {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // create request
        let request = f();
        let response = authorize(provider.clone(), request).await.expect("response is ok");

        assert_snapshot!("authorize:configuration_id:response", &response, {
            ".code" => "[code]",
        });

        // compare response with saved state
        let state =
            StateStore::get::<State>(&provider, &response.code).await.expect("state exists");

        assert_snapshot!(format!("authorize:{name}:state"), state, {
            ".expires_at" => "[expires_at]",
            ".current_step.authorized.*.credential_definition.credentialSubject" => insta::sorted_redaction(),
        });
    }

    fn configuration_id() -> AuthorizationRequest {
        authorization_request!({
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

    fn credential_definition() -> AuthorizationRequest {
        authorization_request!({
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
                        "given_name": {},
                        "family_name": {},
                    }
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn format() -> AuthorizationRequest {
        authorization_request!({
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
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://www.w3.org/2018/credentials/examples/v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "EmployeeIDCredential"
                    ],
                    "credentialSubject": {}
                }
            }],
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER
        })
    }

    fn scope() -> AuthorizationRequest {
        authorization_request!({
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
}
