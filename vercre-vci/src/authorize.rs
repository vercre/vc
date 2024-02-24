//! # Authorization Endpoint
//!
//! The Authorization Endpoint is used in the same manner as defined in [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).
//!
//! An Authorization Request is used to request to grant access to the Credential
//! Endpoint.
//!
//! There are two possible ways to request issuance of a specific Credential type in an
//! Authorization Request:
//!
//! 1. Use of the `authorization_details` parameter as defined in [RFC9396](https://www.rfc-editor.org/rfc/rfc9396):
//!
//! ```json
//! [
//!    {
//!       "type": "openid_credential",
//!       "format": "jwt_vc_json",
//!       "credential_definition": {
//!          "type": [
//!             "VerifiableCredential",
//!             "UniversityDegreeCredential"
//!          ]
//!       }
//!    }
//! ]
//! ```
//!
//! 2. Use OAuth 2.0 `scope` parameter:
//!
//! ```http
//! GET /authorize?
//!   response_type=code
//!   &scope=UniversityDegreeCredential
//!   &resource=https://credential-issuer.example.com
//!   &client_id=s6BhdRkqt3
//!   &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
//!   &code_challenge_method=S256
//!   &redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb
//! Host: https://server.example.com
//! ```

// LATER: implement `SlowDown` checks/errors

use std::fmt::Debug;
use std::vec;

use chrono::Utc;
use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::metadata::Issuer as IssuerMetadata;
pub use vercre_core::vci::{
    AuthorizationDetail, AuthorizationRequest, AuthorizationResponse, TokenAuthorizationDetail,
};
use vercre_core::{
    err, gen, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager,
};

use super::Endpoint;
use crate::state::{AuthState, Expire, State};

impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone + Debug,
{
    /// Authorization request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    pub async fn authorize(&self, request: &AuthorizationRequest) -> Result<AuthorizationResponse> {
        //let request = request.into();

        // attempt to get callback_id from state, if pre-auth flow
        let callback_id = if let Some(state_key) = &request.issuer_state {
            let buf = StateManager::get(&self.provider, state_key).await?;
            let state = State::try_from(buf.as_slice())?;
            state.callback_id
        } else {
            None
        };

        let issuer_meta = Issuer::metadata(&self.provider, &request.credential_issuer).await?;
        let cfg_ids = credential_configuration_ids(request, &issuer_meta)?;

        let ctx = Context {
            callback_id,
            credential_configuration_ids: cfg_ids,
        };

        self.handle_request(request, ctx).await
    }
}

#[derive(Debug)]
struct Context {
    callback_id: Option<String>,
    credential_configuration_ids: Vec<String>,
}

impl super::Context for Context {
    type Request = AuthorizationRequest;
    type Response = AuthorizationResponse;

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    #[instrument]
    async fn verify<P>(&self, provider: &P, request: &Self::Request) -> Result<&Self>
    where
        P: Client + Issuer + Server + Holder + StateManager + Debug,
    {
        trace!("Context::verify");

        let Ok(client_meta) = Client::metadata(provider, &request.client_id).await else {
            err!(Err::InvalidClient, "invalid client_id");
        };
        let server_meta = Server::metadata(provider, &request.credential_issuer).await?;
        let issuer_meta = Issuer::metadata(provider, &request.credential_issuer).await?;

        // 'authorization_code' grant_type allowed (client and server)?
        let client_grant_types = client_meta.grant_types.unwrap_or_default();
        if !client_grant_types.contains(&"authorization_code".to_string()) {
            err!(Err::InvalidRequest, "authorization_code grant not supported for client");
        }
        let server_grant_types = server_meta.grant_types_supported.unwrap_or_default();
        if !server_grant_types.contains(&"authorization_code".to_string()) {
            err!(Err::InvalidRequest, "authorization_code grant not supported for server");
        }

        // holder authorized?
        if request.holder_id.is_empty() {
            err!(Err::AuthorizationPending, "missing holder subject");
        }

        // has a credential been requested?
        if request.authorization_details.is_none() && request.scope.is_none() {
            err!(Err::InvalidRequest, "no credentials requested");
        }

        // verify authorization_details
        'verify_details: for auth_det in request.authorization_details.as_ref().unwrap_or(&vec![]) {
            // we only support `openid_credential` authorization detail requests
            if auth_det.type_ != "openid_credential" {
                err!(Err::InvalidRequest, "invalid authorization_details type");
            }

            let cfg_id_opt = &auth_det.credential_configuration_id;
            let format_opt = &auth_det.format;

            // verify that only one of `credential_configuration_id` or `format` is specified
            if cfg_id_opt.is_some() && format_opt.is_some() {
                err!(
                    Err::InvalidRequest,
                    "`credential_configuration_id` and `format` cannot both be set"
                );
            }
            if cfg_id_opt.is_none() && format_opt.is_none() {
                err!(Err::InvalidRequest, "`credential_configuration_id` or `format` must be set");
            }

            // EITHER: verify requested `credential_configuration_id` is supported
            if let Some(cfg_id) = cfg_id_opt {
                if issuer_meta.credential_configurations_supported.get(cfg_id).is_none() {
                    err!(Err::InvalidRequest, "unsupported credential_configuration_id");
                }
                continue 'verify_details;
            }

            // OR: verify requested `format` and `type` are supported
            if let Some(format) = format_opt {
                let Some(auth_def) = auth_det.credential_definition.as_ref() else {
                    err!(Err::InvalidRequest, "no `credential_definition` specified")
                };

                // check all supported `credential_configurations`
                for cred_cfg in issuer_meta.credential_configurations_supported.values() {
                    if &cred_cfg.format == format
                        && cred_cfg.credential_definition.type_ == auth_def.type_
                    {
                        continue 'verify_details;
                    }
                }

                // couldn't find a matching credential_configuration
                err!(Err::InvalidRequest, "unsupported credential `format` or `type`");
            }
        }

        // verify scope items
        if let Some(scope) = &request.scope {
            'verify_scope: for item in scope.split_whitespace().collect::<Vec<&str>>() {
                for cred_cfg in issuer_meta.credential_configurations_supported.values() {
                    if cred_cfg.scope == Some(item.to_string()) {
                        continue 'verify_scope;
                    }
                }
                err!(Err::InvalidRequest, "scope item {item} is unsupported");
            }
        }

        // TODO: implement `Holder::authorize`
        // - for each requested credential_configuration_id, check if the holder is authorized
        // - save auth_det/scope item for each authorized credential_configuration_id

        // if Holder::authorize(provider, &request.holder_id, &self.credential_configuration_ids).await.is_err() {
        //     err!(Err::AuthorizationPending, "holder is not authorized");
        // }

        // redirect_uri
        let Some(redirect_uri) = &request.redirect_uri else {
            err!(Err::InvalidRequest, "no redirect_uri specified");
        };
        let Some(redirect_uris) = client_meta.redirect_uris else {
            err!(Err::InvalidRequest, "no redirect_uris specified for client");
        };
        if !redirect_uris.contains(redirect_uri) {
            err!(Err::InvalidRequest, "request redirect_uri is not registered");
        }

        // response_type
        if !client_meta.response_types.unwrap_or_default().contains(&request.response_type) {
            err!(Err::UnsupportedResponseType, "the response_type not supported by client");
        }
        if !server_meta.response_types_supported.contains(&request.response_type) {
            err!(Err::UnsupportedResponseType, "response_type not supported by server");
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server_meta.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&request.code_challenge_method) {
            err!(Err::InvalidRequest, "unsupported code_challenge_method");
        }
        if request.code_challenge.len() < 43 || request.code_challenge.len() > 128 {
            err!(Err::InvalidRequest, "code_challenge must be between 43 and 128 characters");
        }

        Ok(self)
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Issuer + Server + Holder + StateManager + Debug,
    {
        trace!("Context::process");

        // save authorization state
        let mut state = State {
            expires_at: Utc::now() + Expire::AuthCode.duration(),
            credential_issuer: request.credential_issuer.clone(),
            client_id: Some(request.client_id.clone()),
            credential_configuration_ids: self.credential_configuration_ids.clone(),
            holder_id: Some(request.holder_id.clone()),
            ..Default::default()
        };

        let mut auth_state = AuthState {
            redirect_uri: request.redirect_uri.clone(),
            code_challenge: Some(request.code_challenge.clone()),
            code_challenge_method: Some(request.code_challenge_method.clone()),
            scope: request.scope.clone(),
            ..Default::default()
        };

        // add `authorization_details` into state
        if let Some(auth_dets) = &request.authorization_details {
            let mut tkn_auth_dets = vec![];

            for auth_det in auth_dets {
                let tkn_auth_det = TokenAuthorizationDetail {
                    authorization_detail: auth_det.clone(),
                    credential_identifiers: None,
                };
                tkn_auth_dets.push(tkn_auth_det.clone());
            }
            auth_state.authorization_details = Some(tkn_auth_dets);
        }

        state.auth = Some(auth_state);

        let code = gen::auth_code();
        StateManager::put(provider, &code, state.to_vec(), state.expires_at).await?;

        // remove offer state
        if let Some(issuer_state) = &request.issuer_state {
            StateManager::purge(provider, issuer_state).await?;
        }

        Ok(AuthorizationResponse {
            code,
            state: request.state.clone(),
            redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
        })
    }
}

#[instrument]
fn credential_configuration_ids(
    request: &AuthorizationRequest, issuer_meta: &IssuerMetadata,
) -> Result<Vec<String>> {
    trace!("credential_configuration_ids");

    let mut cfg_ids = auth_cfg_ids(request, issuer_meta)?;
    cfg_ids.extend(scope_cfg_ids(request, issuer_meta)?);

    Ok(cfg_ids)
}

#[instrument]
fn auth_cfg_ids(
    request: &AuthorizationRequest, issuer_meta: &IssuerMetadata,
) -> Result<Vec<String>> {
    trace!("auth_cfg_ids");

    let Some(authorization_details) = &request.authorization_details else {
        return Ok(vec![]);
    };

    let mut cfg_ids = vec![];

    for auth_det in authorization_details {
        if let Some(cfg_id) = auth_det.credential_configuration_id.clone() {
            // check if requested credential_configuration_id is supported
            if issuer_meta.credential_configurations_supported.get(&cfg_id).is_some() {
                cfg_ids.push(cfg_id);
            }
        } else if let Some(format) = &auth_det.format {
            // check if requested is supported
            for (cfg_id, cred_cfg) in &issuer_meta.credential_configurations_supported {
                // credential_definition must be present
                if &cred_cfg.format == format {
                    let cfg_def = cred_cfg.credential_definition.clone();
                    let auth_def = auth_det.credential_definition.clone().unwrap_or_default();

                    if cfg_def.type_.unwrap_or_default() == auth_def.type_.unwrap_or_default() {
                        cfg_ids.push(cfg_id.clone());
                    }
                }
            }
        }
    }

    Ok(cfg_ids)
}

#[instrument]
fn scope_cfg_ids(
    request: &AuthorizationRequest, issuer_meta: &IssuerMetadata,
) -> Result<Vec<String>> {
    trace!("scope_identifiers");

    let Some(scope) = &request.scope else {
        return Ok(vec![]);
    };
    let mut cfg_ids = vec![];

    for item in scope.split_whitespace().collect::<Vec<&str>>() {
        for (id, cred) in &issuer_meta.credential_configurations_supported {
            if cred.scope == Some(item.to_string()) {
                cfg_ids.push(id.to_owned());
            }
        }
    }

    Ok(cfg_ids)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;

    use super::*;

    #[tokio::test]
    async fn authzn_details() {
        test_utils::init_tracer();

        let provider = Provider::new();

        let auth_dets = json!([{
            "type": "openid_credential",
            "format": "jwt_vc_json",
            "credential_definition": {
                "context": [
                    "https://www.w3.org/2018/credentials/v1",
                    "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ],
                "credential_subject": {}
            }
        }])
        .to_string();

        let verifier_hash = Sha256::digest("ABCDEF12345");

        // create request
        let body = json!({
            "response_type": "code",
            "client_id": wallet::did(),
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
            "code_challenge_method": "S256",
            "authorization_details": auth_dets,
            "holder_id": NORMAL_USER,
            "wallet_issuer": ISSUER,
            "callback_id": "1234"
        });
        let mut request =
            serde_json::from_value::<AuthorizationRequest>(body).expect("should deserialize");
        request.credential_issuer = ISSUER.to_string();

        let response =
            Endpoint::new(provider.clone()).authorize(&request).await.expect("response is ok");

        assert_snapshot!("authzn-ok", response, {
            ".code" => "[code]",
        });

        // compare response with saved state
        let buf = StateManager::get(&provider, &response.code).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("authzn-state", state, {
            ".expires_at" => "[expires_at]",
            ".auth.code" => "[code]",
            ".auth.code_challenge" => "[code_challenge]",
        });
    }

    #[tokio::test]
    async fn scope() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let verifier_hash = Sha256::digest("ABCDEF12345");

        // create request
        let body = json!({
            "response_type": "code",
            "client_id": wallet::did(),
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
            "code_challenge_method": "S256",
            "scope": "EmployeeIDCredential",
            "holder_id": NORMAL_USER,
            "wallet_issuer": ISSUER,
            "callback_id": "1234"
        });
        let mut request =
            serde_json::from_value::<AuthorizationRequest>(body).expect("should deserialize");
        request.credential_issuer = ISSUER.to_string();

        let response =
            Endpoint::new(provider.clone()).authorize(&request).await.expect("response is ok");
        assert_snapshot!("scope-ok", response, {
            ".code" => "[code]",
        });

        // compare response with saved state
        let buf = StateManager::get(&provider, &response.code).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("scope-state", state, {
            ".expires_at" => "[expires_at]",
            ".auth.code" => "[code]",
            ".auth.code_challenge" => "[code_challenge]",
        });
    }
}
