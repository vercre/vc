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
// TODO: implement `Interval` and `SlowDown` checks/errors

use std::collections::HashMap;
use std::fmt::Debug;
use std::vec;

use chrono::Utc;
use core_utils::gen;
use openid::endpoint::{
    ClientMetadata, IssuerMetadata, IssuerProvider, ServerMetadata, StateManager, Subject,
};
use openid::issuer::{
    AuthorizationDetail, AuthorizationDetailType, AuthorizationRequest, AuthorizationResponse,
    GrantType, Issuer, TokenAuthorizationDetail,
};
use openid::{Error, Result};
use tracing::instrument;

// use crate::shell;
use crate::state::{Auth, Expire, State};

/// Authorization request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn authorize(
    provider: impl IssuerProvider, request: &AuthorizationRequest,
) -> Result<AuthorizationResponse> {
    let issuer_meta = IssuerMetadata::metadata(&provider, &request.credential_issuer)
        .await
        .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?;

    let mut ctx = Context {
        issuer_meta,
        auth_dets: HashMap::new(),
        scope_items: HashMap::new(),
    };

    // shell(&mut ctx, provider.clone(), request, verify).await?;
    // shell(&mut ctx, provider, request, process).await
    verify(&mut ctx, provider.clone(), request).await?;
    process(&ctx, provider, request).await
}

#[derive(Debug)]
struct Context {
    issuer_meta: Issuer,
    auth_dets: HashMap<String, AuthorizationDetail>,
    scope_items: HashMap<String, String>,
}

async fn verify(
    context: &mut Context, provider: impl IssuerProvider, request: &AuthorizationRequest,
) -> Result<()> {
    tracing::debug!("Context::verify");

    let Ok(client_config) = ClientMetadata::metadata(&provider, &request.client_id).await else {
        return Err(Error::InvalidClient("invalid client_id".into()));
    };
    let server_config = ServerMetadata::metadata(&provider, &request.credential_issuer)
        .await
        .map_err(|e| Error::ServerError(format!("metadata issue: {e}")))?;

    // 'authorization_code' grant_type allowed (client and server)?
    let client_grant_types = client_config.grant_types.unwrap_or_default();
    if !client_grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Error::InvalidRequest(
            "authorization_code grant not supported for client".into(),
        ));
    }
    let server_grant_types = server_config.grant_types_supported.unwrap_or_default();
    if !server_grant_types.contains(&GrantType::AuthorizationCode) {
        return Err(Error::InvalidRequest(
            "authorization_code grant not supported for server".into(),
        ));
    }

    // is holder identified (authenticated)?
    if request.subject_id.is_empty() {
        return Err(Error::AuthorizationPending("missing holder subject".into()));
    }

    // has a credential been requested?
    if request.authorization_details.is_none() && request.scope.is_none() {
        return Err(Error::InvalidRequest("no credentials requested".into()));
    }

    // verify authorization_details
    if let Some(authorization_details) = &request.authorization_details {
        verify_authorization_details(context, authorization_details)?;
    }
    // verify scope
    if let Some(scope) = &request.scope {
        verify_scope(context, scope)?;
    }

    // redirect_uri
    let Some(redirect_uri) = &request.redirect_uri else {
        return Err(Error::InvalidRequest("no redirect_uri specified".into()));
    };
    let Some(redirect_uris) = client_config.redirect_uris else {
        return Err(Error::InvalidRequest("no redirect_uris specified for client".into()));
    };
    if !redirect_uris.contains(redirect_uri) {
        return Err(Error::InvalidRequest("request redirect_uri is not registered".into()));
    }

    // response_type
    if !client_config.response_types.unwrap_or_default().contains(&request.response_type) {
        return Err(Error::UnsupportedResponseType(
            "the response_type not supported by client".into(),
        ));
    }
    if !server_config.response_types_supported.contains(&request.response_type) {
        return Err(Error::UnsupportedResponseType("response_type not supported by server".into()));
    }

    // code_challenge
    // N.B. while optional in the spec, we require it
    let challenge_methods = server_config.code_challenge_methods_supported.unwrap_or_default();
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

// Authorize Wallet request:
// - check which requested `credential_configuration_id`s the holder is
//   authorized for
// - save related auth_dets/scope items in state
async fn process(
    context: &Context, provider: impl IssuerProvider, request: &AuthorizationRequest,
) -> Result<AuthorizationResponse> {
    tracing::debug!("Context::process");

    let mut authzd_auth_dets = vec![];
    let mut authzd_cfg_ids = vec![];

    // check which requested `authorization_detail` entries the holder is authorized for
    for (cfg_id, auth_det) in &context.auth_dets {
        let auth = Subject::authorize(&provider, &request.subject_id, cfg_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue authorizing holder: {e}")))?;
        if auth {
            let tkn_auth_det = TokenAuthorizationDetail {
                authorization_detail: auth_det.clone(),
                credential_identifiers: None,
            };
            authzd_auth_dets.push(tkn_auth_det.clone());
            authzd_cfg_ids.push(cfg_id.clone());
        }
    }
    let auth_dets = if authzd_auth_dets.is_empty() {
        None
    } else {
        Some(authzd_auth_dets)
    };

    let mut authzd_scope_items = vec![];

    // check which requested `scope` items the holder is authorized for
    for (cfg_id, item) in &context.scope_items {
        let auth = Subject::authorize(&provider, &request.subject_id, cfg_id)
            .await
            .map_err(|e| Error::ServerError(format!("issue authorizing holder: {e}")))?;
        if auth {
            authzd_scope_items.push(item.clone());
            authzd_cfg_ids.push(cfg_id.clone());
        }
    }
    let scope = if authzd_scope_items.is_empty() {
        None
    } else {
        Some(authzd_scope_items.join(" "))
    };

    // error if holder is not authorized for any requested credentials
    if auth_dets.is_none() && scope.is_none() {
        return Err(Error::AccessDenied(
            "holder is not authorized for requested credentials".into(),
        ));
    }

    // save authorization state
    let mut state = State {
        expires_at: Utc::now() + Expire::AuthCode.duration(),
        credential_issuer: request.credential_issuer.clone(),
        client_id: Some(request.client_id.clone()),
        credential_configuration_ids: authzd_cfg_ids,
        subject_id: Some(request.subject_id.clone()),
        ..State::default()
    };

    let auth_state = Auth {
        redirect_uri: request.redirect_uri.clone(),
        code_challenge: Some(request.code_challenge.clone()),
        code_challenge_method: Some(request.code_challenge_method.clone()),
        authorization_details: auth_dets,
        scope,
        ..Auth::default()
    };
    state.auth = Some(auth_state);

    let code = gen::auth_code();
    StateManager::put(&provider, &code, state.to_vec(), state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;

    // remove offer state
    if let Some(issuer_state) = &request.issuer_state {
        StateManager::purge(&provider, issuer_state)
            .await
            .map_err(|e| Error::ServerError(format!("state issue: {e}")))?;
    }

    Ok(AuthorizationResponse {
        code,
        state: request.state.clone(),
        redirect_uri: request.redirect_uri.clone().unwrap_or_default(),
    })
}

// Verify Credentials requested in `authorization_details` are supported.
//
// N.B. has side effect of saving valid `authorization_detail` objects into context
// for later use.
fn verify_authorization_details(
    context: &mut Context, authorization_details: &[AuthorizationDetail],
) -> Result<()> {
    'verify_details: for auth_det in authorization_details {
        // we only support "`openid_credential`" authorization detail requests
        if auth_det.type_ != AuthorizationDetailType::OpenIdCredential {
            return Err(Error::InvalidRequest("invalid authorization_details type".into()));
        }

        let cfg_id_opt = &auth_det.credential_configuration_id;
        let format_opt = &auth_det.format;

        // verify that only one of `credential_configuration_id` or `format` is specified
        if cfg_id_opt.is_some() && format_opt.is_some() {
            return Err(Error::InvalidRequest(
                "'credential_configuration_id and format cannot both be set".into(),
            ));
        }
        if cfg_id_opt.is_none() && format_opt.is_none() {
            return Err(Error::InvalidRequest(
                "credential_configuration_id or format must be set".into(),
            ));
        }

        // EITHER: verify requested `credential_configuration_id` is supported
        if let Some(cfg_id) = cfg_id_opt {
            if !context.issuer_meta.credential_configurations_supported.contains_key(cfg_id) {
                return Err(Error::InvalidRequest(
                    "unsupported credential_configuration_id".into(),
                ));
            }

            // save auth_det by `credential_configuration_id` for later use
            context.auth_dets.insert(cfg_id.clone(), auth_det.clone());
            continue 'verify_details;
        }

        // OR: verify requested `format` and `type` are supported
        if let Some(format) = format_opt {
            let Some(auth_def) = auth_det.credential_definition.as_ref() else {
                return Err(Error::InvalidRequest("no `credential_definition` specified".into()));
            };

            // find matching `CredentialConfiguration`
            for (cfg_id, cred_cfg) in &context.issuer_meta.credential_configurations_supported {
                if &cred_cfg.format == format
                    && cred_cfg.credential_definition.type_ == auth_def.type_
                {
                    // save auth_det by `credential_configuration_id` for later use
                    context.auth_dets.insert(cfg_id.to_string(), auth_det.clone());
                    continue 'verify_details;
                }
            }

            // no matching credential_configuration
            return Err(Error::InvalidRequest("unsupported credential `format` or `type`".into()));
        }
    }

    Ok(())
}

// Verify Credentials requested in `scope` are supported.
//
// N.B. has side effect of saving valid scope items into context for later use.
fn verify_scope(context: &mut Context, scope: &str) -> Result<()> {
    'verify_scope: for item in scope.split_whitespace() {
        for (cfg_id, cred_cfg) in &context.issuer_meta.credential_configurations_supported {
            // `authorization_details` credential request  takes precedence `scope` request
            if context.auth_dets.contains_key(cfg_id) {
                continue;
            }

            if cred_cfg.scope == Some(item.to_string()) {
                // save scope item by `credential_configuration_id` for later use
                context.scope_items.insert(cfg_id.to_string(), item.to_string());
                continue 'verify_scope;
            }
        }
        return Err(Error::InvalidRequest("scope item {item} is unsupported".into()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

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
                "credentialSubject": {}
            }
        }])
        .to_string();

        let verifier_hash = Sha256::digest("ABCDEF12345");

        // create request
        let body = json!({
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
            "code_challenge_method": "S256",
            "authorization_details": auth_dets,
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER,
            "callback_id": "1234"
        });
        let mut request =
            serde_json::from_value::<AuthorizationRequest>(body).expect("should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();

        let response = authorize(provider.clone(), &request).await.expect("response is ok");

        assert_snapshot!("authzn-ok", &response, {
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
            "client_id": CLIENT_ID,
            "redirect_uri": "http://localhost:3000/callback",
            "state": "1234",
            "code_challenge": Base64UrlUnpadded::encode_string(&verifier_hash),
            "code_challenge_method": "S256",
            "scope": "EmployeeIDCredential",
            "subject_id": NORMAL_USER,
            "wallet_issuer": CREDENTIAL_ISSUER,
            "callback_id": "1234"
        });
        let mut request =
            serde_json::from_value::<AuthorizationRequest>(body).expect("should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();

        let response = authorize(provider.clone(), &request).await.expect("response is ok");
        assert_snapshot!("scope-ok", &response, {
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
