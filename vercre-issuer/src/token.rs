//! # Token Endpoint
//!
//! The Token Endpoint issues an Access Token and, optionally, a Refresh Token in
//! exchange for the Authorization Code that client obtained in a successful
//! Authorization Response. It is used in the same manner as defined in
//! [RFC6749](https://tools.ietf.org/html/rfc6749#section-5.1) and follows the
//! recommendations given in [I-D.ietf-oauth-security-topics].
//!
//! The authorization server MUST include the HTTP "Cache-Control" response header
//! field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-store" in any response containing tokens,
//! credentials, or other sensitive information, as well as the "Pragma" response
//! header field [RFC2616](https://www.rfc-editor.org/rfc/rfc2616) with a value of "no-cache".

use std::fmt::Debug;

use base64ct::{Base64UrlUnpadded, Encoding};
use core_utils::gen;
use openid::issuer::{
    GrantType, Provider, ServerMetadata, StateManager, TokenRequest, TokenResponse, TokenType,
};
use openid::{Error, Result};
use sha2::{Digest, Sha256};
use tracing::instrument;

// use crate::shell;
use crate::state::{Expire, State, Token};

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn token(provider: impl Provider, request: &TokenRequest) -> Result<TokenResponse> {
    // restore state
    // RFC 6749 requires a particular error here
    let Ok(buf) = StateManager::get(&provider, &auth_state_key(request)?).await else {
        return Err(Error::InvalidGrant("the authorization code is invalid".into()));
    };
    let Ok(state) = State::try_from(buf.as_slice()) else {
        return Err(Error::InvalidGrant("the authorization code has expired".into()));
    };

    let ctx = Context { state };

    verify(&ctx, provider.clone(), request).await?;
    process(&ctx, provider, request).await
}

#[derive(Debug)]
struct Context {
    state: State,
}

// Verify the token request.
async fn verify(context: &Context, provider: impl Provider, request: &TokenRequest) -> Result<()> {
    tracing::debug!("Context::verify");

    let Ok(server_meta) = ServerMetadata::metadata(&provider, &request.credential_issuer).await
    else {
        return Err(Error::InvalidRequest("unknown authorization server".into()));
    };
    let Some(auth_state) = &context.state.auth else {
        return Err(Error::ServerError("Authorization state not set".into()));
    };

    // grant_type
    match request.grant_type {
        GrantType::AuthorizationCode => {
            // client_id is the same as the one used to obtain the authorization code
            if Some(&request.client_id) != context.state.client_id.as_ref() {
                return Err(Error::InvalidGrant("client_id differs from authorized one".into()));
            }

            // redirect_uri is the same as the one provided in authorization request
            // i.e. either 'None' or 'Some(redirect_uri)'
            if request.redirect_uri != auth_state.redirect_uri {
                return Err(Error::InvalidGrant("redirect_uri differs from authorized one".into()));
            }

            // code_verifier
            let Some(verifier) = &request.code_verifier else {
                return Err(Error::AccessDenied("code_verifier is missing".into()));
            };

            // code_verifier matches code_challenge
            let hash = Sha256::digest(verifier);
            let challenge = Base64UrlUnpadded::encode_string(&hash);

            if Some(&challenge) != auth_state.code_challenge.as_ref() {
                return Err(Error::AccessDenied("code_verifier is invalid".into()));
            }
        }
        GrantType::PreAuthorizedCode => {
            // anonymous access allowed?
            if request.client_id.is_empty()
                && !server_meta.pre_authorized_grant_anonymous_access_supported
            {
                return Err(Error::InvalidClient("anonymous access is not supported".into()));
            }
            // user_code
            if request.user_code != auth_state.user_code {
                return Err(Error::InvalidGrant("invalid user_code provided".into()));
            }
        }
    }

    Ok(())
}

/// Exchange auth code (authorization or pre-authorized) for access token,
/// updating state along the way.
async fn process(
    context: &Context, provider: impl Provider, request: &TokenRequest,
) -> Result<TokenResponse> {
    tracing::debug!("Context::process");

    // prevent auth code reuse
    StateManager::purge(&provider, &auth_state_key(request)?)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    // copy existing state for token state
    let mut state = context.state.clone();

    // get auth state to return `authorization_details` and `scope`
    let Some(auth_state) = state.auth else {
        return Err(Error::ServerError("Auth state not set".into()));
    };
    state.auth = None;

    let token = gen::token();
    let c_nonce = gen::nonce();

    state.token = Some(
        Token::builder()
            .access_token(token.clone())
            .c_nonce(c_nonce.clone())
            .build()
            .map_err(|e| Error::ServerError(format!("issue building token state: {e}")))?,
    );
    StateManager::put(&provider, &token, state.to_vec(), state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(TokenResponse {
        access_token: token,
        token_type: TokenType::Bearer,
        expires_in: Expire::Access.duration().num_seconds(),
        c_nonce: Some(c_nonce),
        c_nonce_expires_in: Some(Expire::Nonce.duration().num_seconds()),
        authorization_details: auth_state.authorization_details.clone(),
        scope: auth_state.scope.clone(),
    })
}

// Helper to get correct authorization state key from request.
// Authorization state is stored by either 'code' or 'pre_authorized_code',
// depending on grant_type.
fn auth_state_key(request: &TokenRequest) -> Result<String> {
    let state_key = match request.grant_type {
        GrantType::AuthorizationCode => request.code.as_ref(),
        GrantType::PreAuthorizedCode => request.pre_authorized_code.as_ref(),
    };
    let Some(state_key) = state_key else {
        return Err(Error::InvalidRequest("missing state key".into()));
    };
    Ok(state_key.to_string())
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use openid::issuer::{
        AuthorizationDetail, AuthorizationDetailType, CredentialDefinition, CredentialType,
        TokenAuthorizationDetail,
    };
    use openid::CredentialFormat;
    use serde_json::json;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

    use super::*;
    use crate::state::Auth;

    #[tokio::test]
    async fn simple_tossken() {
        test_utils::init_tracer();

        let provider = Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".into()];

        let mut state = State::builder()
            .credential_issuer(CREDENTIAL_ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .subject_id(Some(NORMAL_USER.to_string()))
            .build()
            .expect("should build state");

        let pre_auth_code = "ABCDEF";

        state.auth = Some(Auth {
            user_code: Some("1234".into()),
            ..Default::default()
        });

        StateManager::put(&provider, pre_auth_code, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "user_code": "1234"
        });

        let mut request =
            serde_json::from_value::<TokenRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();
        let response = token(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("simpl-token", &response, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // auth state should be removed
        assert!(StateManager::get(&provider, pre_auth_code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateManager::get(&provider, &response.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        // compare response with saved state
        assert_let!(Some(token_state), &state.token);
        assert_eq!(token_state.c_nonce, response.c_nonce.unwrap_or_default());
    }

    #[tokio::test]
    async fn authzn_token() {
        test_utils::init_tracer();

        let provider = Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".into()];

        let mut state = State::builder()
            .credential_issuer(CREDENTIAL_ISSUER.to_string())
            .client_id(CLIENT_ID)
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .subject_id(Some(NORMAL_USER.to_string()))
            .build()
            .expect("should build state");

        let auth_code = "ABCDEF";
        let verifier = "ABCDEF12345";
        let verifier_hash = Sha256::digest(verifier);

        state.auth = Some(Auth {
            redirect_uri: Some("https://example.com".into()),
            code_challenge: Some(Base64UrlUnpadded::encode_string(&verifier_hash)),
            code_challenge_method: Some("S256".into()),
            authorization_details: Some(vec![TokenAuthorizationDetail {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential_type: CredentialType::Format(CredentialFormat::JwtVcJson),
                    credential_definition: Some(CredentialDefinition {
                        type_: Some(vec![
                            "VerifiableCredential".into(),
                            "EmployeeIDCredential".into(),
                        ]),
                        credential_subject: None,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                credential_identifiers: Some(vec!["EmployeeID_JWT".into()]),
            }]),
            ..Default::default()
        });

        StateManager::put(&provider, auth_code, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com",
        });

        let mut request =
            serde_json::from_value::<TokenRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();
        let response = token(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("authzn-token", &response, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // auth state should be removed
        assert!(StateManager::get(&provider, auth_code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateManager::get(&provider, &response.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        // compare response with saved state
        assert_let!(Some(token_state), &state.token);
        assert_eq!(token_state.c_nonce, response.c_nonce.unwrap_or_default());
    }
}
