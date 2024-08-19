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

// TODO: test `credential_configuration_id` in `authorization_details`
// TODO: analyse `credential_identifiers` use in `authorization_details`
// TODO: verify `client_assertion` JWT, when set

use std::fmt::Debug;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::Utc;
use sha2::{Digest, Sha256};
use tracing::instrument;
use vercre_core::gen;
use vercre_openid::issuer::{
    Metadata, Provider, StateStore, TokenGrantType, TokenRequest, TokenResponse, TokenType,
};
use vercre_openid::{Error, Result};

// use crate::shell;
use crate::state::{Expire, Flow, State, Token};

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
    let Ok(buf) = StateStore::get(&provider, &auth_state_key(request)).await else {
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
    tracing::debug!("token::verify");

    let Ok(server_meta) = Metadata::server(&provider, &request.credential_issuer).await else {
        return Err(Error::InvalidRequest("unknown authorization server".into()));
    };
    let Flow::AuthCode(auth_state) = &context.state.flow else {
        return Err(Error::ServerError("authorization state not set".into()));
    };

    // grant_type
    match &request.grant_type {
        TokenGrantType::AuthorizationCode {
            redirect_uri,
            code_verifier,
            ..
        } => {
            // client_id is the same as the one used to obtain the authorization code
            if Some(&request.client_id) != context.state.client_id.as_ref() {
                return Err(Error::InvalidGrant("client_id differs from authorized one".into()));
            }

            // redirect_uri is the same as the one provided in authorization request
            // i.e. either 'None' or 'Some(redirect_uri)'
            if redirect_uri != &auth_state.redirect_uri {
                return Err(Error::InvalidGrant("redirect_uri differs from authorized one".into()));
            }

            // code_verifier
            let Some(verifier) = &code_verifier else {
                return Err(Error::AccessDenied("code_verifier is missing".into()));
            };

            // code_verifier matches code_challenge
            let hash = Sha256::digest(verifier);
            let challenge = Base64UrlUnpadded::encode_string(&hash);

            if Some(&challenge) != auth_state.code_challenge.as_ref() {
                return Err(Error::AccessDenied("code_verifier is invalid".into()));
            }
        }
        TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
            // anonymous access allowed?
            if request.client_id.is_empty()
                && !server_meta.pre_authorized_grant_anonymous_access_supported
            {
                return Err(Error::InvalidClient("anonymous access is not supported".into()));
            }
            // tx_code
            if tx_code != &auth_state.tx_code {
                return Err(Error::InvalidGrant("invalid tx_code provided".into()));
            }
        }
    }

    Ok(())
}

/// Exchange auth_code code (authorization or pre-authorized) for access token,
/// updating state along the way.
async fn process(
    context: &Context, provider: impl Provider, request: &TokenRequest,
) -> Result<TokenResponse> {
    tracing::debug!("token::process");

    // prevent auth_code code reuse
    StateStore::purge(&provider, &auth_state_key(request))
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    // copy existing state for token state
    let mut state = context.state.clone();

    // get auth_code state to return `authorization_details` and `scope`
    let Flow::AuthCode(auth_state) = state.flow else {
        return Err(Error::ServerError("AuthCode state not set".into()));
    };

    let access_token = gen::token();
    let c_nonce = gen::nonce();

    state.flow = Flow::Token(Token {
        access_token: access_token.clone(),
        c_nonce: c_nonce.clone(),
        c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
        ..Token::default()
    });
    StateStore::put(&provider, &access_token, state.to_vec()?, state.expires_at)
        .await
        .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

    Ok(TokenResponse {
        access_token,
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
fn auth_state_key(request: &TokenRequest) -> String {
    let state_key = match &request.grant_type {
        TokenGrantType::AuthorizationCode { code, .. } => code,
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => pre_authorized_code,
    };
    state_key.to_string()
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_openid::issuer::{
        AuthorizationCredential, AuthorizationDetail, AuthorizationDetailType,
        CredentialDefinition, TokenAuthorizationDetail,
    };
    use vercre_openid::CredentialFormat;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

    use super::*;
    use crate::state::AuthCode;

    #[tokio::test]
    async fn simple_token() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".into()];

        let mut state = State {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            expires_at: Utc::now() + Expire::AuthCode.duration(),
            credential_identifiers: credentials,
            subject_id: Some(NORMAL_USER.into()),
            ..State::default()
        };

        let pre_auth_code = "ABCDEF";

        state.flow = Flow::AuthCode(AuthCode {
            tx_code: Some("1234".into()),
            ..Default::default()
        });

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, pre_auth_code, ser, state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "tx_code": "1234"
        });

        let mut request =
            serde_json::from_value::<TokenRequest>(body).expect("request should deserialize");
        request.credential_issuer = CREDENTIAL_ISSUER.to_string();

        let token_resp = token(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("simple-token", &token_resp, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // auth_code state should be removed
        assert!(StateStore::get(&provider, pre_auth_code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateStore::get(&provider, &token_resp.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        // compare response with saved state
        assert_let!(Flow::Token(token_state), &state.flow);
        assert_eq!(token_state.c_nonce, token_resp.c_nonce.unwrap_or_default());
    }

    #[tokio::test]
    async fn authzn_token() {
        vercre_test_utils::init_tracer();

        let provider = Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".into()];

        let mut state = State {
            credential_issuer: CREDENTIAL_ISSUER.to_string(),
            client_id: Some(CLIENT_ID.into()),
            expires_at: Utc::now() + Expire::AuthCode.duration(),
            credential_identifiers: credentials,
            subject_id: Some(NORMAL_USER.into()),
            ..State::default()
        };

        let auth_code = "ABCDEF";
        let verifier = "ABCDEF12345";
        let verifier_hash = Sha256::digest(verifier);

        state.flow = Flow::AuthCode(AuthCode {
            redirect_uri: Some("https://example.com".into()),
            code_challenge: Some(Base64UrlUnpadded::encode_string(&verifier_hash)),
            code_challenge_method: Some("S256".into()),
            authorization_details: Some(vec![TokenAuthorizationDetail {
                authorization_detail: AuthorizationDetail {
                    type_: AuthorizationDetailType::OpenIdCredential,
                    credential_identifier: AuthorizationCredential::Format(
                        CredentialFormat::JwtVcJson,
                    ),
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

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, auth_code, ser, state.expires_at).await.expect("state exists");

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

        // auth_code state should be removed
        assert!(StateStore::get(&provider, auth_code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateStore::get(&provider, &response.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        // compare response with saved state
        assert_let!(Flow::Token(token_state), &state.flow);
        assert_eq!(token_state.c_nonce, response.c_nonce.unwrap_or_default());
    }
}
