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
use crate::state::{Expire, State, Step, Token};

/// Token request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn token(provider: impl Provider, request: &TokenRequest) -> Result<TokenResponse> {
    // restore state
    let state_key = match &request.grant_type {
        TokenGrantType::AuthorizationCode { code, .. } => code,
        TokenGrantType::PreAuthorizedCode {
            pre_authorized_code, ..
        } => pre_authorized_code,
    };

    // RFC 6749 requires a particular error here
    let Ok(buf) = StateStore::get(&provider, state_key).await else {
        return Err(Error::InvalidGrant("the authorization code is invalid".into()));
    };
    let Ok(state) = State::try_from(buf.as_slice()) else {
        return Err(Error::InvalidGrant("the authorization code has expired".into()));
    };

    let ctx = Context { state };

    ctx.verify(&provider, request).await?;
    ctx.process(&provider, request).await
}

#[derive(Debug)]
struct Context {
    state: State,
}

impl Context {
    // Verify the token request.
    async fn verify(&self, provider: &impl Provider, request: &TokenRequest) -> Result<()> {
        tracing::debug!("token::verify");

        let Ok(server_meta) = Metadata::server(provider, &request.credential_issuer).await else {
            return Err(Error::InvalidRequest("unknown authorization server".into()));
        };

        // grant_type
        match &request.grant_type {
            TokenGrantType::AuthorizationCode {
                redirect_uri,
                code_verifier,
                ..
            } => {
                let Step::Authorization(auth_state) = &self.state.current_step else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };

                // client_id is the same as the one used to obtain the authorization code
                if request.client_id != auth_state.client_id {
                    return Err(Error::InvalidGrant(
                        "client_id differs from authorized one".into(),
                    ));
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if redirect_uri != &auth_state.redirect_uri {
                    return Err(Error::InvalidGrant(
                        "redirect_uri differs from authorized one".into(),
                    ));
                }

                // code_verifier
                let Some(verifier) = &code_verifier else {
                    return Err(Error::AccessDenied("code_verifier is missing".into()));
                };

                // code_verifier matches code_challenge
                let hash = Sha256::digest(verifier);
                let challenge = Base64UrlUnpadded::encode_string(&hash);

                if challenge != auth_state.code_challenge {
                    return Err(Error::AccessDenied("code_verifier is invalid".into()));
                }
            }
            TokenGrantType::PreAuthorizedCode { tx_code, .. } => {
                let Step::PreAuthorized(auth_state) = &self.state.current_step else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };

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

    /// Exchange `auth_code` code (authorization or pre-authorized) for access token,
    /// updating state along the way.
    async fn process(
        &self, provider: &impl Provider, request: &TokenRequest,
    ) -> Result<TokenResponse> {
        tracing::debug!("token::process");

        let (subject_id, authorized, scope, state_key) = match &request.grant_type {
            TokenGrantType::AuthorizationCode { code, .. } => {
                let Step::Authorization(auth_state) = &self.state.current_step else {
                    return Err(Error::ServerError("authorization state not set".into()));
                };
                (
                    auth_state.subject_id.clone(),
                    auth_state.authorized.clone(),
                    auth_state.scope.clone(),
                    code,
                )
            }
            TokenGrantType::PreAuthorizedCode {
                pre_authorized_code, ..
            } => {
                let Step::PreAuthorized(auth_state) = &self.state.current_step else {
                    return Err(Error::ServerError("pre-authorized state not set".into()));
                };
                (
                    auth_state.subject_id.clone(),
                    Some(auth_state.authorized.clone()),
                    None,
                    pre_authorized_code,
                )
            }
        };

        // prevent `auth_code` code reuse
        StateStore::purge(provider, state_key)
            .await
            .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

        let access_token = gen::token();
        let c_nonce = gen::nonce();

        let mut state = self.state.clone();
        state.current_step = Step::Token(Token {
            access_token: access_token.clone(),
            c_nonce: c_nonce.clone(),
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            subject_id,
            authorized: authorized.clone(),
            scope: scope.clone(),
        });
        StateStore::put(provider, &access_token, state.to_vec()?, state.expires_at)
            .await
            .map_err(|e| Error::ServerError(format!("issue saving state: {e}")))?;

        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer,
            expires_in: Expire::Access.duration().num_seconds(),
            c_nonce: Some(c_nonce),
            c_nonce_expires_in: Some(Expire::Nonce.duration().num_seconds()),
            authorization_details: authorized,
            scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_openid::issuer::{
        AuthorizationDetail, AuthorizationDetailType, Authorized, CredentialDefinition,
        CredentialType,
    };
    use vercre_openid::CredentialFormat;
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::snapshot;

    use super::*;
    use crate::state::{Authorization, PreAuthorized};

    #[tokio::test]
    async fn pre_authorized() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();

        // set up PreAuthorized state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            current_step: Step::PreAuthorized(PreAuthorized {
                subject_id: NORMAL_USER.into(),
                authorized: vec![Authorized {
                    authorization_detail: AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential_type: CredentialType::ConfigurationId("EmployeeID_JWT".into()),
                        ..AuthorizationDetail::default()
                    },
                    credential_identifiers: vec!["PHLEmployeeID".into()],
                }],
                tx_code: Some("1234".into()),
            }),
            ..State::default()
        };

        let pre_auth_code = "ABCDEF";

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, pre_auth_code, ser, state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "tx_code": "1234"
        });

        let request =
            serde_json::from_value::<TokenRequest>(value).expect("request should deserialize");
        let token_resp = token(provider.clone(), &request).await.expect("response is valid");

        assert_snapshot!("token:pre_authorized:response", &token_resp, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // pre-authorized state should be removed
        assert!(StateStore::get(&provider, pre_auth_code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateStore::get(&provider, &token_resp.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_snapshot!("token:pre_authorized:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.access_token" => "[access_token]",
            ".current_step.c_nonce" => "[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }

    #[tokio::test]
    async fn authorization() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            current_step: Step::Authorization(Authorization {
                code_challenge: Base64UrlUnpadded::encode_string(&Sha256::digest(verifier)),
                code_challenge_method: "S256".into(),

                subject_id: NORMAL_USER.into(),
                authorized: Some(vec![Authorized {
                    authorization_detail: AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential_type: CredentialType::ConfigurationId("EmployeeID_JWT".into()),
                        ..AuthorizationDetail::default()
                    },
                    credential_identifiers: vec!["PHLEmployeeID".into()],
                }]),
                client_id: CLIENT_ID.into(),
                ..Authorization::default()
            }),
            ..State::default()
        };

        let code = "ABCDEF";

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, code, ser, state.expires_at).await.expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
        });

        let request =
            serde_json::from_value::<TokenRequest>(value).expect("request should deserialize");
        let token_resp = token(provider.clone(), &request).await.expect("response is valid");

        assert_snapshot!("token:authorization:response", &token_resp, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // authorization state should be removed
        assert!(StateStore::get(&provider, code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateStore::get(&provider, &token_resp.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_snapshot!("token:authorization:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.access_token" => "[access_token]",
            ".current_step.c_nonce" => "[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }

    #[tokio::test]
    async fn authorization_details() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let verifier = "ABCDEF12345";

        // set up Authorization state
        let state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            current_step: Step::Authorization(Authorization {
                client_id: CLIENT_ID.into(),
                redirect_uri: Some("https://example.com".into()),
                code_challenge: Base64UrlUnpadded::encode_string(&Sha256::digest(verifier)),
                code_challenge_method: "S256".into(),
                subject_id: NORMAL_USER.into(),
                authorized: Some(vec![Authorized {
                    authorization_detail: AuthorizationDetail {
                        type_: AuthorizationDetailType::OpenIdCredential,
                        credential_type: CredentialType::Format(CredentialFormat::JwtVcJson),
                        credential_definition: Some(CredentialDefinition {
                            type_: Some(vec![
                                "VerifiableCredential".into(),
                                "EmployeeIDCredential".into(),
                            ]),
                            credential_subject: None,
                            ..CredentialDefinition::default()
                        }),
                        ..AuthorizationDetail::default()
                    },
                    credential_identifiers: vec!["EmployeeID_JWT".into()],
                }]),
                ..Authorization::default()
            }),
            ..State::default()
        };

        let code = "ABCDEF";

        let ser = state.to_vec().expect("should serialize");
        StateStore::put(&provider, code, ser, state.expires_at).await.expect("state exists");

        // create TokenRequest to 'send' to the app
        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "client_id": CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com",
        });

        let request =
            serde_json::from_value::<TokenRequest>(value).expect("request should deserialize");
        let response = token(provider.clone(), &request).await.expect("response is valid");

        assert_snapshot!("token:authorization_details:response", &response, {
            ".access_token" => "[access_token]",
            ".c_nonce" => "[c_nonce]"
        });

        // auth_code state should be removed
        assert!(StateStore::get(&provider, code).await.is_err());

        // should be able to retrieve state using access token
        let buf = StateStore::get(&provider, &response.access_token).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_snapshot!("token:authorization_details:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.access_token" => "[access_token]",
            ".current_step.c_nonce" => "[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]",
        });
    }
}
