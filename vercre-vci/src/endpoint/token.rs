//! # Token Handler
//!
//! The Token Handler issues an Access Token and, optionally, a Refresh Token in
//! exchange for the Authorization Code that client obtained in a successful
//! Authorization Response. It is used in the same manner as defined in
//! [RFC6749] and follows the recommendations given in [I-D.ietf-oauth-security-topics].

use std::fmt::Debug;

use anyhow::anyhow;
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest, Sha256};
use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::metadata::{AUTH_CODE_GRANT_TYPE, PRE_AUTH_GRANT_TYPE};
// use vercre_core::metadata::{ClientMetadata, IssuerMetadata, ServerMetadata};
use vercre_core::vci::{TokenRequest, TokenResponse};
use vercre_core::{
    err, gen, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager,
};

use super::Handler;
use crate::state::{Expire, State, TokenState};

/// Token request handler.
impl<P> Handler<P, TokenRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<TokenResponse> {
        trace!("Handler::call");
        self.handle_request(Context::new()).await
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Server + StateManager,
{
    provider: Option<P>,
    state: Option<State>,
}

impl<P> Context<P>
where
    P: Server + StateManager,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");
        Self {
            provider: None,
            state: None,
        }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Server + StateManager + Debug,
{
    type Provider = P;
    type Request = TokenRequest;
    type Response = TokenResponse;

    #[instrument]
    async fn init(&mut self, req: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        // restore state
        // RFC 6749 requires a particular error here
        let Ok(buf) = StateManager::get(&provider, &auth_state_key(req)?).await else {
            err!(Err::InvalidGrant, "The authorization code is invalid");
        };
        let Ok(state) = State::try_from(buf.as_slice()) else {
            err!(Err::InvalidGrant, "The authorization code has expired");
        };
        self.state = Some(state);

        self.provider = Some(provider);

        Ok(self)
    }

    fn callback_id(&self) -> Option<String> {
        if let Some(state) = &self.state {
            return state.callback_id.clone();
        }
        None
    }

    /// Verify the token request.
    #[instrument]
    async fn verify(&self, req: &Self::Request) -> Result<&Self> {
        trace!("Context::verify");

        let Some(provider) = &self.provider else {
            err!("Provider not set");
        };

        let Ok(server_meta) = Server::metadata(provider, &req.credential_issuer).await else {
            err!(Err::InvalidRequest, "Unknown authorization server");
        };
        let Some(state) = &self.state else {
            err!("State not set");
        };
        let Some(auth_state) = &state.auth else {
            err!("Authorization state not set");
        };

        // grant_type
        match req.grant_type.as_str() {
            AUTH_CODE_GRANT_TYPE => {
                // client_id is the same as the one used to obtain the authorization code
                if Some(&req.client_id) != state.client_id.as_ref() {
                    err!(Err::InvalidGrant, "client_id differs from authorized one");
                }

                // redirect_uri is the same as the one provided in authorization request
                // i.e. either 'None' or 'Some(redirect_uri)'
                if req.redirect_uri != auth_state.redirect_uri {
                    err!(Err::InvalidGrant, "redirect_uri differs from authorized one");
                }

                // code_verifier
                let Some(verifier) = &req.code_verifier else {
                    err!(Err::AccessDenied, "code_verifier is missing");
                };

                // code_verifier matches code_challenge
                let hash = Sha256::digest(verifier);
                let challenge = Base64UrlUnpadded::encode_string(&hash);

                if Some(&challenge) != auth_state.code_challenge.as_ref() {
                    err!(Err::AccessDenied, "code_verifier is invalid");
                }
            }

            PRE_AUTH_GRANT_TYPE => {
                // anonymous access allowed?
                if req.client_id.is_empty()
                    && !server_meta.pre_authorized_grant_anonymous_access_supported
                {
                    err!(Err::InvalidClient, "Anonymous access is not supported");
                }
                // user_pin
                if req.user_pin != auth_state.user_pin {
                    err!(Err::InvalidGrant, "Invalid user_pin provided");
                }
            }
            _ => {
                err!(Err::UnsupportedGrantType, "Grant {} is not supported", req.grant_type)
            }
        }

        Ok(self)
    }

    /// Exchange auth code (authorization or pre-authorized) for access token,
    /// updating state along the way.
    #[instrument]
    async fn process(&self, req: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        let Some(provider) = &self.provider else {
            err!("Provider not set");
        };

        // remove authorization state to prevent auth code reuse
        StateManager::purge(provider, &auth_state_key(req)?).await?;

        // clone authorization state, update, then save as token state
        let Some(mut state) = self.state.clone() else {
            err!("State not set");
        };

        // we need a copy of auth_state in order to return authorization_details
        // in TokenResponse
        let Some(auth_state) = state.auth else {
            err!("Auth state not set");
        };
        state.auth = None;

        let token = gen::token();
        let c_nonce = gen::nonce();

        state.token = Some(
            TokenState::builder().access_token(token.clone()).c_nonce(c_nonce.clone()).build(),
        );
        StateManager::put(provider, &token, state.to_vec(), state.expires_at).await?;

        Ok(TokenResponse {
            access_token: token,
            token_type: String::from("Bearer"),
            expires_in: Expire::Access.duration().num_seconds(),
            c_nonce: Some(c_nonce),
            c_nonce_expires_in: Some(Expire::Nonce.duration().num_seconds()),
            authorization_details: auth_state.authorization_details,
            // LATER: implement this
            scope: None,
        })
    }
}

// Helper to get correct authorization state key from request.
// Authorization state is stored by either 'code' or 'pre_authorized_code',
// depending on grant_type.
fn auth_state_key(req: &TokenRequest) -> Result<String> {
    let state_key = match req.grant_type.as_str() {
        AUTH_CODE_GRANT_TYPE => req.code.as_ref(),
        PRE_AUTH_GRANT_TYPE => req.pre_authorized_code.as_ref(),
        _ => {
            err!(Err::UnsupportedGrantType, "Grant {} is not supported", req.grant_type)
        }
    };
    let Some(state_key) = state_key else {
        err!(Err::InvalidRequest, "Missing state key");
    };
    Ok(state_key.to_string())
}

#[cfg(test)]
mod tests {

    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;
    use vercre_core::metadata::CredentialDefinition;
    use vercre_core::vci::{AuthorizationDetail, TokenRequest};

    use super::*;
    use crate::state::{AuthState, Expire, State};

    #[tokio::test]
    async fn simple_token() {
        test_utils::init_tracer();

        let provider = &Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".to_string()];

        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(credentials)
            .holder_id(Some(NORMAL_USER.to_string()))
            .build();

        let pre_auth_code = "ABCDEF";

        state.auth = Some(AuthState {
            user_pin: Some("1234".to_string()),
            ..Default::default()
        });

        StateManager::put(&provider, pre_auth_code, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": wallet::did(),
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
            "user_pin": "1234"
        });

        let mut request =
            serde_json::from_value::<TokenRequest>(body).expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        let response = Handler::new(provider, request).call().await.expect("response is valid");
        assert_snapshot!("simpl-token", response, {
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

        let provider = &Provider::new();

        // set up state
        let credentials = vec!["EmployeeID_JWT".to_string()];

        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .client_id(wallet::did())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(credentials)
            .holder_id(Some(NORMAL_USER.to_string()))
            .build();

        let auth_code = "ABCDEF";
        let verifier = "ABCDEF12345";
        let verifier_hash = Sha256::digest(verifier);

        state.auth = Some(AuthState {
            redirect_uri: Some("https://example.com".to_string()),
            code_challenge: Some(Base64UrlUnpadded::encode_string(&verifier_hash)),
            code_challenge_method: Some("S256".to_string()),
            authorization_details: Some(vec![AuthorizationDetail {
                type_: "openid_credential".to_string(),
                format: "jwt_vc_json".to_string(),
                credential_definition: CredentialDefinition {
                    type_: vec![
                        "VerifiableCredential".to_string(),
                        "EmployeeIDCredential".to_string(),
                    ],
                    credential_subject: None,
                    ..Default::default()
                },
                credential_identifiers: Some(vec!["EmployeeID_JWT".to_string()]),
                locations: None,
            }]),
            ..Default::default()
        });

        StateManager::put(&provider, auth_code, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // create TokenRequest to 'send' to the app
        let body = json!({
            "client_id": wallet::did(),
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": verifier,
            "redirect_uri": "https://example.com",
        });

        let mut request =
            serde_json::from_value::<TokenRequest>(body).expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        let response = Handler::new(provider, request).call().await.expect("response is valid");
        assert_snapshot!("authzn-token", response, {
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
