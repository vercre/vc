//! # Authorization Handler
//!
//! The Authorization Endpoint is used in the same manner as defined in [RFC6749].
//!
//! An Authorization Request is used to request to grant access to the Credential
//! Endpoint.
//!
//! ```text
//! +--------------+   +-----------+                                    +-------------------+
//! | User         |   |   Wallet  |                                    | Credential Issuer |
//! +--------------+   +-----------+                                    +-------------------+
//!         |                |                                                    |
//!         |    interacts   |                                                    |
//!         |--------------->|                                                    |
//!         |                |  (1) Obtains Issuer's Credential Issuer metadata   |
//!         |                |<-------------------------------------------------->|
//!         |                |                                                    |
//!         |                |  (2) Authorization Request                         |
//!         |                |      (type(s) of Credentials to be issued)         |
//!         |                |--------------------------------------------------->|
//!         |                |                                                    |
//!         |   User Authentication / Consent                                     |
//!         |                |                                                    |
//!         |                |  (3)   Authorization Response (code)               |
//!         |                |<---------------------------------------------------|
//!         |                |                                                    |
//!         |                |  (4) Token Request (code)                          |
//!         |                |--------------------------------------------------->|
//!         |                |      Token Response (access_token)                 |
//!         |                |<---------------------------------------------------|
//!         |                |                                                    |
//!         |                |  (5) Credential Request (access_token, proof(s))   |
//!         |                |--------------------------------------------------->|
//!         |                |      Credential Response                           |
//!         |                |      (credential(s) OR transaction_id)             |
//!         |                |<---------------------------------------------------|
//! ```
//!
//! There are two possible ways to request issuance of a specific Credential type in an
//! Authorization Request:
//!
//! 1. Use of the `authorization_details` parameter as defined in [RFC9396]:
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

use anyhow::anyhow;
use chrono::Utc;
use tracing::{instrument, trace};
use vercre_core::error::{Ancillary, Err};
use vercre_core::metadata::Issuer as IssuerMetadata;
use vercre_core::vci::{AuthorizationDetail, AuthorizationRequest, AuthorizationResponse};
use vercre_core::{
    err, gen, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager,
};

use super::Handler;
use crate::state::{AuthState, Expire, State};

/// Authorize request handler.
impl<P> Handler<P, AuthorizationRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<AuthorizationResponse> {
        trace!("Handler::call");

        // add client state to error responses
        match self.handle_request(Context::new()).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                if let Some(state) = &self.request.state {
                    return Err(e).state(state.clone());
                };
                Err(e)
            }
        }
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Client + Issuer + Server + StateManager,
{
    provider: Option<P>,
    issuer_meta: IssuerMetadata,
    state: Option<State>,
    authorization_details: Vec<AuthorizationDetail>,
    identifiers: Vec<String>,
}

impl<P> Context<P>
where
    P: Client + Issuer + Server + StateManager,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");

        Self {
            provider: None,
            issuer_meta: IssuerMetadata::default(),
            state: None,
            authorization_details: vec![],
            identifiers: vec![],
        }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Debug,
{
    type Provider = P;
    type Request = AuthorizationRequest;
    type Response = AuthorizationResponse;

    // Prepare the context for processing the request.
    #[instrument]
    async fn init(&mut self, req: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        self.issuer_meta = Issuer::metadata(&provider, &req.credential_issuer).await?;

        // restore state (from a credential offer), if exists
        if let Some(state_key) = &req.issuer_state {
            let buf = StateManager::get(&provider, state_key).await?;
            self.state = Some(State::try_from(buf.as_slice())?);
        }

        // resolve scope and authorization_details to credential identifiers
        self.identifiers = self.resolve_scope(req)?;
        self.authorization_details = self.resolve_authzn(req)?;
        for auth_det in &self.authorization_details {
            self.identifiers.extend(auth_det.credential_identifiers.clone().unwrap_or_default());
        }
        self.identifiers.dedup();

        self.provider = Some(provider);
        Ok(self)
    }

    fn callback_id(&self) -> Option<String> {
        if let Some(state) = &self.state {
            return state.callback_id.clone();
        }
        None
    }

    #[instrument]
    async fn verify(&self, req: &Self::Request) -> Result<&Self> {
        trace!("Context::verify");

        let Some(provider) = &self.provider else {
            err!("Provider not set");
        };
        let Ok(client_meta) = Client::metadata(provider, &req.client_id).await else {
            err!(Err::InvalidClient, "Invalid client_id");
        };
        let server_meta = Server::metadata(provider, &req.credential_issuer).await?;

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
        if req.holder_id.is_empty() {
            err!(Err::AuthorizationPending, "Missing holder subject");
        }
        if Holder::authorize(provider, &req.holder_id, &self.identifiers).await.is_err() {
            err!(Err::AuthorizationPending, "Holder is not authorized");
        }

        // credential request?
        if req.authorization_details.is_none() && req.scope.is_none() {
            err!(Err::InvalidRequest, "No credentials requested");
        }

        // authorization_details (basic type validation)
        if let Some(authorization_details) = &req.authorization_details {
            for auth_det in authorization_details {
                if auth_det.type_ != "openid_credential" {
                    err!(Err::InvalidRequest, "Invalid authorization_details type");
                }
            }
        }

        // redirect_uri
        let Some(redirect_uri) = &req.redirect_uri else {
            err!(Err::InvalidRequest, "No redirect_uri specified");
        };
        let Some(redirect_uris) = client_meta.redirect_uris else {
            err!(Err::InvalidRequest, "No redirect_uris specified for client");
        };
        if !redirect_uris.contains(redirect_uri) {
            err!(Err::InvalidRequest, "Request redirect_uri is not registered");
        }

        // response_type
        if !client_meta.response_types.unwrap_or_default().contains(&req.response_type) {
            err!(Err::UnsupportedResponseType, "The response_type not supported by client");
        }
        if !server_meta.response_types_supported.contains(&req.response_type) {
            err!(Err::UnsupportedResponseType, "response_type not supported by server");
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server_meta.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&req.code_challenge_method) {
            err!(Err::InvalidRequest, "Unsupported code_challenge_method");
        }
        if req.code_challenge.len() < 43 || req.code_challenge.len() > 128 {
            err!(Err::InvalidRequest, "code_challenge must be between 43 and 128 characters");
        }

        Ok(self)
    }

    #[instrument]
    async fn process(&self, req: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        let Some(provider) = &self.provider else {
            err!("Provider not set");
        };

        // save authorization state
        let mut state = State::builder()
            .credential_issuer(req.credential_issuer.clone())
            .client_id(req.client_id.clone())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(self.identifiers.clone())
            .holder_id(Some(req.holder_id.clone()))
            .build();

        // save redirect uri and verify in token endpoint
        let Some(redirect_uri) = &req.redirect_uri else {
            err!(Err::InvalidRequest, "No redirect_uri specified");
        };
        let mut auth_state = AuthState::builder()
            .redirect_uri(redirect_uri.clone())
            .code_challenge(req.code_challenge.clone(), req.code_challenge_method.clone())
            .scope(req.scope.clone())
            .build();

        if !self.authorization_details.is_empty() {
            let mut details = self.authorization_details.clone();

            // remove credential_identifiers if not supported for this issuer
            if !self.issuer_meta.credential_identifiers_supported.unwrap_or_default() {
                for det in &mut details {
                    det.credential_identifiers = None;
                }
            }
            auth_state.authorization_details = Some(details);
        }

        state.auth = Some(auth_state);

        let code = gen::auth_code();
        StateManager::put(provider, &code, state.to_vec(), state.expires_at).await?;

        // remove offer state
        if let Some(issuer_state) = &req.issuer_state {
            StateManager::purge(provider, issuer_state).await?;
        }

        Ok(AuthorizationResponse {
            code,
            state: req.state.clone(),
            redirect_uri: redirect_uri.clone(),
        })
    }
}

impl<P> Context<P>
where
    P: Client + Issuer + Server + StateManager,
{
    // resolve credentials specified in authorization_details to supported
    // credential identifiers
    #[instrument]
    fn resolve_authzn(&self, req: &AuthorizationRequest) -> Result<Vec<AuthorizationDetail>>
    where
        P: Client + Issuer + Server + StateManager + Debug,
    {
        trace!("Context::resolve_authzn");

        let Some(mut auth_dets) = req.authorization_details.clone() else {
            return Ok(vec![]);
        };

        for auth_det in &mut auth_dets {
            let mut identifiers = vec![];
            for (id, cred) in &self.issuer_meta.credentials_supported {
                if cred.format == auth_det.format
                    && cred.credential_definition.type_ == auth_det.credential_definition.type_
                {
                    identifiers.push(id.to_owned());
                }
            }

            if identifiers.is_empty() {
                err!(Err::InvalidRequest, "Unsupported credentials requested");
            }
            auth_det.credential_identifiers = Some(identifiers);
        }

        Ok(auth_dets)
    }

    #[instrument]
    fn resolve_scope(&self, req: &AuthorizationRequest) -> Result<Vec<String>>
    where
        P: Client + Issuer + Server + StateManager + Debug,
    {
        trace!("Context::resolve_scope");

        let Some(scope) = &req.scope else {
            return Ok(vec![]);
        };

        let mut identifiers = vec![];

        for item in scope.split_whitespace().collect::<Vec<&str>>() {
            for (id, cred) in &self.issuer_meta.credentials_supported {
                if cred.scope == Some(item.to_string()) {
                    identifiers.push(id.to_owned());
                }
            }
        }

        Ok(identifiers)
    }
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

        let response = Handler::new(&provider, request).call().await.expect("response is ok");

        assert_snapshot!("authzn-ok", response, {
            ".code" => "[code]",
        });

        // compare response with saved state
        let buf = StateManager::get(&&provider, &response.code).await.expect("state exists");
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

        let response = Handler::new(&provider, request).call().await.expect("response is ok");
        assert_snapshot!("scope-ok", response, {
            ".code" => "[code]",
        });

        // compare response with saved state
        let buf = StateManager::get(&&provider, &response.code).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");
        assert_snapshot!("scope-state", state, {
            ".expires_at" => "[expires_at]",
            ".auth.code" => "[code]",
            ".auth.code_challenge" => "[code_challenge]",
        });
    }
}
