//! # Authorization Endpoint
//!
//! The Authorization Endpoint is used in the same manner as defined in [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).
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
use vercre_core::vci::{AuthorizationDetail, AuthorizationRequest, AuthorizationResponse};
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
    pub async fn authorize(
        &self, request: impl Into<AuthorizationRequest>,
    ) -> Result<AuthorizationResponse> {
        let request = request.into();

        // attempt to get callback_id from state, if pre-auth flow
        let callback_id = if let Some(state_key) = &request.issuer_state {
            let buf = StateManager::get(&self.provider, state_key).await?;
            let state = State::try_from(buf.as_slice())?;
            state.callback_id
        } else {
            None
        };

        let issuer_meta = Issuer::metadata(&self.provider, &request.credential_issuer).await?;

        // resolve scope and authorization_details to credential identifiers
        let mut identifiers = scope_identifiers(&request, &issuer_meta)?;
        let authorization_details = authzn_identifiers(&request, &issuer_meta)?;

        // // remove credential_identifiers if not supported for this issuer
        // if !issuer_meta.credential_identifiers_supported.unwrap_or_default() {
        //     for det in &mut authorization_details {
        //         det.credential_identifiers = None;
        //     }
        // }

        for det in &authorization_details {
            identifiers.extend(det.credential_identifiers.clone().unwrap_or_default());
        }
        identifiers.dedup();

        let ctx = Context {
            callback_id,
            authorization_details,
            identifiers,
        };

        self.handle_request(request, ctx).await
    }
}

#[derive(Debug)]
struct Context {
    callback_id: Option<String>,
    authorization_details: Vec<AuthorizationDetail>,
    identifiers: Vec<String>,
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
            err!(Err::InvalidClient, "Invalid client_id");
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
            err!(Err::AuthorizationPending, "Missing holder subject");
        }
        if Holder::authorize(provider, &request.holder_id, &self.identifiers).await.is_err() {
            err!(Err::AuthorizationPending, "Holder is not authorized");
        }

        // credential request?
        if request.authorization_details.is_none() && request.scope.is_none() {
            err!(Err::InvalidRequest, "No credentials requested");
        }

        // authorization_details (basic type validation)
        if let Some(authorization_details) = &request.authorization_details {
            let supported = issuer_meta.credential_identifiers_supported.unwrap_or_default();

            for auth_det in authorization_details {
                if auth_det.type_ != "openid_credential" {
                    err!(Err::InvalidRequest, "Invalid authorization_details type");
                }
                if !supported && auth_det.credential_identifiers.is_some() {
                    err!(Err::InvalidRequest, "credential_identifiers not supported");
                }
            }
        }

        // redirect_uri
        let Some(redirect_uri) = &request.redirect_uri else {
            err!(Err::InvalidRequest, "No redirect_uri specified");
        };
        let Some(redirect_uris) = client_meta.redirect_uris else {
            err!(Err::InvalidRequest, "No redirect_uris specified for client");
        };
        if !redirect_uris.contains(redirect_uri) {
            err!(Err::InvalidRequest, "Request redirect_uri is not registered");
        }

        // response_type
        if !client_meta.response_types.unwrap_or_default().contains(&request.response_type) {
            err!(Err::UnsupportedResponseType, "The response_type not supported by client");
        }
        if !server_meta.response_types_supported.contains(&request.response_type) {
            err!(Err::UnsupportedResponseType, "response_type not supported by server");
        }

        // code_challenge
        // N.B. while optional in the spec, we require it
        let challenge_methods = server_meta.code_challenge_methods_supported.unwrap_or_default();
        if !challenge_methods.contains(&request.code_challenge_method) {
            err!(Err::InvalidRequest, "Unsupported code_challenge_method");
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

        let issuer_meta = Issuer::metadata(provider, &request.credential_issuer).await?;

        // save authorization state
        let mut state = State::builder()
            .credential_issuer(request.credential_issuer.clone())
            .client_id(request.client_id.clone())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(self.identifiers.clone())
            .holder_id(Some(request.holder_id.clone()))
            .build();

        // save `redirect_uri` and verify in `token` endpoint
        let Some(redirect_uri) = &request.redirect_uri else {
            err!(Err::InvalidRequest, "No redirect_uri specified");
        };
        let mut auth_state = AuthState::builder()
            .redirect_uri(redirect_uri.clone())
            .code_challenge(request.code_challenge.clone(), request.code_challenge_method.clone())
            .scope(request.scope.clone())
            .build();

        // remove `credential_identifiers` if not supported
        // if !issuer_meta.credential_identifiers_supported.unwrap_or_default() {
        //     let mut details = self.authorization_details.clone();
        //     for det in &mut details {
        //         det.credential_identifiers = None;
        //     }
        //     auth_state.authorization_details = Some(details);
        // }

        if !self.authorization_details.is_empty() {
            let mut details = self.authorization_details.clone();

            // remove credential_identifiers if not supported for this issuer
            if !issuer_meta.credential_identifiers_supported.unwrap_or_default() {
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
        if let Some(issuer_state) = &request.issuer_state {
            StateManager::purge(provider, issuer_state).await?;
        }

        Ok(AuthorizationResponse {
            code,
            state: request.state.clone(),
            redirect_uri: redirect_uri.clone(),
        })
    }
}

// resolve credentials specified in authorization_details to supported
// credential identifiers
#[instrument]
fn authzn_identifiers(
    req: &AuthorizationRequest, issuer_meta: &IssuerMetadata,
) -> Result<Vec<AuthorizationDetail>> {
    trace!("authzn_identifiers");

    let Some(mut auth_dets) = req.authorization_details.clone() else {
        return Ok(vec![]);
    };

    for auth_det in &mut auth_dets {
        let mut identifiers = vec![];
        for (id, cred) in &issuer_meta.credential_configurations_supported {
            if Some(&cred.format) == auth_det.format.as_ref()
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
fn scope_identifiers(
    request: &AuthorizationRequest, issuer_meta: &IssuerMetadata,
) -> Result<Vec<String>> {
    trace!("scope_identifiers");

    let Some(scope) = &request.scope else {
        return Ok(vec![]);
    };
    let mut identifiers = vec![];

    for item in scope.split_whitespace().collect::<Vec<&str>>() {
        for (id, cred) in &issuer_meta.credential_configurations_supported {
            if cred.scope == Some(item.to_string()) {
                identifiers.push(id.to_owned());
            }
        }
    }

    Ok(identifiers)
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
            Endpoint::new(provider.clone()).authorize(request).await.expect("response is ok");

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
            Endpoint::new(provider.clone()).authorize(request).await.expect("response is ok");
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
