//! # Credential Offer Handler
//!
//! The Credential Offer endpoint is for Credential Issuers to generate a Credential Offer
//! which can be used to initiate Credential issuance with a Wallet.
//!
//! When a Credential Issuer is already interacting with a user and wishes to initate a
//! Credential issuance, they can 'send' the user's Wallet a Credential Offer.
//!
//! The diagram illustrates this Credential Issuer initiated flow:
//!
//! ```text
//! +--------------+   +-----------+                                    +-------------------+
//! | User         |   |   Wallet  |                                    | Credential Issuer |
//! +--------------+   +-----------+                                    +-------------------+
//!         |                |                                                    |
//!         |                |  (1) User provides  information required           |
//!         |                |      for the issuance of a certain Credential      |
//!         |-------------------------------------------------------------------->|
//!         |                |                                                    |
//!         |                |  (2) Credential Offer (Pre-Authorized Code)        |
//!         |                |<---------------------------------------------------|
//!         |                |  (3) Obtains Issuer's Credential Issuer metadata   |
//!         |                |<-------------------------------------------------->|
//!         |   interacts    |                                                    |
//!         |--------------->|                                                    |
//!         |                |                                                    |
//!         |                |  (4) Token Request (Pre-Authorized Code, pin)      |
//!         |                |--------------------------------------------------->|
//!         |                |      Token Response (access_token)                 |
//!         |                |<---------------------------------------------------|
//!         |                |                                                    |
//!         |                |  (5) Credential Request (access_token, proof(s))   |
//!         |                |--------------------------------------------------->|
//!         |                |      Credential Response                           |
//!         |                |      (credential(s))                               |
//!         |                |<---------------------------------------------------|
//! ```
//!
//! While JSON-based, the Offer can be sent to the Wallet's Credential Offer Handler URL
//! as an HTTP GET request, an HTTP redirect, or a QR code.
//!
//! Below is a non-normative example of a Credential Offer Object for a Pre-Authorized
//! Code Flow (with a credential type reference):
//!
//! ```json
//! {
//!    "credential_issuer": "https://credential-issuer.example.com",
//!    "credentials": [
//!       "UniversityDegree_LDP_VC"
//!    ],
//!    "grants": {
//!       "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
//!           "pre-authorized_code": "adhjhdjajkdkhjhdj",
//!           "user_pin_required": true
//!       }
//!   }
//! }
//! ```
//!
//! See <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-endpoint>

use std::fmt::Debug;

use anyhow::anyhow;
use chrono::Utc;
use tracing::{instrument, trace};
use vercre_core::error::Err;
use vercre_core::metadata::Issuer as IssuerMetadata;
use vercre_core::vci::{
    AuthorizationCodeGrant, CredentialOffer, Grants, InvokeRequest, InvokeResponse,
    PreAuthorizedCodeGrant,
};
use vercre_core::{
    err, gen, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager,
};

use super::Handler;
use crate::state::{AuthState, Expire, State};

/// Credential Offer request handler.
impl<P> Handler<P, InvokeRequest>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Call the request for the Request Object endpoint.
    #[instrument]
    pub async fn call(&self) -> Result<InvokeResponse> {
        trace!("Handler::call");
        self.handle_request(Context::new()).await
    }
}

#[derive(Debug)]
struct Context<P>
where
    P: Issuer + StateManager,
{
    callback_id: Option<String>,
    issuer_meta: IssuerMetadata,
    provider: Option<P>,
}

impl<P> Context<P>
where
    P: Issuer + StateManager,
{
    #[instrument]
    pub fn new() -> Self {
        trace!("Context::new");
        Self {
            callback_id: None,
            issuer_meta: IssuerMetadata::default(),
            provider: None,
        }
    }
}

impl<P> vercre_core::Context for Context<P>
where
    P: Issuer + StateManager + Debug,
{
    type Provider = P;
    type Request = InvokeRequest;
    type Response = InvokeResponse;

    // Prepare the context for processing the request.
    #[instrument]
    async fn init(&mut self, req: &Self::Request, provider: Self::Provider) -> Result<&Self> {
        trace!("Context::prepare");

        self.callback_id = req.callback_id.clone();
        self.issuer_meta = Issuer::metadata(&provider, &req.credential_issuer).await?;
        self.provider = Some(provider);

        Ok(self)
    }

    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    // Verify the request is valid.
    #[instrument]
    async fn verify(&self, req: &Self::Request) -> Result<&Self> {
        trace!("Context::verify");

        // credential_issuer required
        if req.credential_issuer.is_empty() {
            err!(Err::InvalidRequest, "No credential_issuer specified");
        };
        // credentials required
        if req.credentials.is_empty() {
            err!(Err::InvalidRequest, "No credentials requested");
        };
        // requested credential is supported
        for cred_id in &req.credentials {
            let Some(_) = self.issuer_meta.credentials_supported.get(cred_id) else {
                err!(Err::UnsupportedCredentialType, "Requested credential is unsupported");
            };
        }
        // holder_id is required
        if req.holder_id.is_none() {
            err!(Err::InvalidRequest, "No holder_id specified");
        };

        Ok(self)
    }

    // Process the request.
    #[instrument]
    async fn process(&self, req: &Self::Request) -> Result<Self::Response> {
        trace!("Context::process");

        let Some(provider) = &self.provider else {
            err!("Provider not set");
        };

        let mut state = State::builder()
            .credential_issuer(req.credential_issuer.clone())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credentials(req.credentials.clone())
            .holder_id(req.holder_id.clone())
            .callback_id(req.callback_id.clone())
            .build();

        let mut pre_auth_grant = None;
        let mut auth_grant = None;
        let mut user_pin = None;

        if req.pre_authorize {
            // ------------------------------------------------
            // Pre-authorized Code Grant
            // ------------------------------------------------
            let pre_auth_code = gen::auth_code();

            pre_auth_grant = Some(PreAuthorizedCodeGrant {
                pre_authorized_code: pre_auth_code.clone(),
                user_pin_required: Some(req.user_pin_required),
                interval: None,
                authorization_server: None,
            });

            if req.user_pin_required {
                user_pin = Some(gen::user_pin());
            }

            // save state by pre-auth_code
            state.auth = Some(
                AuthState::builder()
                    // .issuer_state(iss_state.clone())
                    .user_pin(user_pin.clone())
                    .build(),
            );
            StateManager::put(provider, &pre_auth_code, state.to_vec(), state.expires_at).await?;
        } else {
            // ------------------------------------------------
            // Authorization Code Grant
            // ------------------------------------------------
            let iss_state = gen::state_key();

            auth_grant = Some(AuthorizationCodeGrant {
                issuer_state: Some(iss_state.clone()),
                authorization_server: None,
            });
            StateManager::put(provider, &iss_state, state.to_vec(), state.expires_at).await?;
        }

        // return response
        Ok(InvokeResponse {
            credential_offer: Some(CredentialOffer {
                credential_issuer: req.credential_issuer.clone(),
                credentials: req.credentials.clone(),
                grants: Some(Grants {
                    authorization_code: auth_grant,
                    pre_authorized_code: pre_auth_grant,
                }),
            }),
            user_pin,

            // LATER: save offer to state and return uri
            credential_offer_uri: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};

    use super::*;

    #[tokio::test]
    async fn pre_authorize() {
        test_utils::init_tracer();

        let provider = Provider::new();

        // create offer to 'send' to the app
        let body = json!({
            "credentials": ["EmployeeID_JWT"],
            "holder_id": NORMAL_USER,
            "pre-authorize": true,
            "user_pin_required": true,
            "callback_id": "1234"
        });

        let mut request =
            serde_json::from_value::<InvokeRequest>(body).expect("request should deserialize");
        request.credential_issuer = ISSUER.to_string();
        let response = Handler::new(&provider, request).call().await.expect("response is ok");
        assert_snapshot!("invoke", response, {
            ".credential_offer.grants.authorization_code.issuer_state" => "[state]",
            ".credential_offer.grants[\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"][\"pre-authorized_code\"]" => "[pre-authorized_code]",
            ".user_pin" => "[user_pin]"
        });

        // check redacted fields
        let offer = response.credential_offer.as_ref().expect("has credential_offer");
        assert_let!(Some(grants), &offer.grants);
        assert_let!(Some(pre_auth_code), &grants.pre_authorized_code);
        assert!(grants.pre_authorized_code.is_some());

        // compare response with saved state
        let state_key = &pre_auth_code.pre_authorized_code; //as_ref().expect("has state");
        let buf = StateManager::get(&&provider, state_key).await.expect("state exists");
        let state = State::try_from(buf).expect("state is valid");

        assert_snapshot!("state", state, {
            ".expires_at" => "[expires_at]",
            ".auth.code"=>"[code]",
            ".auth.issuer_state" => "[issuer_state]",
            ".auth.user_pin" => "[user_pin]"
        });

        assert_let!(Some(auth_state), &state.auth);
        assert_eq!(auth_state.user_pin, response.user_pin);
    }
}
