//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the Credential
//! Endpoint or Batch Credential Endpoint in cases where the Credential Issuer was not
//! able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is valid for
//! the issuance of the Credential previously requested at the Credential Endpoint or
//! the Batch Credential Endpoint.

use std::fmt::Debug;

use openid4vc::endpoint::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
use openid4vc::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use openid4vc::issuance::{DeferredCredentialRequest, DeferredCredentialResponse, ProofClaims};
use openid4vc::Result;
use proof::signature::{Signer, Verifier};
use tracing::instrument;

use super::Endpoint;
use crate::state::State;

impl<P> Endpoint<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Verifier
        + Callback
        + Clone
        + Debug,
{
    /// Deferred credential request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
    #[instrument(level = "debug", skip(self))]
    pub async fn deferred(
        &self, request: &DeferredCredentialRequest,
    ) -> Result<DeferredCredentialResponse> {
        let Ok(buf) = StateManager::get(&self.provider, &request.access_token).await else {
            return Err(Err::AccessDenied("invalid access token".into()));
        };
        let Ok(state) = State::try_from(buf) else {
            return Err(Err::AccessDenied("invalid state for access token".into()));
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            _p: std::marker::PhantomData,
        };

        openid4vc::endpoint::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    _p: std::marker::PhantomData<P>,
}

impl<P> openid4vc::endpoint::Context for Context<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
        + Verifier
        + Callback
        + Clone
        + Debug,
{
    type Provider = P;
    type Request = DeferredCredentialRequest;
    type Response = DeferredCredentialResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    async fn process(
        &self, provider: &Self::Provider, request: &Self::Request,
    ) -> Result<Self::Response> {
        tracing::debug!("Context::process");

        // retrieve deferred credential request from state
        let Ok(buf) = StateManager::get(provider, &request.transaction_id).await else {
            return Err(Err::InvalidTransactionId("deferred state not found".into()));
        };
        let Ok(state) = State::try_from(buf) else {
            return Err(Err::InvalidTransactionId("deferred state is expired or corrupted".into()));
        };

        let Some(deferred_state) = state.deferred else {
            return Err(Err::ServerError("Deferred state not found.".into()));
        };

        // remove deferred state item
        StateManager::purge(provider, &request.transaction_id)
            .await
            .map_err(|e| Err::ServerError(format!("issue purging state: {e}")))?;

        // make credential request
        let mut cred_req = deferred_state.credential_request;
        cred_req.credential_issuer.clone_from(&request.credential_issuer);
        cred_req.access_token.clone_from(&request.access_token);

        let response = Endpoint::new(provider.clone()).credential(&cred_req).await?;

        Ok(DeferredCredentialResponse {
            credential_response: response,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use openid4vc::issuance::{CredentialRequest, ProofClaims};
    use proof::jose::jws::{self, Type};
    use serde_json::json;
    use test_utils::holder;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use w3c_vc::proof::{Payload, Verify};

    use super::*;
    use crate::state::{Deferred, Expire, Token};

    #[tokio::test]
    async fn deferred_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "tkn-ABCDEF";
        let c_nonce = "1234ABCD".to_string();
        let transaction_id = "txn-ABCDEF";
        let credentials = vec!["EmployeeID_JWT".into()];

        // create CredentialRequest to 'send' to the app
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.clone()),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
            "format": "jwt_vc_json",
            "credential_definition": {
                "type": [
                    "VerifiableCredential",
                    "EmployeeIDCredential"
                ]
            },
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });

        let mut cred_req =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        cred_req.credential_issuer = CREDENTIAL_ISSUER.into();
        cred_req.access_token = access_token.into();

        // set up state
        let mut state = State::builder()
            .credential_issuer(CREDENTIAL_ISSUER.into())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .subject_id(Some(NORMAL_USER.into()))
            .build()
            .expect("should build state");

        // state entry 1: token state keyed by access_token
        state.token = Some(Token {
            access_token: access_token.into(),
            token_type: "Bearer".into(),
            c_nonce,
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            ..Default::default()
        });
        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // state entry 2: deferred state keyed by transaction_id
        state.token = None;
        state.deferred = Some(Deferred {
            transaction_id: transaction_id.into(),
            credential_request: cred_req.clone(),
        });
        StateManager::put(&provider, transaction_id, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: access_token.into(),
            transaction_id: transaction_id.into(),
        };

        let response =
            Endpoint::new(provider.clone()).deferred(&request).await.expect("response is valid");
        assert_snapshot!("response", &response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // extract credential response
        let cred_resp = response.credential_response;

        // verify credential
        let Some(vc_kind) = &cred_resp.credential else {
            panic!("VC is not base64 encoded string");
        };
        let Payload::Vc(vc) =
            w3c_vc::proof::verify(Verify::Vc(vc_kind), &provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(buf), StateManager::get(&provider, access_token).await);
        let state = State::try_from(buf).expect("token state is valid");
        assert_snapshot!("state", state, {
            ".expires_at" => "[expires_at]",
            ".token.c_nonce"=>"[c_nonce]",
            ".token.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });

        // deferred state should not exist
        assert!(StateManager::get(&provider, transaction_id).await.is_err());
    }
}
