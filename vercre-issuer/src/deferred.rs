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

use anyhow::anyhow;
use tracing::instrument;
use vercre_core::error::Err;
use vercre_core::provider::{
    Callback, ClientMetadata, IssuerMetadata, ServerMetadata, StateManager, Subject,
};
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vci::{DeferredCredentialRequest, DeferredCredentialResponse};
use vercre_core::{err, Result};
use vercre_vc::proof::Signer;

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
            err!(Err::AccessDenied, "invalid access token");
        };
        let Ok(state) = State::try_from(buf) else {
            err!(Err::AccessDenied, "invalid state for access token");
        };

        let ctx = Context {
            callback_id: state.callback_id.clone(),
            _p: std::marker::PhantomData,
        };

        vercre_core::Endpoint::handle_request(self, request, ctx).await
    }
}

#[derive(Debug)]
struct Context<P> {
    callback_id: Option<String>,
    _p: std::marker::PhantomData<P>,
}

impl<P> vercre_core::Context for Context<P>
where
    P: ClientMetadata
        + IssuerMetadata
        + ServerMetadata
        + Subject
        + StateManager
        + Signer
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
            err!(Err::InvalidTransactionId, "deferred state not found");
        };
        let Ok(state) = State::try_from(buf) else {
            err!(Err::InvalidTransactionId, "deferred state is expired or corrupted");
        };

        let Some(deferred_state) = state.deferred else {
            err!("Deferred state not found.");
        };

        // remove deferred state item
        StateManager::purge(provider, &request.transaction_id).await?;

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
    use providers::issuance::{Provider, CREDENTIAL_ISSUER, NORMAL_USER};
    use providers::wallet;
    use serde_json::json;
    use vercre_core::vci::{CredentialRequest, ProofClaims};

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
            iss: Some(wallet::CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.clone()),
        };
        let jwt = vercre_proof::jose::encode(
            vercre_proof::jose::Typ::Proof,
            &claims,
            wallet::Provider::new(),
        )
        .await
        .expect("should encode");

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
            .holder_id(Some(NORMAL_USER.into()))
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
        let vc_val = cred_resp.credential.expect("VC is present");
        let token = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let vercre_vc::proof::Type::Vc(vc) =
            vercre_vc::proof::verify(&token, vercre_vc::proof::DataType::Vc)
                .await
                .expect("should decode")
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
