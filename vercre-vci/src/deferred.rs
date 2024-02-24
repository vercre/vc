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
use tracing::{instrument, trace};
use vercre_core::error::Err;
#[allow(clippy::module_name_repetitions)]
pub use vercre_core::vci::{DeferredCredentialRequest, DeferredCredentialResponse};
use vercre_core::{err, Callback, Client, Holder, Issuer, Result, Server, Signer, StateManager};

use super::Endpoint;
use crate::state::State;

impl<P> Endpoint<P>
where
    P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
{
    /// Deferred credential request handler.
    ///
    /// # Errors
    ///
    /// Returns an `OpenID4VP` error if the request is invalid or if the provider is
    /// not available.
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
        };

        self.handle_request(request, ctx).await
    }
}

#[derive(Debug)]
struct Context {
    callback_id: Option<String>,
}

impl super::Context for Context {
    type Request = DeferredCredentialRequest;
    type Response = DeferredCredentialResponse;

    // TODO: get callback_id from state
    fn callback_id(&self) -> Option<String> {
        self.callback_id.clone()
    }

    #[instrument]
    async fn process<P>(&self, provider: &P, request: &Self::Request) -> Result<Self::Response>
    where
        P: Client + Issuer + Server + Holder + StateManager + Signer + Callback + Clone,
    {
        trace!("Context::process");

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
        cred_req.credential_issuer = request.credential_issuer.clone();
        cred_req.access_token = request.access_token.clone();

        let response = Endpoint::new(provider.clone()).credential(&cred_req).await?;

        Ok(DeferredCredentialResponse {
            credential_response: response,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use assert_let_bind::assert_let;
    use base64ct::{Base64UrlUnpadded, Encoding};
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::vci_provider::{Provider, ISSUER, NORMAL_USER};
    use test_utils::wallet;
    use vercre_core::jwt::{self, Jwt};
    use vercre_core::vci::{CredentialRequest, ProofClaims};
    use vercre_core::w3c::vc::VcClaims;

    use super::*;
    use crate::state::{DeferredState, Expire, TokenState};

    #[tokio::test]
    async fn deferred_ok() {
        test_utils::init_tracer();

        let provider = Provider::new();
        let access_token = "tkn-ABCDEF";
        let c_nonce = "1234ABCD".to_string();
        let transaction_id = "txn-ABCDEF";
        let credentials = vec!["EmployeeID_JWT".to_string()];

        // create CredentialRequest to 'send' to the app
        let jwt_enc = Jwt {
            header: jwt::Header {
                typ: "vercre-vci-proof+jwt".to_string(),
                alg: wallet::alg(),
                kid: wallet::kid(),
            },
            claims: ProofClaims {
                iss: wallet::did(),
                aud: ISSUER.to_string(),
                iat: Utc::now().timestamp(),
                nonce: c_nonce.to_string(),
            },
        }
        .to_string();
        let sig = wallet::sign(jwt_enc.as_bytes());
        let sig_enc = Base64UrlUnpadded::encode_string(&sig);
        let signed_jwt = format!("{jwt_enc}.{sig_enc}");

        let body = json!({
            "credential_identifier": "EmployeeID_JWT",
            "proof":{
                "proof_type": "jwt",
                "jwt": signed_jwt
            }
        });

        let mut cred_req =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");
        cred_req.credential_issuer = ISSUER.to_string();
        cred_req.access_token = access_token.to_string();

        // set up state
        let mut state = State::builder()
            .credential_issuer(ISSUER.to_string())
            .expires_at(Utc::now() + Expire::AuthCode.duration())
            .credential_configuration_ids(credentials)
            .holder_id(Some(NORMAL_USER.to_string()))
            .build()
            .expect("should build state");

        // state entry 1: token state keyed by access_token
        state.token = Some(TokenState {
            access_token: access_token.to_string(),
            token_type: "Bearer".to_string(),
            c_nonce,
            c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            ..Default::default()
        });
        StateManager::put(&provider, access_token, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        // state entry 2: deferred state keyed by transaction_id
        state.token = None;
        state.deferred = Some(DeferredState {
            transaction_id: transaction_id.to_string(),
            credential_request: cred_req.clone(),
        });
        StateManager::put(&provider, transaction_id, state.to_vec(), state.expires_at)
            .await
            .expect("state exists");

        let request = DeferredCredentialRequest {
            credential_issuer: ISSUER.to_string(),
            access_token: access_token.to_string(),
            transaction_id: transaction_id.to_string(),
        };

        let response =
            Endpoint::new(provider.clone()).deferred(&request).await.expect("response is valid");
        assert_snapshot!("response", response, {
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".c_nonce_expires_in" => "[c_nonce_expires_in]"
        });

        // extract credential response
        let cred_resp = response.credential_response;

        // verify credential
        let vc_val = cred_resp.credential.expect("VC is present");
        let vc_b64 = serde_json::from_value::<String>(vc_val).expect("base64 encoded string");
        let vc_jwt = Jwt::<VcClaims>::from_str(&vc_b64).expect("VC as JWT");
        assert_snapshot!("vc_jwt", vc_jwt, {
            ".claims.iat" => "[iat]",
            ".claims.nbf" => "[nbf]",
            ".claims.vc.issuanceDate" => "[issuanceDate]",
            ".claims.vc.credentialSubject" => insta::sorted_redaction()
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
