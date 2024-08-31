//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the Credential
//! Endpoint or Batch Credential Endpoint in cases where the Credential Issuer was not
//! able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is valid for
//! the issuance of the Credential previously requested at the Credential Endpoint or
//! the Batch Credential Endpoint.

use tracing::instrument;
use vercre_openid::issuer::{
    DeferredCredentialRequest, DeferredCredentialResponse, Provider, StateStore,
};
use vercre_openid::{Error, Result};

use crate::credential::credential;
// use crate::shell;
use crate::state::{State, Step};

/// Deferred credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn deferred(
    provider: impl Provider, request: &DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    process(provider, request).await
}

async fn process(
    provider: impl Provider, request: &DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    tracing::debug!("deferred::process");

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<State>(&provider, &request.transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".into()));
    };

    if state.is_expired() {
        return Err(Error::InvalidRequest("state expired".into()));
    }

    let Step::Deferred(deferred_state) = state.current_step else {
        return Err(Error::ServerError("Deferred state not found.".into()));
    };

    // remove deferred state item
    StateStore::purge(&provider, &request.transaction_id)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    // make credential request
    let mut cred_req = deferred_state.credential_request;
    cred_req.credential_issuer.clone_from(&request.credential_issuer);
    cred_req.access_token.clone_from(&request.access_token);

    let response = credential(provider.clone(), &cred_req).await?;

    Ok(DeferredCredentialResponse {
        credential_response: response,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_let_bind::assert_let;
    use chrono::Utc;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use vercre_datasec::jose::jws::{self, Type};
    use vercre_openid::issuer::{CredentialRequest, CredentialResponseType, ProofClaims};
    use vercre_test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use vercre_test_utils::{holder, snapshot};
    use vercre_w3c_vc::proof::{self, Payload, Verify};

    use super::*;
    use crate::state::{Deferred, Expire, Token};

    #[tokio::test]
    async fn deferred_ok() {
        vercre_test_utils::init_tracer();
        snapshot!("");

        let provider = Provider::new();
        let access_token = "tkn-ABCDEF";
        let c_nonce = "1234ABCD".to_string();
        let transaction_id = "txn-ABCDEF";

        // create CredentialRequest to 'send' to the app
        let claims = ProofClaims {
            iss: Some(CLIENT_ID.into()),
            aud: CREDENTIAL_ISSUER.into(),
            iat: Utc::now().timestamp(),
            nonce: Some(c_nonce.clone()),
        };
        let jwt = jws::encode(Type::Proof, &claims, holder::Provider).await.expect("should encode");

        let body = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
            "credential_identifier": "PHLEmployeeID",
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let cred_req =
            serde_json::from_value::<CredentialRequest>(body).expect("request should deserialize");

        // set up state
        let mut state = State {
            expires_at: Utc::now() + Expire::Authorized.duration(),
            subject_id: Some(NORMAL_USER.into()),
            credentials: Some(HashMap::from([("PHLEmployeeID".into(), "EmployeeID_JWT".into())])),
            current_step: Step::Token(Token {
                access_token: access_token.into(),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            ..State::default()
        };

        StateStore::put(&provider, access_token, &state, state.expires_at)
            .await
            .expect("state exists");

        // state entry 2: deferred state keyed by transaction_id
        state.current_step = Step::Deferred(Deferred {
            transaction_id: transaction_id.into(),
            credential_request: cred_req.clone(),
        });
        StateStore::put(&provider, transaction_id, &state, state.expires_at)
            .await
            .expect("state exists");

        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: access_token.into(),
            transaction_id: transaction_id.into(),
        };

        let response = deferred(provider.clone(), &request).await.expect("response is valid");
        assert_snapshot!("deferred:deferred_ok:response", &response, {
            ".transaction_id" => "[transaction_id]",
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
        });

        // extract credential response
        let cred_resp = response.credential_response;

        // verify credential
        let CredentialResponseType::Credential(vc_kind) = &cred_resp.response else {
            panic!("expected a single credential");
        };
        let Payload::Vc(vc) =
            proof::verify(Verify::Vc(&vc_kind), &provider).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("deferred:deferred_ok:vc", vc, {
            ".issuanceDate" => "[issuanceDate]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("deferred:deferred_ok:state", state, {
            ".expires_at" => "[expires_at]",
            ".current_step.c_nonce"=>"[c_nonce]",
            ".current_step.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });

        // deferred state should not exist
        assert!(StateStore::get::<State>(&provider, transaction_id).await.is_err());
    }
}
