//! # Deferred Credential Endpoint
//!
//! This endpoint is used to issue a Credential previously requested at the
//! Credential Endpoint or Batch Credential Endpoint in cases where the
//! Credential Issuer was not able to immediately issue this Credential.
//!
//! The Wallet MUST present to the Deferred Endpoint an Access Token that is
//! valid for the issuance of the Credential previously requested at the
//! Credential Endpoint or the Batch Credential Endpoint.

use tracing::instrument;
use vercre_openid::issuer::{
    CredentialResponseType, DeferredCredentialRequest, DeferredCredentialResponse, Provider,
    StateStore,
};
use vercre_openid::{Error, Result};

use crate::credential::credential;
use crate::state::{Stage, State};

/// Deferred credential request handler.
///
/// # Errors
///
/// Returns an `OpenID4VP` error if the request is invalid or if the provider is
/// not available.
#[instrument(level = "debug", skip(provider))]
pub async fn deferred(
    provider: impl Provider, request: DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    process(&provider, request).await
}

async fn process(
    provider: &impl Provider, request: DeferredCredentialRequest,
) -> Result<DeferredCredentialResponse> {
    tracing::debug!("deferred::process");

    // retrieve deferred credential request from state
    let Ok(state) = StateStore::get::<State>(provider, &request.transaction_id).await else {
        return Err(Error::InvalidTransactionId("deferred state not found".into()));
    };
    if state.is_expired() {
        return Err(Error::InvalidRequest("state expired".into()));
    }

    let Stage::Deferred(deferred_state) = state.stage else {
        return Err(Error::ServerError("Deferred state not found.".into()));
    };

    // remove deferred state item
    StateStore::purge(provider, &request.transaction_id)
        .await
        .map_err(|e| Error::ServerError(format!("issue purging state: {e}")))?;

    // make credential request
    let mut cred_req = deferred_state.credential_request;
    cred_req.credential_issuer.clone_from(&request.credential_issuer);
    cred_req.access_token.clone_from(&request.access_token);

    let response = credential(provider.clone(), cred_req).await?;

    // is issuance still pending?
    if let CredentialResponseType::TransactionId(_) = response.response {
        // TODO: make retry interval configurable
        return Err(Error::IssuancePending(5));
    }

    Ok(DeferredCredentialResponse {
        credential_response: response,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use assert_let_bind::assert_let;
    use chrono::Utc;
    use credibil_infosec::jose::JwsBuilder;
    use insta::assert_yaml_snapshot as assert_snapshot;
    use serde_json::json;
    use test_utils::issuer::{Provider, CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};
    use test_utils::{holder, snapshot};
    use vercre_openid::issuer::{CredentialRequest, CredentialResponseType, ProofClaims};
    use vercre_w3c_vc::proof::{self, Payload, Type, Verify};

    use super::*;
    use crate::state::{Authorized, Deferrance, Expire, Token};

    #[tokio::test]
    async fn deferred_ok() {
        test_utils::init_tracer();
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
        let jws = JwsBuilder::new()
            .jwt_type(Type::Openid4VciProofJwt)
            .payload(claims)
            .add_signer(&holder::Provider)
            .build()
            .await
            .expect("jws should build");
        let jwt = jws.encode().expect("jws should encode");

        let value = json!({
            "credential_issuer": CREDENTIAL_ISSUER,
            "access_token": access_token,
            "credential_identifier": "PHLEmployeeID",
            "proof":{
                "proof_type": "jwt",
                "jwt": jwt
            }
        });
        let request: CredentialRequest = serde_json::from_value(value).expect("request is valid");

        // set up state
        let mut state = State {
            stage: Stage::Validated(Token {
                access_token: access_token.into(),
                credentials: HashMap::from([(
                    "PHLEmployeeID".into(),
                    Authorized {
                        credential_identifier: "PHLEmployeeID".into(),
                        credential_configuration_id: "EmployeeID_JWT".into(),
                        claim_ids: None,
                    },
                )]),
                c_nonce: c_nonce.into(),
                c_nonce_expires_at: Utc::now() + Expire::Nonce.duration(),
            }),
            subject_id: Some(NORMAL_USER.into()),
            expires_at: Utc::now() + Expire::Authorized.duration(),
        };

        StateStore::put(&provider, access_token, &state, state.expires_at)
            .await
            .expect("state exists");

        // state entry 2: deferred state keyed by transaction_id
        state.stage = Stage::Deferred(Deferrance {
            transaction_id: transaction_id.into(),
            credential_request: request.clone(),
        });
        StateStore::put(&provider, transaction_id, &state, state.expires_at)
            .await
            .expect("state exists");

        let request = DeferredCredentialRequest {
            credential_issuer: CREDENTIAL_ISSUER.into(),
            access_token: access_token.into(),
            transaction_id: transaction_id.into(),
        };

        let response = deferred(provider.clone(), request).await.expect("response is valid");
        assert_snapshot!("deferred:deferred_ok:response", &response, {
            ".transaction_id" => "[transaction_id]",
            ".credential" => "[credential]",
            ".c_nonce" => "[c_nonce]",
            ".notification_id" => "[notification_id]",
        });

        // extract credential response
        let cred_resp = response.credential_response;

        // verify credential
        let CredentialResponseType::Credential(vc_kind) = &cred_resp.response else {
            panic!("expected a single credential");
        };
        let Payload::Vc { vc, .. } =
            proof::verify(Verify::Vc(&vc_kind), provider.clone()).await.expect("should decode")
        else {
            panic!("should be VC");
        };

        assert_snapshot!("deferred:deferred_ok:vc", vc, {
            ".validFrom" => "[validFrom]",
            ".credentialSubject" => insta::sorted_redaction()
        });

        // token state should remain unchanged
        assert_let!(Ok(state), StateStore::get::<State>(&provider, access_token).await);
        assert_snapshot!("deferred:deferred_ok:state", state, {
            ".expires_at" => "[expires_at]",
            ".stage.access_token" => "[access_token]",
            ".stage.c_nonce"=>"[c_nonce]",
            ".stage.c_nonce_expires_at" => "[c_nonce_expires_at]"
        });

        // deferred state should not exist
        assert!(StateStore::get::<State>(&provider, transaction_id).await.is_err());
    }
}
