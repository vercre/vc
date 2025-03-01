//! Tests for the `deferred` endpoint

mod utils;

use std::collections::HashMap;

use assert_let_bind::assert_let;
use chrono::Utc;
use credibil_infosec::jose::JwsBuilder;
use credibil_vc::issuer;
use credibil_vc::issuer::state::{Authorized, Deferrance, Expire, Stage, State, Token};
use credibil_vc::openid::issuer::{
    CredentialRequest, CredentialResponseType, DeferredCredentialRequest, ProofClaims,
};
use credibil_vc::openid::provider::StateStore;
use credibil_vc::w3c_vc::proof::{self, Payload, Type, Verify};
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::json;
use test_issuer::{CLIENT_ID, CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn deferred_ok() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

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
        .add_signer(&test_holder::ProviderImpl)
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

    StateStore::put(&provider, access_token, &state, state.expires_at).await.expect("state exists");

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

    let response = issuer::deferred(provider.clone(), request).await.expect("response is valid");
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
