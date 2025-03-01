//! Tests for the notification endpoint.

mod utils;

use assert_let_bind::assert_let;
use chrono::Utc;
use credibil_vc::oid4vci;
use credibil_vc::oid4vci::provider::StateStore;
use credibil_vc::oid4vci::state::{Credential, Expire, Stage, State};
use credibil_vc::oid4vci::types::{NotificationEvent, NotificationRequest};
use credibil_vc::w3c_vc::model::VerifiableCredential;
use insta::assert_yaml_snapshot as assert_snapshot;
use test_issuer::{CREDENTIAL_ISSUER, NORMAL_USER};

#[tokio::test]
async fn notification_ok() {
    utils::init_tracer();
    snapshot!("");
    let provider = test_issuer::ProviderImpl::new();

    let notification_id = "123456";

    let state = State {
        expires_at: Utc::now() + Expire::Authorized.duration(),
        subject_id: Some(NORMAL_USER.into()),
        stage: Stage::Issued(Credential {
            credential: VerifiableCredential::default(),
        }),
    };
    StateStore::put(&provider, notification_id, &state, state.expires_at)
        .await
        .expect("state exists");

    let request = NotificationRequest {
        credential_issuer: CREDENTIAL_ISSUER.to_string(),
        access_token: "ABCDEF".into(),
        notification_id: notification_id.into(),
        event: NotificationEvent::CredentialAccepted,
        event_description: Some("Credential accepted".into()),
    };
    let response = oid4vci::endpoint::handle(CREDENTIAL_ISSUER, request, &provider)
        .await
        .expect("response is ok");

    assert_snapshot!("notification:ok:response", response);
    assert_let!(Err(_), StateStore::get::<State>(&provider, notification_id).await);
}
