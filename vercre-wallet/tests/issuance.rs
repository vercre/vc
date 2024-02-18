mod issuer;

use assert_let_bind::assert_let;
use axum_test::http::header::{HeaderValue, AUTHORIZATION};
use crux_core::testing::AppTester; // assert_effect,
use crux_http::protocol::HttpResponse;
use crux_http::testing::ResponseBuilder;
use http_types::Body;
use insta::assert_yaml_snapshot as assert_snapshot;
use serde_json::{json, Value};
use test_utils::vci_provider::NORMAL_USER;
use test_utils::wallet;
use vercre_core::vci::{
    CredentialResponse, InvokeResponse, MetadataResponse, TokenRequest, TokenResponse,
};
use vercre_wallet::capabilities::signer::{SignerRequest, SignerResponse};
use vercre_wallet::capabilities::store::StoreResponse;
use vercre_wallet::credential;
use vercre_wallet::issuance::*;

/// Test that a `Offer` event causes the app to fetch credentials
/// in the offer.
#[tokio::test]
async fn receive_offer() {
    let issuer = issuer::new();

    // instantiate our app via the test harness
    let app = AppTester::<App, _>::default();
    let mut model = Model::default();

    // create InvokeRequest
    let body = json!({
        "credentials": ["EmployeeID_JWT"],
        "holder_id": NORMAL_USER,
        "pre-authorize": true,
        "user_pin_required": true,
        "callback_id": "1234"
    });

    let resp = issuer.post("/invoke").expect_success().json(&body).await;

    // generate issuer offer to 'send' to the app
    let offer_resp = resp.json::<InvokeResponse>();
    let offer = offer_resp.credential_offer.expect("should have offer");

    // ------------------------------------------------
    // Event::Offer
    //   1. saves offer to model
    //   2. creates an Issuer MetadataRequest
    //   3. emits Event::Metadata
    // ------------------------------------------------
    let offer_str = serde_json::to_string(&offer).expect("offer should serialize to string");

    let mut update = app.update(Event::Offer(offer_str), &mut model);
    assert_snapshot!("offer", app.view(&model),{
        ".offered" => insta::sorted_redaction(),

    });

    // make real metadata request
    assert_let!(Effect::Http(request), &mut update.effects[0]);
    let op = &request.operation;
    assert_eq!(op.url, format!("{}/.well-known/openid-credential-issuer", &offer.credential_issuer));

    let resp = issuer.get("/.well-known/openid-credential-issuer").expect_success().await;
    let metadata: MetadataResponse = resp.json();
    let response = HttpResponse::ok().body(resp.into_bytes()).build();
    let update = app.resolve(request, response).expect("update");

    // check the app emitted an (internal) event to update the model
    let response = ResponseBuilder::ok().body(metadata.clone()).build();
    assert_eq!(update.events, vec![Event::Metadata(Ok(response.clone()))]);

    // ------------------------------------------------
    // Event::Metadata
    //   1. saves metadata to model
    // ------------------------------------------------
    app.update(Event::Metadata(Ok(response)), &mut model);
    assert_snapshot!("metadata", app.view(&model), {
        ".offered" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject" => insta::sorted_redaction()
    });

    // ------------------------------------------------
    // Event::Accept
    //   1. emits Event::GetToken
    // ------------------------------------------------
    app.update(Event::Accept, &mut model);
    assert_snapshot!("accept", app.view(&model), {
        ".credentials" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject" => insta::sorted_redaction()
    });

    // ------------------------------------------------
    // Event::Pin
    //   1. emits Event::GetToken
    // ------------------------------------------------
    let user_pin = offer_resp.user_pin.expect("user pin should be set");
    let mut update = app.update(Event::Pin(user_pin.clone()), &mut model);
    assert_snapshot!("pin", app.view(&model), {
        ".credentials" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject"=> insta::sorted_redaction()
    });

    // ------------------------------------------------
    // Event::GetToken
    //   1. creates a TokenRequest
    //   2. emits Event::Token
    // ------------------------------------------------
    assert_let!(Effect::Http(request), &mut update.effects[0]);
    assert_eq!(request.operation.url, format!("{}/token", &offer.credential_issuer));

    // make real token request
    let body = Body::from_bytes(request.operation.body.clone());
    let form: TokenRequest = body.into_form().await.expect("should deserialize");
    let resp = issuer.post("/token").form(&form).expect_success().await;

    // resolve the app request with a ~~simulated~~ response from the server
    let token: TokenResponse = resp.json();
    let response = HttpResponse::ok().body(resp.into_bytes()).build();
    let update = app.resolve(request, response).expect("update");

    // check the app emitted an (internal) event to update the model
    let response = ResponseBuilder::ok().body(token.clone()).build();
    assert_eq!(update.events, vec![Event::Token(Ok(response.clone()))]);

    // ------------------------------------------------
    // Event::Token
    //   1. saves TokenResponse to model
    //   2. requests verification method from shell
    //   2. emits Event::Proof with verification result
    // ------------------------------------------------
    let mut update = app.update(Event::Token(Ok(response)), &mut model);
    assert_snapshot!("token", app.view(&model), {
        ".credentials" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject"=> insta::sorted_redaction()
    });

    assert_let!(Effect::Signer(request), &mut update.effects[0]);
    assert_eq!(request.operation, SignerRequest::Verification);

    // simulate the SignerResponse
    let response = SignerResponse::Verification {
        alg: wallet::alg(),
        kid: wallet::kid(),
    };
    let update = app.resolve(request, response).expect("an update");

    // verify the app emitted a Proof event
    assert_let!(Event::Proof(Ok((alg, kid))), &update.events[0]);

    // ------------------------------------------------
    // Event::Proof
    //   1. saves SignerResult to model
    //   requests JWT signing from shell
    //   2. emits Event::Signed
    // ------------------------------------------------
    let mut update = app.update(Event::Proof(Ok((alg.clone(), kid.clone()))), &mut model);

    assert_snapshot!("proof", app.view(&model), {
        ".credentials" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject"=> insta::sorted_redaction()
    });

    // check that the app emitted a Signer request
    assert_eq!(update.events, vec![]);
    assert_let!(Effect::Signer(request), &mut update.effects[0]);
    assert_let!(SignerRequest::Sign(msg), &request.operation);

    // simulate the SignerResponse
    let signature = wallet::sign(msg);
    let response = SignerResponse::Signature(signature);
    let update = app.resolve(request, response).expect("an update");

    // verify the app emitted a Signed event
    assert_let!(Event::Signed(Ok(signed)), &update.events[0]);

    // ------------------------------------------------
    // Event::Signed
    //   1. saves TokenResponse to model
    //   2. emits Event::GetCredential for each credential in offer
    // ------------------------------------------------
    let mut update = app.update(Event::Signed(Ok(signed.to_string())), &mut model);
    assert_snapshot!("signed", app.view(&model), {
        ".credentials" => insta::sorted_redaction(),
        ".offered.*.credential_definition.credentialSubject"=> insta::sorted_redaction()
    });

    assert_let!(Effect::Http(request), &mut update.effects[0]);
    let op = &request.operation;
    assert_eq!(op.url, format!("{}/credential", &offer.credential_issuer));

    // make real credential request
    let body: Value = serde_json::from_slice(&op.body).expect("should deserialize");
    let auth_header = HeaderValue::from_str(&format!("Bearer {}", &token.access_token))
        .expect("should create header");
    let resp = issuer
        .post("/credential")
        .add_header(AUTHORIZATION, auth_header)
        .json(&body)
        .expect_success()
        .await;

    // resolve the app request with a ~~simulated~~ response from the server
    let cred: CredentialResponse = resp.json();
    let response = HttpResponse::ok().body(resp.into_bytes()).build();
    let update = app.resolve(request, response).expect("update");

    // check the app emitted an (internal) event to interpret the response
    let response = ResponseBuilder::ok().body(cred.clone()).build();
    assert_eq!(update.events, vec![Event::Credential(Ok(response.clone()))]);

    // ------------------------------------------------
    // Event::Credential
    //   1. Unpacks Credential from CredentialResponse
    //   2. emits Event::GetLogo
    // ------------------------------------------------

    let mut update = app.update(Event::Credential(Ok(response.clone())), &mut model);
    assert_let!(Effect::Http(_request), &mut update.effects[0]);
    let response =
        ResponseBuilder::ok().body(b"sample".to_vec()).header("Content-Type", "image/png").build();
    let credential = credential::Credential::sample();
    let mut update = app.update(Event::Logo(credential, Ok(response.clone())), &mut model);

    // ------------------------------------------------
    // Event::AddCredential
    //   1. saves Credential to store
    //   2. emits Event::CredentialAdded
    // ------------------------------------------------

    // resolve store.add() output
    assert_let!(Effect::Store(request), &mut update.effects[0]);
    let update = app.resolve(request, StoreResponse::Ok).expect("update");

    // ------------------------------------------------
    // Event::CredentialAdded
    //   1. model is reset
    // ------------------------------------------------
    app.update(update.events[0].clone(), &mut model);
    assert_snapshot!("credential-saved", app.view(&model));
}
