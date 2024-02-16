use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Host};
use axum_extra::TypedHeader;
use axum_test::http::header::HOST;
use axum_test::http::HeaderValue;
use axum_test::TestServer;
use serde::Serialize;
use serde_json::json;
use test_utils::vci_provider::Provider;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use vercre_vci::endpoint::{
    AuthorizationRequest, BatchCredentialRequest, BatchCredentialResponse, CredentialRequest,
    CredentialResponse, DeferredCredentialRequest, DeferredCredentialResponse, Handler,
    InvokeRequest, InvokeResponse, MetadataRequest, MetadataResponse, TokenRequest, TokenResponse,
};

#[derive(Clone)]
pub struct AppState {
    provider: Provider,
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

impl AppState {
    pub fn new() -> Self {
        Self {
            provider: Provider::new(),
        }
    }
}

// Set up issuance test server
pub fn new() -> TestServer {
    // set host header for all requests
    let mut server = TestServer::new(app()).expect("new server");
    server.add_header(HOST, HeaderValue::from_static("credibil.io"));
    server
}

pub fn app() -> Router {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let state = Arc::new(AppState::new());
    Router::new()
        .route("/pre-auth", post(credential_offer))
        .route("/auth", get(authorize))
        .route("/token", post(token))
        .route("/credential", post(credential))
        .route("/deferred_credential", post(deferred_credential))
        .route("/batch_credential", post(batch_credential))
        .route("/metadata", get(metadata))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// Push endpoint
async fn credential_offer(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<InvokeRequest>,
) -> AxResult<InvokeResponse> {
    req.credential_issuer = format!("http://{}", host);
    Handler::new(&state.provider, req).call().await.into()
}

// Authorize endpoint
async fn authorize(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    Form(mut req): Form<AuthorizationRequest>,
) -> impl IntoResponse {
    req.credential_issuer = format!("http://{}", host);

    // check whether requestor is authenticated
    if req.holder_id.is_empty() {
        return Redirect::to("auth_url").into_response();
    }

    // TODO: do redirect here
    // process request
    let res = Handler::new(&state.provider, req).call().await;
    AxResult(res).into_response()
}

// Token endpoint
async fn token(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    Form(mut req): Form<TokenRequest>,
) -> AxResult<TokenResponse> {
    req.credential_issuer = format!("http://{}", host);
    Handler::new(&state.provider, req).call().await.into()
}

// Credential endpoint
async fn credential(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>, Json(mut req): Json<CredentialRequest>,
) -> AxResult<CredentialResponse> {
    req.credential_issuer = format!("http://{}", host);
    req.access_token = auth.token().to_string().clone();
    Handler::new(&state.provider, req).call().await.into()
}

pub async fn deferred_credential(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
) -> AxResult<DeferredCredentialResponse> {
    // TODO: move request generation to client
    let req = DeferredCredentialRequest {
        credential_issuer: format!("http://{}", host),
        access_token: auth.0.token().to_string(),
        // TODO: generate transaction_id
        transaction_id: auth.0.token().to_string(),
    };
    Handler::new(&state.provider, req).call().await.into()
}

pub async fn batch_credential(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(mut req): Json<BatchCredentialRequest>,
) -> AxResult<BatchCredentialResponse> {
    req.credential_issuer = format!("http://{}", host);
    req.access_token = auth.0.token().to_string();
    Handler::new(&state.provider, req).call().await.into()
}

// '/metadata' endpoint
pub async fn metadata(
    State(state): State<Arc<AppState>>, TypedHeader(host): TypedHeader<Host>,
) -> AxResult<MetadataResponse> {
    let req = MetadataRequest {
        credential_issuer: format!("http://{}", host),
    };
    Handler::new(&state.provider, req).call().await.into()
}

// ----------------------------------------------------------------------------
// Axum Response
// ----------------------------------------------------------------------------

pub struct AxResult<T>(vercre_core::Result<T>);

impl<T> IntoResponse for AxResult<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        match self.0 {
            Ok(v) => (StatusCode::OK, Json(json!(v))),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(e.to_json())),
        }
        .into_response()
    }
}

impl<T> From<vercre_core::Result<T>> for AxResult<T> {
    fn from(val: vercre_core::Result<T>) -> Self {
        Self(val)
    }
}
