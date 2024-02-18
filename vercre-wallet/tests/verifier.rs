use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::headers::Host;
use axum_extra::TypedHeader;
use axum_test::http::header::HOST;
use axum_test::http::HeaderValue;
use axum_test::TestServer;
use serde::Serialize;
use serde_json::json;
use test_utils::vp_provider::Provider;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use vercre_vp::endpoint::{
    Endpoint, InvokeRequest, InvokeResponse, RequestObjectRequest, RequestObjectResponse,
    ResponseRequest,
};

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

    let endpoint = Arc::new(Endpoint::new(Provider::new()));

    Router::new()
        .route("/invoke", post(invoke))
        .route("/request/:client_state", get(request_object))
        .route("/callback", get(response))
        .route("/post", post(response))
        .layer(TraceLayer::new_for_http())
        .with_state(endpoint)
}

// Generate Authorization Request endpoint
#[axum::debug_handler]
async fn invoke(
    State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<InvokeRequest>,
) -> AxResult<InvokeResponse> {
    req.client_id = format!("http://{}", host);
    endpoint.invoke(req).await.into()
}

// Retrieve Authorization Request Object endpoint
#[axum::debug_handler]
async fn request_object(
    State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
    Path(client_state): Path<String>,
) -> AxResult<RequestObjectResponse> {
    let req = RequestObjectRequest {
        client_id: format!("http://{}", host),
        state: client_state,
    };
    endpoint.request_object(req).await.into()
}

// Wallet Authorization response endpoint
#[axum::debug_handler]
async fn response(
    State(endpoint): State<Arc<Endpoint<Provider>>>, Form(req): Form<ResponseRequest>,
) -> impl IntoResponse {
    let res = endpoint.response(req).await;
    AxResult(res)
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
