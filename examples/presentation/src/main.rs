// mod provider;

//! # Verifiable Credential Provider
//!
//! This is a simple Verifiable Credential Provider (VCP) that implements the
//! [Verifiable Credential HTTP API](
//! https://identity.foundation/verifiable-credential/spec/#http-api).

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::headers::Host;
use axum_extra::TypedHeader;
use providers::presentation::Provider;
use serde::Serialize;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use vercre_verifier::create_request::{CreateRequestRequest, CreateRequestResponse};
use vercre_verifier::request::{RequestObjectRequest, RequestObjectResponse};
use vercre_verifier::response::ResponseRequest;
use vercre_verifier::Endpoint;

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    let endpoint = Arc::new(Endpoint::new(Provider::new()));
    // CORS. Just an example for local development. Set this properly in production.
    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/create_request", post(create_request))
        .route("/request/:client_state", get(request_object))
        .route("/callback", get(response))
        .route("/post", post(response))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(endpoint);

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("local_addr should be set"));
    axum::serve(listener, router).await.expect("should run");
}

// Generate Authorization Request endpoint
#[axum::debug_handler]
async fn create_request(
    State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
    Json(mut request): Json<CreateRequestRequest>,
) -> AxResult<CreateRequestResponse> {
    request.client_id = format!("http://{host}");
    endpoint.create_request(&request).await.into()
}

// Retrieve Authorization Request Object endpoint
#[axum::debug_handler]
async fn request_object(
    State(endpoint): State<Arc<Endpoint<Provider>>>, TypedHeader(host): TypedHeader<Host>,
    Path(client_state): Path<String>,
) -> AxResult<RequestObjectResponse> {
    let request = RequestObjectRequest {
        client_id: format!("http://{host}"),
        state: client_state,
    };
    endpoint.request_object(&request).await.into()
}

// Wallet Authorization response endpoint
#[axum::debug_handler]
async fn response(
    State(endpoint): State<Arc<Endpoint<Provider>>>, Form(request): Form<ResponseRequest>,
) -> impl IntoResponse {
    let response = endpoint.response(&request).await;
    AxResult(response)
}

// ----------------------------------------------------------------------------
// Axum Response
// ----------------------------------------------------------------------------

/// Axum response wrapper
pub struct AxResult<T>(openid4vc::Result<T>);

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

impl<T> From<openid4vc::Result<T>> for AxResult<T> {
    fn from(val: openid4vc::Result<T>) -> Self {
        Self(val)
    }
}
