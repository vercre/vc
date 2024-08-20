//! # HTTP Server Example
//!
//! This example demonstrates how to use the Verifiable Credential Issuer (VCI)

mod provider;

use std::collections::HashMap;
use std::sync::LazyLock;

use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use axum_extra::headers::authorization::Bearer;
use axum_extra::headers::{Authorization, Host};
use axum_extra::TypedHeader;
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;
use vercre_issuer::{
    AuthorizationRequest, CreateOfferRequest, CreateOfferResponse, CredentialOfferRequest,
    CredentialOfferResponse, CredentialRequest, CredentialResponse, DeferredCredentialRequest,
    DeferredCredentialResponse, MetadataRequest, MetadataResponse, TokenRequest, TokenResponse,
};

use crate::provider::Provider;

static AUTHORIZED: LazyLock<RwLock<HashMap<String, AuthorizationRequest>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[tokio::main]
async fn main() {
    let subscriber = FmtSubscriber::builder().with_max_level(Level::ERROR).finish();
    tracing::subscriber::set_global_default(subscriber).expect("set subscriber");

    let cors = CorsLayer::new().allow_methods(Any).allow_origin(Any).allow_headers(Any);

    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/credential_offer/:offer_id", get(credential_offer))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .route("/auth", get(authorize))
        .route("/login", post(login))
        .route("/token", post(token))
        .route("/credential", post(credential))
        .route("/deferred_credential", post(deferred_credential))
        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache, no-store"),
        ))
        .with_state(Provider::new());

    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    tracing::info!("listening on {}", listener.local_addr().expect("should have addr"));
    axum::serve(listener, router).await.expect("server should run");
}

// Credential Offer endpoint
#[axum::debug_handler]
async fn create_offer(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<CreateOfferRequest>,
) -> AxResult<CreateOfferResponse> {
    req.credential_issuer = format!("http://{host}");

    vercre_issuer::create_offer(provider, &req).await.into()
}

// Retrieve Authorization Request Object endpoint
#[axum::debug_handler]
async fn credential_offer(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    Path(offer_id): Path<String>,
) -> AxResult<CredentialOfferResponse> {
    let request = CredentialOfferRequest {
        credential_issuer: format!("http://{host}"),
        id: offer_id,
    };
    vercre_issuer::credential_offer(provider, &request).await.into()
}

// Metadata endpoint
// TODO: override default  Cache-Control header to allow caching
#[axum::debug_handler]
async fn metadata(
    headers: HeaderMap, State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
) -> AxResult<MetadataResponse> {
    let req = MetadataRequest {
        credential_issuer: format!("http://{host}"),
        languages: headers
            .get("accept-language")
            .and_then(|v| v.to_str().ok())
            .map(ToString::to_string),
    };
    vercre_issuer::metadata(provider.clone(), &req).await.into()
}

/// Authorize endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-4.1.2
///
/// The authorization server issues an authorization code and delivers it to the
/// client by adding the response parameters to the query component of the redirection
/// URI using the "application/x-www-form-urlencoded" format.
#[axum::debug_handler]
async fn authorize(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    Form(mut req): Form<AuthorizationRequest>,
) -> impl IntoResponse {
    // return error if no subject_id
    if req.subject_id.is_empty() {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no subject_id"}))).into_response();
    }

    // show login form if subject_id is unauthorized
    // (subject is authorized if they can be found in the 'authorized' HashMap)
    if AUTHORIZED.read().await.get(&req.subject_id).is_none() {
        // save request
        let csrf = CsrfToken::new_random();
        let token = csrf.secret();

        AUTHORIZED.write().await.insert(token.clone(), req);

        // prompt user to login
        let login_form = format!(
            r#"
            <form method="post" action="/login">
                <input type="text" name="username" placeholder="username" value="normal_user" />
                <input type="password" name="password" placeholder="password" value="password" />
                <input type="hidden" name="csrf_token" value="{token}" />
                <input type="submit" value="Login" />
            </form>
            "#
        );
        return (StatusCode::UNAUTHORIZED, Html(login_form)).into_response();
    }

    // process request
    req.credential_issuer = format!("http://{host}");

    let Some(redirect_uri) = req.redirect_uri.clone() else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "no redirect_uri"})))
            .into_response();
    };

    match vercre_issuer::authorize(provider.clone(), &req).await {
        Ok(v) => (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?code={}", v.code)))
            .into_response(),
        Err(e) => {
            let err_params = e.to_querystring();
            (StatusCode::FOUND, Redirect::to(&format!("{redirect_uri}?{err_params}")))
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    csrf_token: String,
}

#[axum::debug_handler]
async fn login(
    TypedHeader(host): TypedHeader<Host>, Form(req): Form<LoginRequest>,
) -> impl IntoResponse {
    // check username and password
    if req.username != "normal_user" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid username"})))
            .into_response();
    }
    if req.password != "password" {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid password"})))
            .into_response();
    }

    // update 'authorized' HashMap with subject as key
    let Some(auth_req) = AUTHORIZED.write().await.remove(&req.csrf_token) else {
        return (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid csrf_token"})))
            .into_response();
    };
    AUTHORIZED.write().await.insert(req.username.clone(), auth_req.clone());

    // redirect back to authorize endpoint
    let qs = serde_qs::to_string(&auth_req).expect("should serialize");
    (StatusCode::FOUND, Redirect::to(&format!("http://{host}/auth?{qs}"))).into_response()
}

/// Token endpoint
/// RFC 6749: https://tools.ietf.org/html/rfc6749#section-5.1
///
/// The parameters are included in the entity-body of the HTTP response using the
/// "application/json" media type as defined by [RFC4627].  The parameters are
/// serialized into JSON
///
/// The authorization server MUST include the HTTP "Cache-Control" response header
/// field [RFC2616] with a value of "no-store" in any response containing tokens,
/// credentials, or other sensitive information, as well as the "Pragma" response
/// header field [RFC2616] with a value of "no-cache".
///
/// [RFC2616]: (https://www.rfc-editor.org/rfc/rfc2616)
#[axum::debug_handler]
async fn token(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    Form(mut req): Form<TokenRequest>,
) -> AxResult<TokenResponse> {
    req.credential_issuer = format!("http://{host}");
    vercre_issuer::token(provider.clone(), &req).await.into()
}

// Credential endpoint
#[axum::debug_handler]
async fn credential(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>, Json(mut req): Json<CredentialRequest>,
) -> AxResult<CredentialResponse> {
    req.credential_issuer = format!("http://{host}");
    req.access_token = auth.token().to_string();
    vercre_issuer::credential(provider.clone(), &req).await.into()
}

// Deferred endpoint
#[axum::debug_handler]
async fn deferred_credential(
    State(provider): State<Provider>, TypedHeader(host): TypedHeader<Host>,
    TypedHeader(auth): TypedHeader<Authorization<Bearer>>,
    Json(mut req): Json<DeferredCredentialRequest>,
) -> AxResult<DeferredCredentialResponse> {
    req.credential_issuer = format!("http://{host}");
    req.access_token = auth.0.token().to_string();
    vercre_issuer::deferred(provider.clone(), &req).await.into()
}

// ----------------------------------------------------------------------------
// Axum Response
// ----------------------------------------------------------------------------

/// Wrapper for `axum::Response`
pub struct AxResult<T>(vercre_issuer::Result<T>);

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

impl<T> From<vercre_issuer::Result<T>> for AxResult<T> {
    fn from(val: vercre_issuer::Result<T>) -> Self {
        Self(val)
    }
}
