# Endpoints

The following is a minimal example web server using the issuance API. The example uses 
[axum](https://docs.rs/axum/latest/axum/), but any Rust web server will suffice.

For the sake of brevity, imports, tracing, etc. are omitted. The full example can be 
found in the [examples directory](https://github.com/vercre/vercre/tree/main/examples/issuance).


```rust,ignore
#[tokio::main]
async fn main() {
    // set up requisite providers
    let endpoint = Arc::new(Endpoint::new(Provider::new()));

    // define http endpoints
    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/token", post(token))
        .route("/credential", post(credential))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .layer(cors)
        .with_state(endpoint);

    // run the server
    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    axum::serve(listener, router).await.expect("server should run");
}
```

By way of example, the `create_offer` handler is shown below. Here, the heavy lifting of
converting the HTTP request body to the `CreateOfferRequest` object is handled by `axum`.

Other than forwarding the request to the library, the handler is responsible for setting
the `credential_issuer` attribute on the request object. This typically comes from the
 `host`, `:authority`, or `Forwarded` (if behind a proxy) header of the HTTP request.

```rust,ignore
async fn create_offer(
    State(endpoint): State<Arc<Endpoint<Provider>>>, 
    TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<CreateOfferRequest>,
) -> AxResult<CreateOfferResponse> {
    req.credential_issuer = format!("http://{host}");
    endpoint.create_offer(&req).await.into()
}
```
