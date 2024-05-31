# Issuance

Based on the [OpenID for Verifiable Credential Issuance] specification, the [vercre-vci]
library provides an API for issuing Verifiable Credentials.

The specification defines an API for Credential issuance provided by a Credential Issuer. 

The API is comprised of the following endpoints:

- `Create Offer` — for Issuer-initiated Credential issuance (Pre-Authorized Code flow).

- `Authorization` — for Wallet authorization and Wallet-initiated Credential issuance
  (Authorization Code flow).

- `Token` — for the Wallet to exchange an authorization code for an access token 
  during both pre-authorized code and authorization code flows.

- `Credential` — for Credential issuance.

- `Batch Credential` — for issuance of multiple Credentials in a single batch.

- `Deferred Credential` — for deferred issuance of Credentials.

- `Metadata` — publishes metadata about the Issuer and the Credentials they can issue.

- `Notification` — for the Issuer to receive Wallet notifications about the status of 
  issued Credentials.


## HTTP Endpoints

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

## Providers

So far, so straightforward. The real work for API users is in implementing providers.

Providers allow the library request implementation-specific data, and functionality.
Each provider implements its corresponding trait, as defined in [`vercre-vci`].

Providers are:

- `Client` — provides Client metadata, typically from a persistent data store or 
  external API.

- `Issuer` — provides Credential Issuer metadata, as above.

- `Server` — provides Authorization Server metadata, as above.

- `Callback` — used to notify a wallet or other client of issuance status.

- `Holder` — provides holder (or user) user information used during credential issuance.

- `StateManager` — used to temporarily store and manage server state.

- `Signer` — provide signing functionality, typically implemented using a secure
  enclave or HSM.

The `Client` provider trait is shown below as an example. For a more complete example, see 
Vercre's [example providers](https://github.com/vercre/vercre/blob/main/crates/test-utils/src/vci-provider.rs)
used in examples and tests.

```rust,ignore
/// The Client trait is used by implementers to provide Client metadata to the
/// library.
pub trait Client: Send + Sync {
    /// Returns client metadata for the specified client.
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<ClientMetadata>> + Send;

    /// Used by OAuth 2.0 clients to dynamically register with the authorization
    /// server.
    fn register(
        &self, client_meta: &ClientMetadata,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;
}
```

[OpenID for Verifiable Credential Issuance]: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
[vercre-vci]: https://github.com/vercre/vercre/tree/main/vercre-vci