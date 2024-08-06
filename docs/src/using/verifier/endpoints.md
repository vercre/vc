# Endpoints

The presentation API is comprised of the a set of endpoints,
called in sequence to issue a Credential. The primary endpoints are:

- `Create Request` — prepares an Authorization Request for the Verifier to send to the 
  Wallet to request authorization (in the form of Verifiable Presentations).

- `Authorization Request` — used by the Wallet in cross-device flows to retrieve a 
  previously created Authorization Request Object.

- `Authorization Response` — the endpoint the Wallet sends the Authorization Response
  (containing Verifiable Presentations) back to the Verifier.

- `Verifier Metadata` — endpoint to surface Verifier metadata to the Wallet.

Each endpoint is described in more detail below.

## Exposing Endpoints

In order for Wallets to interact with presentation API, endpoints must be exposed over HTTP.

The following is a minimal example web server exposing endpoints required to support a 
minimal Pre-Authorized flow example. The example uses [axum](https://docs.rs/axum/latest/axum/), 
but any Rust web server should suffice.

For the sake of brevity, imports, tracing, etc. are omitted. A more complete example can
be found in the [examples directory](https://github.com/vercre/vercre/tree/main/examples/verifier).

```rust,ignore
#[tokio::main]
async fn main() {
    // http endpoints
    let router = Router::new()
        .route("/create_request", post(create_request))
        .route("/request/:client_state", get(request_object))
        .route("/callback", get(response))
        .route("/post", post(response))
        .with_state(Provider::new());  // <- set up requisite providers in server state

    // run the server
    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    axum::serve(listener, router).await.expect("server should run");
}
```

### Endpoint handlers

In our example above, we have defined handlers for each `axum` route. Each handler
is responsible for converting the HTTP request to a request object that can be passed
to the associated endpoint.

The following example shows how the `create_request` handler uses `axum` to wrap the
heavy lifting of converting the HTTP request body to a `CreateRequestRequest` object
ready to forward to the endpoint.

Other than forwarding the request to the library, the handler is responsible for setting
the `verifier` attribute on the request object. This value should come from one
of `host`, `:authority`, or `Forwarded` (if behind a proxy) headers of the HTTP request.

```rust,ignore
async fn create_request(
    State(endpoint): State<Provider>,  // <- get providers from state
    TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<CreateRequestRequest>,        // <- convert request body
) -> AxResult<CreateOfferResponse> {
    request.client_id = format!("http://{host}");     // <- set verifier
    vercre_verifier::create_request(provider, &request).await.into()    // <- forward to library
}
```

## More On Endpoints

The following sections describe each endpoint in more detail, highlighting the
implementer responsibilities and expected behavior.

**Cache-Control** 

The presentation HTTP API MUST include the HTTP `Cache-Control` response header
(per [RFC2616](https://www.rfc-editor.org/rfc/rfc2616)) with values of `"no-store"`
and `"no-cache"` in any responses containing sensitive information. That is, from all
endpoints except the Metadata endpoint.

### Create Rquest

The `Create Request` endpoint is used by the Verifier to create an Authorization Request. 
The Request is used to initiate the presentation process with the Wallet by sending it 
directly to the Wallet as a Request Object or by the Wallet scanning a QR code to get a 
URL pointing to the location of the Request Object.

### Authorization Request

The `Authorization Request` endpoint is used by the Wallet to retrieve a previously
created Authorization Request Object.

The Request Object is created by the Verifier when calling the `Create Request` endpoint to
create an Authorization Request. Instead of sending the Request Object to the Wallet,
the Verifier sends an Authorization Request containing a `request_uri` which can be
used to retrieve the saved Request Object.

### Response

The `Response` endpoint is where the Wallet sends its response, in the form of an 
[RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html) Authorization Response to the
Verifier's Authorization Request.

If the Authorization Request's Response Type value is "`vp_token`", the VP Token
is returned in the Authorization Response. When the Response Type value is
"`vp_token id_token`" and the scope parameter contains "openid", the VP Token is
returned in the Authorization Response alongside a Self-Issued ID Token as defined
in [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html).

If the Response Type value is "code" (Authorization Code Grant Type), the VP
Token is provided in the Token Response.

### Metadata

The `Metadata` endpoint is used to make Verifier metadata available to the Wallet.

As the Verifier is a client to the Wallet's Authorization Server, this endpoint
returns Client metadata as defined in [RFC7591](https://www.rfc-editor.org/rfc/rfc7591).

