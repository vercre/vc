# Endpoints

As mentioned previously, the issuance API is comprised of the a set of endpoints,
called in sequence to issue a Credential. The primary endpoints are:

- `Create Offer` — creates Credential Offer used by Issuer to initiate issuance
- `Authorization` — OAuth 2.0 Authorization endpoint
- `Token` — OAuth 2.0 Token endpoint
- `Credential` — issues requested Credential
- `Batch Credential` — issuances multiple Credentials in a single batch
- `Deferred Credential` — issues Credential when issuance has been 'deferred'
- `Metadata` — Issuer and Credential metadata
- `Notification` — used by the Wallet to notify of events about issued Credentials

Each endpoint is described in more detail further down.

## Exposing Endpoints

In order for Wallets to interact with issuance API, endpoints must be exposed over HTTP.

The following is a minimal example web server exposing endpoints required to support a 
minimal Pre-Authorized flow example. The example uses [axum](https://docs.rs/axum/latest/axum/), 
but any Rust web server should suffice.

For the sake of brevity, imports, tracing, etc. are omitted. A more complete example can
be found in the [examples directory](https://github.com/vercre/vercre/tree/main/examples/issuance).

```rust,ignore
#[tokio::main]
async fn main() {
    // set up requisite providers
    let endpoint = Arc::new(Endpoint::new(Provider::new()));

    // http endpoints
    let router = Router::new()
        .route("/create_offer", post(create_offer))
        .route("/.well-known/openid-credential-issuer", get(metadata))
        .route("/token", post(token))
        .route("/credential", post(credential))
        .with_state(endpoint);

    // run the server
    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    axum::serve(listener, router).await.expect("server should run");
}
```

### Endpoint handlers

In our example above, we have defined handlers for each `axum` route. Each handler
is responsible for converting the HTTP request to a request object that can be passed
to the associated endpoint.

The following example shows how the `create_offer` handler uses `axum` to wrap the
heavy lifting of converting the HTTP request body to a `CreateOfferRequest` object
ready to forward to the endpoint.

Other than forwarding the request to the library, the handler is responsible for setting
the `credential_issuer` attribute on the request object. This value should come from one
of `host`, `:authority`, or `Forwarded` (if behind a proxy) headers of the HTTP request.

```rust,ignore
async fn create_offer(
    State(endpoint): State<Arc<Endpoint<Provider>>>,  // <- get providers from state
    TypedHeader(host): TypedHeader<Host>,
    Json(mut req): Json<CreateOfferRequest>,          // <- convert request body
) -> AxResult<CreateOfferResponse> {
    req.credential_issuer = format!("http://{host}"); // <- set credential issuer
    endpoint.create_offer(&req).await.into()          // <- forward to library
}
```

## More On Endpoints

The following sections describe each endpoint in more detail, highlighting the
implementer responsibilities and expected behavior.

**Cache-Control** 

The issuance HTTP API MUST include the HTTP `Cache-Control` response header
(per [RFC2616](https://www.rfc-editor.org/rfc/rfc2616)) with values of `"no-store"`
and `"no-cache"` in any responses containing sensitive information. That is, from all
endpoints except the Metadata endpoint.

### Create Offer

The `Create Offer` endpoint is used by the Issuer to create a Credential Offer. The Offer
is used to initiate the issuance process with the Wallet by sending it directly to the
Wallet or by the Wallet scanning a QR code.

Below is an example of a JSON-based Credential Offer for a Pre-Authorized Code Flow.
The JSON is serialized from the `CreateOfferResponse` struct returned by the endpoint.

```json
{
    "credential_issuer": "https://credential-issuer.example.com",
    "credential_configuration_ids": [
        "UniversityDegree_LDP_VC"
    ],
    "grants": {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": "adhjhdjajkdkhjhdj",
            "tx_code": {
                "input_mode":"numeric",
                "length":6,
                "description":"Please provide the one-time code that was sent via e-mail"
            }
       }
    }
}
```

### Metadata

The `Metadata` endpoint is used by the Wallet to determine the capabilities of the
Issuer and the Credential. The metadata contains information on the Credential Issuer's
technical capabilities, supported Credentials, and (internationalized) display 
information.

The metadata MUST be published as a JSON document available at the path formed by 
concatenating the Credential Issuer Identifier (HTTP `host`) with the path
`/.well-known/openid-credential-issuer`.

For example,

```http
GET /.well-known/openid-credential-issuer HTTP/1.1
    Host: credential-issuer.example.com
    Accept-Language: fr-ch, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5
```

### Authorization

The `Authorization` endpoint is used by the Wallet to authorize the End-User for
access to the Credential endpoint. That is, to request issuance of a Credential. 

The endpoint is used in the same manner as defined in [RFC6749](https://www.rfc-editor.org/rfc/rfc6749.html).

**N.B.** It is the implementers responsibility to authenticate the End-User and ensure their
eligibility to receive the requested Credential.


### Token

The `Token` endpoint is used by the Wallet to exchange a Pre-Authorized Code or an 
Authorization Code for an Access Token. The Access Token can subsequently be used to
request a Credential at the Credential Endpoint.

The endpoint is used in the same manner as defined in [RFC6749](https://tools.ietf.org/html/rfc6749#section-5.1).

### Credential

The `Credential` endpoint is used by the Wallet to request Credential issuance. 

The Wallet sends the Access Token obtained at the Token Endpoint to this endpoint. The
Wallet MAY use the same Access Token to send multiple Credential Requests to request
issuance of multiple Credentials of different types bound to the same proof, or multiple
Credentials of the same type bound to different proofs.

### Batch Credential

The `Batch Credential` endpoint is used by the Wallet to request issuance of multiple Credentials
in a single batch. Other than batched Credential requests and responses, this endpoint is the same
as the Credential endpoint.

### Deferred Credential

The `Deferred Credential` endpoint is used by the Wallet to request issuance of a 
Credential where issuance was previously deferred (typically to allow for out-of-band
request processing).

### Notification

The `Notification` endpoint is used by the Wallet to notify the Issuer of events about 
issued Credentials. The Issuer uses this endpoint to receive notifications about the 
status of issued Credentials.
