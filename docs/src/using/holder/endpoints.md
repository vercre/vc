# Endpoints

The holder API is comprised of a set of endpoints that orchestrate the issuance or presentation of verifiable credentials. The holder endpoints assume the sequences implied by the [verce-issuer](../issuer/endpoints.md) and [verce-verifier](../verifier/endpoints.md) endpoints.

The primary endpoints for issuance are:

* `Offer` - processes an offer of a credential from the issuer and asks the issuer for metadata.
* `Accept` - receives acceptance from the holder to accept the offer.
* `PIN` - receives a PIN from the holder in cases where the issuer requires one and has sent the PIN via another channel.
* `Get Credential` - requests an access token from the issuer and then uses it to request the credential(s) on offer.

The primary endpoints for presentation are:

* `Request` - processes a request for presentation from a verifier.
* `Authorize` - receives authorization from the holder to make the presentation.
* `Present` - presents the requested credentials to the verifier.

## Exposing Endpoints

While the OpenID specification assumes HTTP endpoints for the issuer and verifier services, it may not be a practical protocol for a wallet. However, this does not mean it cannot be used. The repository provides a [non-HTTP example (using Tauri)](https://github.com/vercre/vercre/tree/main/examples/wallet) but the following is a minimal example web server exposing endpoints required to support a minimal Pre-Authorized flow example. The example uses [axum](https://docs.rs/axum/latest/axum/), but any Rust web server should suffice.

```rust,ignore
#[tokio::main]
async fn main() {
    // http endpoints
    let router = Router::new()
        .route("/offer", post(offer))
        .route("/accept", post(accept))
        .route("/pin", post(pin))
        .route("/credential", post(credential))
        .route("/request", post(request))
        .route("/authorize", post(authorize))
        .route("/present", post(present))
        .with_state(Provider::new());  // <- set up requisite providers in server state

    // run the server
    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("should bind");
    axum::serve(listener, router).await.expect("server should run");
}
```

### Endpoint handlers

In our example above, we have defined handlers for each `axum` route. Each handler is responsible for converting the HTTP request to a request object that can be passed to the associated endpoint.

The following example shows how the `offer` handler uses `axum` to wrap the heavy lifting of converting the HTTP request body to an `OfferRequest` object ready to forward to the endpoint.

```rust,ignore
async fn offer(
    State(provider): State<Provider>,                 // <- get providers from state
    Json(mt req): Json<OfferRequest>,                 // <- convert request body
) -> AxResult<Issuance> {
    vercre_holder::offer(provider, &req).await.into() // <- forward to library
}
```

## More On Endpoints

The following sections describe each endpoint in more detail, highlighting the implementer responsibilities and exepected behavior.

### Offer

The `Offer` endpoint receives an offer for a credential from an issuer. This could be implemented, for example, by presenting a QR code to the wallet and passing the retrieved offer to this endpoint. The endpoint will get issuer and credential metadata from the issuer and stash state for subsequent steps in the issuance flow.

The endpoint returns the metadata information so that it can be displayed for consideration of acceptance by the holder.

### Accept

The `Accept` endpoint receives advice from the holder to proceed with issuance.

### PIN

The `PIN` endpoint receives a PIN from the holder in cases where the issuer requires one and has sent the PIN via another channel.

### Get Credential

The `Get Credential` endpoint requests an access token from the issuer and then uses it to request the credential(s) on offer. If required, the PIN will be used in the request. The credentials will be stored in a repository provided by the implementer.

### Request

The `Request` endpoint processes a request for presentation from a verifier. The request can be a fully-formed presentation request or a URI that the wallet can use to retrieve the request from the verifier. In the latter case, using the implementer's provider, the presentation request is retrieved.

The endpoint then looks for the requested credentials in the repository provided by the implementer and returns a rich representation of the presentation request so that it can be considered by the holder for authorization.

### Authorize

The `Authorize` endpoint receives advice from the holder to proceed with presentation.

### Present

The `Present` endpoint presents the requested credentials to the verifier. As required by the OpenID for Verifiable Presentations specification, the credentials are packaged as a Presentation Submission, signed by the implementer's `Signer` provider.
