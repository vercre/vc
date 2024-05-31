# Providers

So far, so straightforward. The real work for API users is in implementing providers.

Providers allow the library request implementation-specific data, and functionality.
Each provider implements its corresponding trait, as defined in 
[`vercre-vci`](https://github.com/vercre/vercre/tree/main/vercre-vci).

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

## Provider Traits

Providers are defined by traits that must be implemented by the library user.

By way of example, the `Client` provider trait is outlined below. 

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

For a more complete example of providers, see Vercre's 
[example providers](https://github.com/vercre/vercre/blob/main/examples/providers/src/issuance.rs)
used in examples and tests.