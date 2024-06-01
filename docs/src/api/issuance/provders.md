# Providers

So far, so straightforward. The real work for API users is in implementing providers.

Providers allow the library request implementation-specific data, and functionality.
Each provider implements its corresponding trait, as defined in 
[`vercre-vci`](https://github.com/vercre/vercre/tree/main/vercre-vci).

Each provider is defined by a trait that must be implemented by the library user.

### Client

The `Client` provider is responsible for managing the OAuth 2.0 Client — or Wallet —
metadata on behalf of the library. The provider retrieves Client metadata as well as
dynamic Client (Wallet) registration.

```rust,ignore
pub trait Client: Send + Sync {
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<ClientMetadata>> + Send;

    fn register(
        &self, client_meta: &ClientMetadata,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;
}
```

### Issuer

Provides Credential Issuer metadata, as above.

```rust,ignore
pub trait Issuer: Send + Sync {
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = Result<IssuerMetadata>> + Send;
}
```

### Server

Provides Authorization Server metadata, as above.

### Callback

Used to notify a wallet or other client of issuance status.

### Holder

Provides holder (or user) user information used during credential issuance.

### StateManager

Used to temporarily store and manage server state.

### Signer

Provide signing functionality, typically implemented using a secure enclave or HSM.



For a more complete example of providers, see Vercre's 
[example providers](https://github.com/vercre/vercre/blob/main/examples/providers/src/issuance.rs)
used in examples and tests.