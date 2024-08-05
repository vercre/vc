# Providers

While exposing and implementing endpoints may be relatively straightforward, the real
work is in implementing providers.

Providers are a set of Rust traits that allow the library to outsource 
data persistence, secure signing, and callback functionality. Each provider requires the
library user to implement a corresponding trait, as defined below.

_See Vercre's example
[issuance providers](https://github.com/vercre/vercre/blob/main/examples/providers/src/issuance.rs)
for more detail._

## Client

The `Client` provider is responsible for managing the OAuth 2.0 Client — or Verifier —
metadata on behalf of the library. In the case of Verifiable Presentation, the Verifier 
is a client of the Authorization Server (the Wallet). The provider retrieves Client 
metadata.

```rust,ignore
pub trait Client: Send + Sync {
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<ClientMetadata>> + Send;
}
```

## StateManager

As its name implies, `StateManager` is responsible for temporarily storing and 
managing state on behalf of the library.

```rust,ignore
pub trait StateManager: Send + Sync {
    fn put(&self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn get(&self, key: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;

    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}
```

## Signer

The `Signer` provides the library with secure signing functionality by implementing
one of the supported signing and verification algorithms. Typically, implementers
will use a key vault, secure enclave, or HSM to manage private keys used for signing.

```rust,ignore
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> Algorithm;

    fn verification_method(&self) -> String;

    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
```

## Callback

The library uses callbacks to notify the Wallet or other interested parties of 
verification status during the verification process.

```rust,ignore
pub trait Callback: Send + Sync {
    fn callback(&self, pl: &callback::Payload) -> impl Future<Output = Result<()>> + Send;
}
```
