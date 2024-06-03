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

## Issuer

The `Issuer` provider is responsible for making Credential Issuer metadata available to 
the issuance library. The library uses this metadata to determine the Issuer's 
capabilities as well as returning Credential metadata to the Wallet.

```rust,ignore
pub trait Issuer: Send + Sync {
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = Result<IssuerMetadata>> + Send;
}
```

## Server

The `Server` provider is responsible for making OAuth 2.0 Authorization Server metadata
available to the issuance library. As with Issuer metadata, the library uses this to 
determine capabilities of the Issuer.

```rust,ignore
pub trait Server: Send + Sync {
    fn metadata(&self, server_id: &str) -> impl Future<Output = Result<ServerMetadata>> + Send;
}
```

## Holder

The `Holder` provider is responsible for providing the issuance library with information
about the Holder, or end-user the Credential is to be issued to. This information is used
to:

1. Determine whether the Holder is authorized to receive the requested Credential.
2. Provide the information used to construct the issued Credential (including Credential 
   claims).

```rust,ignore
pub trait Holder: Send + Sync {
    fn authorize(
        &self, holder_id: &str, credential_configuration_id: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn claims(
        &self, holder_id: &str, credential: &CredentialDefinition,
    ) -> impl Future<Output = Result<Claims>> + Send;
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

Supported algorithms are defined in the Credential Issuer metadata.

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

The library uses callbacks to notify the Wallet or other interested parties of issuance
status during the issuance process.

```rust,ignore
pub trait Callback: Send + Sync {
    fn callback(&self, pl: &callback::Payload) -> impl Future<Output = Result<()>> + Send;
}
```
