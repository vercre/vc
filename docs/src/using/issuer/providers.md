# Providers

While exposing and implementing endpoints may be relatively straightforward, the real
work is in implementing providers.

Providers are a set of Rust traits that allow the library to outsource 
data persistence, secure signing, and callback functionality. Each provider requires the
library user to implement a corresponding trait, as defined below.

_See Credibil VC's example
[issuer providers](https://github.com/credibil/vc/blob/main/examples/issuer/src/provider.rs)
for more detail._

## Client Metadata

The `ClientMetadata` provider is responsible for managing the OAuth 2.0 Client — or Wallet —
metadata on behalf of the library. The provider retrieves Client metadata as well as
dynamic Client (Wallet) registration.

```rust,ignore
pub trait ClientMetadata: Send + Sync {
    fn metadata(&self, client_id: &str) -> impl Future<Output = Result<ClientMetadata>> + Send;

    fn register(
        &self, client_meta: &ClientMetadata,
    ) -> impl Future<Output = Result<ClientMetadata>> + Send;
}
```

## Issuer Metadata

The `IssuerMetadata` provider is responsible for making Credential Issuer metadata available to 
the issuer library. The library uses this metadata to determine the Issuer's 
capabilities as well as returning Credential metadata to the Wallet.

```rust,ignore
pub trait IssuerMetadata: Send + Sync {
    fn metadata(&self, issuer_id: &str) -> impl Future<Output = Result<IssuerMetadata>> + Send;
}
```

## Server Metadata

The `ServerMetadata` provider is responsible for making OAuth 2.0 Authorization Server metadata
available to the issuer library. As with Issuer metadata, the library uses this to 
determine capabilities of the Issuer.

```rust,ignore
pub trait ServerMetadata: Send + Sync {
    fn metadata(&self, server_id: &str) -> impl Future<Output = Result<ServerMetadata>> + Send;
}
```

## Subject

The `Subject` provider is responsible for providing the issuer library with information
about the Holder, or end-user the Credential is to be issued to. This information is used
to:

1. Determine whether the Holder is authorized to receive the requested Credential.
2. Provide the information used to construct the issued Credential (including Credential 
   claims).

```rust,ignore
pub trait Subject: Send + Sync {
    fn authorize(
        &self, subject_id: &str, credential_identifier: &str,
    ) -> impl Future<Output = Result<bool>> + Send;

    fn claims(
        &self, subject_id: &str, credential: &CredentialDefinition,
    ) -> impl Future<Output = Result<Claims>> + Send;
}
```

## State Manager

As its name implies, `StateStore` is responsible for temporarily storing and 
managing state on behalf of the library.

```rust,ignore
pub trait StateStore: Send + Sync {
    fn put(&self, key: &str, data: Vec<u8>, expiry: DateTime<Utc>,
    ) -> impl Future<Output = Result<()>> + Send;

    fn get(&self, key: &str) -> impl Future<Output = Result<Vec<u8>>> + Send;

    fn purge(&self, key: &str) -> impl Future<Output = Result<()>> + Send;
}
```

## Data Security

`KeyOps` provides the library with functionality for signing, encrypting, verifying and decrypting
data by implementing one of the supported signing and verification algorithms. Typically, implementers
will use a key vault, secure enclave, or HSM to manage private keys used for signing.

Supported algorithms are defined in the Credential Issuer metadata.

```rust,ignore
pub trait KeyOps: Send + Sync {
    fn signer(&self, identifier: &str) -> anyhow::Result<impl Signer>;

    fn verifier(&self, identifier: &str) -> anyhow::Result<impl Verifier>;

    fn encryptor(&self, identifier: &str) -> anyhow::Result<impl Encryptor>;

    fn decryptor(&self, identifier: &str) -> anyhow::Result<impl Decryptor>;
}
```

### Signer

The `Signer` trait provides the library with signing functionality for Verifiable Credential issuance.

```rust,ignore
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> Algorithm;

    fn verification_method(&self) -> String;

    fn sign(&self, msg: &[u8]) -> impl Future<Output = Vec<u8>> + Send {
        let v = async { self.try_sign(msg).await.expect("should sign") };
        v.into_future()
    }

    fn try_sign(&self, msg: &[u8]) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
```

### Verifier

The `Verifier` trait provides the library with signing verification functionality for Verifiable Credential issuance.

```rust,ignore
pub trait Verifier: Send + Sync {
    fn deref_jwk(&self, did_url: &str)
        -> impl Future<Output = anyhow::Result<PublicKeyJwk>> + Send;
}
```

### Encryptor

The `Encryptor` trait provides the library with encryption functionality for Verifiable Credential issuance.

```rust,ignore
pub trait Encryptor: Send + Sync {
    fn encrypt(
        &self, plaintext: &[u8], recipient_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;

    fn public_key(&self) -> Vec<u8>;
}
```

### Decryptor

The `Decryptor` trait provides the library with decryption functionality for Verifiable Credential issuance.

```rust,ignore
pub trait Decryptor: Send + Sync {
    fn decrypt(
        &self, ciphertext: &[u8], sender_public_key: &[u8],
    ) -> impl Future<Output = anyhow::Result<Vec<u8>>> + Send;
}
```
